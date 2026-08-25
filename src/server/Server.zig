//! The SMB2 server: one poll loop, one thread, no heap.
//!
//! Everything is a fixed table inside one `Server` value — connections, the
//! sessions on each connection, the trees on each session, the open handles on
//! each tree. Sizing is a compile-time decision, so a deployment's memory
//! ceiling is knowable before it runs rather than discovered under load.
//!
//! What it speaks: SMB 2.0.2 and 2.1, NTLMv2 authentication (never guest,
//! never anonymous), HMAC-SHA256 signing, and compounded requests. What it
//! deliberately does not: oplocks and leases (never granted, so no client
//! caches data we might invalidate), byte-range locks (accepted, not enforced),
//! change notification, DFS, and SMB3 — the dialect list stops at 2.1 because
//! every 3.x feature a client would then expect (signing over CMAC, negotiate
//! contexts, preauth integrity, encryption) is a correctness cliff, not an
//! optimisation.

const std = @import("std");
const builtin = @import("builtin");

const wire = @import("../smb/wire.zig");
const hdr = @import("../smb/header.zig");
const status = @import("../smb/status.zig");
const info = @import("../smb/info.zig");
const signing = @import("../smb/sign.zig");
const unicode = @import("../smb/unicode.zig");
const filetime = @import("../smb/time.zig");

const ntlm = @import("../auth/ntlm.zig");
const spnego = @import("../auth/spnego.zig");
const Authenticator = @import("../auth/Authenticator.zig");
const Share = @import("../vfs/Share.zig");

const poller_mod = @import("../net/poller.zig");
const socket = @import("../net/socket.zig");
const log = @import("../log.zig");
const random = @import("../random.zig");

pub const Limits = struct {
    max_connections: usize = 32,
    sessions_per_connection: usize = 4,
    trees_per_session: usize = 8,
    opens_per_session: usize = 64,
    max_shares: usize = 8,
    /// Must hold one whole message plus whatever else has been pipelined.
    in_buffer: usize = 192 * 1024,
    /// Must hold a full compound chain of responses.
    out_buffer: usize = 256 * 1024,
    max_read: u32 = 64 * 1024,
    max_write: u32 = 64 * 1024,
    max_transact: u32 = 64 * 1024,
    /// Longest path an open handle remembers.
    path_bytes: usize = 512,
    search_pattern_bytes: usize = 128,
};

pub const Config = struct {
    bind: []const u8 = "",
    port: u16 = 445,
    /// Announced as the NetBIOS name and as the NTLM target. Clients bind the
    /// value into their NTLMv2 response, so it is not cosmetic.
    netbios_name: []const u8 = "EASYSAMBA",
    domain: []const u8 = "WORKGROUP",
    /// Refuse to serve a client that will not sign. Windows 11 signs by
    /// default; older clients may not.
    require_signing: bool = false,
    /// Credits granted per request. Enough to keep a client pipelining, small
    /// enough that one client cannot claim unbounded server work.
    max_credits: u16 = 128,
    /// How long a connection may go without finishing authentication. Without
    /// this, opening connections and saying nothing is enough to fill the
    /// connection table and keep every real client out. Zero disables it.
    handshake_timeout_ms: i64 = 30_000,
};

/// DesiredAccess bits from MS-SMB2 that decide what an open may do.
const access = struct {
    const READ_DATA: u32 = 0x0000_0001;
    const WRITE_DATA: u32 = 0x0000_0002;
    const APPEND_DATA: u32 = 0x0000_0004;
    const READ_EA: u32 = 0x0000_0008;
    const WRITE_EA: u32 = 0x0000_0010;
    const EXECUTE: u32 = 0x0000_0020;
    const DELETE_CHILD: u32 = 0x0000_0040;
    const READ_ATTRIBUTES: u32 = 0x0000_0080;
    const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;

    const full: u32 = 0x001F_01FF;
    const read_only: u32 = READ_DATA | READ_EA | READ_ATTRIBUTES | EXECUTE | READ_CONTROL | SYNCHRONIZE;

    fn wantsWrite(mask: u32) bool {
        return mask & (WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES |
            WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL) != 0;
    }
    fn wantsRead(mask: u32) bool {
        return mask & (READ_DATA | READ_EA | READ_ATTRIBUTES | EXECUTE |
            GENERIC_READ | GENERIC_EXECUTE | GENERIC_ALL) != 0;
    }
    fn wantsDelete(mask: u32) bool {
        return mask & (DELETE | DELETE_CHILD | GENERIC_ALL) != 0;
    }
};

const create_options = struct {
    const DIRECTORY_FILE: u32 = 0x0000_0001;
    const NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const DELETE_ON_CLOSE: u32 = 0x0000_1000;
};

const query_dir_flags = struct {
    const RESTART_SCANS: u8 = 0x01;
    const RETURN_SINGLE_ENTRY: u8 = 0x02;
    const INDEX_SPECIFIED: u8 = 0x04;
    const REOPEN: u8 = 0x10;
};

/// The tree index that means IPC$ rather than a real share.
///
/// There is no named-pipe support here and there is not going to be, but a
/// client that cannot connect IPC$ at all behaves worse than one that connects
/// it and finds nothing: Windows opens it as part of establishing a session,
/// and macOS asks for it on every mount. So it exists, it is empty, and
/// everything anyone tries to open on it is refused.
const ipc_share: usize = std.math.maxInt(usize);
const ipc_name = "IPC$";

/// A FileId of all-ones means "the handle the previous CREATE in this compound
/// chain produced" — how a client opens, reads and closes in one round trip.
const chained_file_id = [_]u8{0xFF} ** 16;

pub fn Server(comptime limits: Limits) type {
    return struct {
        config: Config = .{},
        auth: Authenticator,
        shares: [limits.max_shares]Share = undefined,
        share_count: usize = 0,

        guid: [16]u8 = @splat(0),
        start_time: u64 = 0,
        id_counter: u64 = 0,

        conns: [limits.max_connections]Conn = undefined,
        /// Which connection slots are free, and how many connections have not
        /// authenticated yet. Both exist so the event loop never walks the
        /// connection table: one `Conn` is most of a megabyte, so a scan of 32
        /// of them touches tens of megabytes of cold memory — more work per
        /// wakeup than answering the request that caused it.
        free_slots: std.StaticBitSet(limits.max_connections) = undefined,
        unauthenticated: usize = 0,
        poller: Poller = undefined,
        listen_fd: socket.Handle = socket.invalid,

        const Self = @This();
        const Poller = poller_mod.Poller(limits.max_connections + 1);
        const listener_token: poller_mod.Token = @intCast(limits.max_connections);

        /// Never start a response we might not be able to finish: a read can
        /// fill max_read, and an error reply plus a transport header still has
        /// to fit after it.
        const response_reserve: usize = limits.max_read + 4096 + hdr.transport_header_size;

        // ------------------------------------------------------------ state

        pub const Tree = struct {
            active: bool = false,
            id: u32 = 0,
            share: usize = 0,
        };

        pub const Open = struct {
            active: bool = false,
            id: u64 = 0,
            tree_id: u32 = 0,
            share: usize = 0,
            handle: Share.Handle = 0,
            path: [limits.path_bytes]u8 = undefined,
            path_len: usize = 0,
            is_dir: bool = false,
            can_read: bool = false,
            can_write: bool = false,
            delete_on_close: bool = false,

            // Directory enumeration state. A client walks a directory across
            // several QUERY_DIRECTORY requests on one handle, so the position
            // lives with the handle, not with the request.
            dir_phase: DirPhase = .dot,
            cursor: Share.Cursor = .{},
            pattern: [limits.search_pattern_bytes]u8 = undefined,
            pattern_len: usize = 0,
            dir_matched: bool = false,

            const DirPhase = enum { dot, dotdot, entries, done };

            pub fn path_(o: *const Open) []const u8 {
                return o.path[0..o.path_len];
            }
            fn pattern_(o: *const Open) []const u8 {
                return o.pattern[0..o.pattern_len];
            }
        };

        pub const Session = struct {
            active: bool = false,
            id: u64 = 0,
            established: bool = false,
            sign_required: bool = false,
            /// Torn down after the response is signed: the signature needs the
            /// key the teardown destroys.
            logoff_pending: bool = false,
            session_key: [16]u8 = @splat(0),
            account: Authenticator.Account = .{ .nt_hash = @splat(0) },
            user: [64]u8 = undefined,
            user_len: usize = 0,

            /// In-flight NTLM exchange. The two prior messages are kept only so
            /// the client's MIC can be checked against them.
            challenge: [8]u8 = @splat(0),
            raw_ntlm: bool = false,
            negotiate_msg: [256]u8 = undefined,
            negotiate_len: usize = 0,
            challenge_msg: [512]u8 = undefined,
            challenge_len: usize = 0,

            trees: [limits.trees_per_session]Tree = @splat(.{}),
            opens: [limits.opens_per_session]Open = @splat(.{}),

            pub fn user_(s: *const Session) []const u8 {
                return s.user[0..s.user_len];
            }
        };

        pub const Conn = struct {
            active: bool = false,
            fd: socket.Handle = socket.invalid,
            token: poller_mod.Token = 0,

            in: [limits.in_buffer]u8 = undefined,
            /// Unread input is `in[in_start..in_len]`. Answering advances the
            /// start; the tail is only shuffled down when the buffer has
            /// actually reached its end, which for a client whose messages fit
            /// is never.
            in_start: usize = 0,
            in_len: usize = 0,
            out: [limits.out_buffer]u8 = undefined,
            out_len: usize = 0,
            out_sent: usize = 0,

            /// What the poller has been told this connection wants. Kept so a
            /// request that changes nothing costs no syscall: at one
            /// epoll_ctl/kevent per request, that is a measurable share of the
            /// work in a small-read workload.
            interest: poller_mod.Interest = .{ .read = true },

            /// When the connection was accepted, on the monotonic clock. Only
            /// used until it authenticates.
            opened_at: i64 = 0,
            /// Set once any session on this connection reaches established.
            authenticated: bool = false,

            negotiated: bool = false,
            dialect: hdr.Dialect = .smb_2_1,
            client_signing_required: bool = false,
            sessions: [limits.sessions_per_connection]Session = @splat(.{}),

            /// Set when a fatal protocol error means the connection must go
            /// once whatever is already queued has been written.
            closing: bool = false,

            fn outPending(c: *const Conn) usize {
                return c.out_len - c.out_sent;
            }

            pub fn inPending(c: *const Conn) usize {
                return c.in_len - c.in_start;
            }

            /// Makes room at the end of the input buffer by dropping the part
            /// already answered. Only worth doing when the buffer is actually
            /// against its end, which for a client whose messages fit is never.
            fn compactInput(c: *Conn) void {
                if (c.in_start == 0) return;
                if (c.in_start == c.in_len) {
                    c.in_start = 0;
                    c.in_len = 0;
                    return;
                }
                std.mem.copyForwards(u8, c.in[0..], c.in[c.in_start..c.in_len]);
                c.in_len -= c.in_start;
                c.in_start = 0;
            }

            /// Puts a slot back to its starting state. Assigning a whole `Conn`
            /// would be shorter, but it also rewrites the two I/O buffers and
            /// every path and pattern field behind the handle tables — close to
            /// a megabyte of stores, and a megabyte of pages made resident, for
            /// a connection that may only ever ask for a directory listing.
            /// Only the fields that mean something get touched.
            fn reset(c: *Conn) void {
                c.active = false;
                c.fd = socket.invalid;
                c.token = 0;
                c.in_start = 0;
                c.in_len = 0;
                c.out_len = 0;
                c.out_sent = 0;
                c.interest = .{ .read = true };
                c.opened_at = 0;
                c.authenticated = false;
                c.negotiated = false;
                c.dialect = .smb_2_1;
                c.client_signing_required = false;
                c.closing = false;
                for (&c.sessions) |*session| session.active = false;
            }
        };

        // ------------------------------------------------------------- setup

        pub fn init(s: *Self, config: Config, auth: Authenticator) void {
            s.config = config;
            s.auth = auth;
            s.share_count = 0;
            s.listen_fd = socket.invalid;
            s.id_counter = 0;
            s.start_time = filetime.now();
            random.fill(&s.guid);
            s.free_slots = .initFull();
            s.unauthenticated = 0;
            // The connection table is deliberately left alone. Writing even one
            // byte per slot would make the whole pool resident — the slots are
            // a megabyte apart and Linux backs an anonymous fault with a 2 MiB
            // huge page — so an idle daemon would start out holding its entire
            // ceiling. `free_slots` is the record of which slots exist; a slot
            // is written for the first time when a client arrives to use it.
        }

        /// The slots a client occupies. Callers iterate this rather than
        /// `conns` itself: reading one field from every slot would touch every
        /// slot, which is precisely the memory an idle daemon avoids. It is a
        /// copy, so closing a connection mid-walk cannot disturb the walk.
        fn takenSlots(s: *const Self) std.StaticBitSet(limits.max_connections) {
            var taken = s.free_slots;
            taken.toggleAll();
            return taken;
        }

        pub fn addShare(s: *Self, share: Share) !void {
            if (s.share_count == limits.max_shares) return error.TooManyShares;
            if (share.name.len == 0) return error.InvalidShareName;
            // Names are matched case-insensitively, so two that differ only in
            // case would make which one a client reaches a matter of order.
            if (s.findShare(share.name) != null) return error.DuplicateShareName;
            s.shares[s.share_count] = share;
            s.share_count += 1;
        }

        fn findShare(s: *Self, name: []const u8) ?usize {
            for (s.shares[0..s.share_count], 0..) |share, i| {
                if (unicode.eqlIgnoreCase(share.name, name)) return i;
            }
            return null;
        }

        fn nextId(s: *Self) u64 {
            s.id_counter += 1;
            return s.id_counter;
        }

        // -------------------------------------------------------- event loop

        pub fn listen(s: *Self) !void {
            socket.ignoreSigpipe();
            const address = try socket.Address.parse(s.config.bind, s.config.port);
            s.listen_fd = try socket.listenTcp(address, 128);
            try s.poller.init();
            try s.poller.add(s.listen_fd, listener_token, .{ .read = true });
        }

        pub fn deinit(s: *Self) void {
            var taken = s.takenSlots();
            var live = taken.iterator(.{});
            while (live.next()) |index| {
                const c = &s.conns[index];
                if (c.active) s.closeConn(c);
            }
            if (s.listen_fd != socket.invalid) socket.close(s.listen_fd);
            s.poller.deinit();
        }

        pub fn run(s: *Self) !void {
            var events: [poller_mod.max_events]poller_mod.Event = undefined;
            while (true) {
                // Blocks forever when every connection has authenticated, so an
                // idle server costs nothing; wakes on the earliest handshake
                // deadline otherwise.
                const ready = try s.poller.wait(&events, s.nextTimeout());
                for (ready) |event| {
                    if (event.token == listener_token) {
                        s.acceptAll();
                        continue;
                    }
                    const c = &s.conns[event.token];
                    if (!c.active) continue;
                    if (event.readiness.write) {
                        s.flush(c);
                        // Draining output is what un-pauses a connection whose
                        // requests `pump` stopped processing for lack of room
                        // to answer. Without this the pipelined requests still
                        // sitting in the input buffer are never looked at
                        // again, and a client that is waiting for exactly those
                        // answers waits forever — a deadlock that only appears
                        // once a client has enough credits to fill the output
                        // buffer in one go.
                        if (c.active and c.inPending() > 0) s.pump(c);
                    }
                    if (c.active and event.readiness.read) s.onReadable(c);
                    if (c.active and event.readiness.hangup and c.outPending() == 0) s.closeConn(c);
                    if (c.active) s.updateInterest(c);
                }
                s.reapUnauthenticated(socket.monotonicMs());
            }
        }

        fn nextTimeout(s: *Self) i32 {
            if (s.config.handshake_timeout_ms <= 0 or s.unauthenticated == 0) return -1;
            const now = socket.monotonicMs();
            var soonest: ?i64 = null;
            var pending = s.unauthenticated;
            var taken = s.takenSlots();
            var live = taken.iterator(.{});
            while (live.next()) |index| {
                const c = &s.conns[index];
                if (!c.active or c.authenticated) continue;
                const remaining = c.opened_at + s.config.handshake_timeout_ms - now;
                if (soonest == null or remaining < soonest.?) soonest = remaining;
                pending -= 1;
                if (pending == 0) break;
            }
            const wait = soonest orelse return -1;
            return @intCast(@max(wait, 10));
        }

        /// Drops connections that never got as far as authenticating.
        pub fn reapUnauthenticated(s: *Self, now: i64) void {
            if (s.config.handshake_timeout_ms <= 0 or s.unauthenticated == 0) return;
            var taken = s.takenSlots();
            var live = taken.iterator(.{});
            while (live.next()) |index| {
                const c = &s.conns[index];
                if (!c.active or c.authenticated) continue;
                if (now - c.opened_at < s.config.handshake_timeout_ms) continue;
                log.warn("connection {d}: no authentication within {d}ms, dropping", .{
                    c.token, s.config.handshake_timeout_ms,
                });
                s.closeConn(c);
            }
        }

        fn acceptAll(s: *Self) void {
            while (socket.accept(s.listen_fd)) |fd| {
                const index = s.free_slots.findFirstSet() orelse {
                    log.warn("connection table full ({d}); refusing a client", .{limits.max_connections});
                    socket.close(fd);
                    continue;
                };
                const c = &s.conns[index];
                c.reset();
                c.active = true;
                c.fd = fd;
                c.token = @intCast(index);
                c.opened_at = socket.monotonicMs();
                c.interest = .{ .read = true };
                s.free_slots.unset(index);
                s.unauthenticated += 1;
                socket.setNoDelay(fd);
                s.poller.add(fd, c.token, c.interest) catch {
                    log.err("cannot register a connection with the poller", .{});
                    c.active = false;
                    s.free_slots.set(index);
                    s.unauthenticated -= 1;
                    socket.close(fd);
                    continue;
                };
                log.debug("connection {d} accepted", .{c.token});
            }
        }

        /// Claims a connection slot that has no socket behind it: the
        /// in-process client is a connection in every respect except the file
        /// descriptor, and going through the same door keeps the connection
        /// table's bookkeeping true for it too.
        pub fn adopt(s: *Self, index: usize) *Conn {
            const c = &s.conns[index];
            // Asking the slot itself whether it is in use would read a field
            // that has never been written for a slot no client has occupied.
            if (!s.free_slots.isSet(index)) s.closeConn(c);
            c.reset();
            c.active = true;
            c.token = @intCast(index);
            c.opened_at = socket.monotonicMs();
            s.free_slots.unset(index);
            s.unauthenticated += 1;
            return c;
        }

        fn markAuthenticated(s: *Self, c: *Conn) void {
            if (c.authenticated) return;
            c.authenticated = true;
            s.unauthenticated -= 1;
        }

        fn closeConn(s: *Self, c: *Conn) void {
            // Closing twice would hand the same slot back twice and take the
            // unauthenticated count below zero.
            if (!c.active) return;
            for (&c.sessions) |*session| {
                if (session.active) s.endSession(session);
            }
            // A connection that never had a socket — the in-process client and
            // its tests — has nothing registered and nothing to close.
            if (c.fd != socket.invalid) {
                s.poller.remove(c.fd, c.token);
                socket.close(c.fd);
            }
            c.active = false;
            c.fd = socket.invalid;
            if (!c.authenticated) s.unauthenticated -= 1;
            s.free_slots.set(c.token);
            log.debug("connection {d} closed", .{c.token});
        }

        fn updateInterest(s: *Self, c: *Conn) void {
            if (c.closing and c.outPending() == 0) {
                s.closeConn(c);
                return;
            }
            // Reading is paused while the output buffer is too full to hold
            // another response: that is the backpressure that keeps one slow
            // client from making the server buffer without bound.
            const wanted: poller_mod.Interest = .{
                .read = !c.closing and c.out_len + response_reserve <= limits.out_buffer,
                .write = c.outPending() > 0,
            };
            if (wanted.read == c.interest.read and wanted.write == c.interest.write) return;
            c.interest = wanted;
            s.poller.modify(c.fd, c.token, wanted) catch s.closeConn(c);
        }

        fn onReadable(s: *Self, c: *Conn) void {
            while (true) {
                // Nothing left to append to: reclaim whatever has been answered
                // before deciding the client is at fault.
                if (c.in_len == limits.in_buffer) c.compactInput();
                if (c.in_len == limits.in_buffer) {
                    // Still full, and pump could not drain it. Either the
                    // client is sending a message larger than we ever agreed
                    // to, or we are simply out of room to answer — the second
                    // is backpressure and resolves itself once output drains.
                    if (c.out_len + response_reserve > limits.out_buffer) return;
                    log.warn("connection {d}: oversized message, dropping", .{c.token});
                    s.closeConn(c);
                    return;
                }
                const space = c.in[c.in_len..];
                switch (socket.read(c.fd, space)) {
                    .read => |n| {
                        c.in_len += n;
                        s.pump(c);
                        if (!c.active or c.closing) return;
                        if (n < space.len) return; // the socket is drained for now
                    },
                    .status => |st| switch (st) {
                        .would_block => return,
                        .eof, .failed => {
                            s.closeConn(c);
                            return;
                        },
                    },
                }
            }
        }

        /// Hands `bytes` to a connection exactly as a socket read would, and
        /// processes whatever complete messages that produces. Returns how many
        /// bytes were accepted — fewer than offered means the input buffer is
        /// full. Passing nothing resumes a connection that backpressure paused.
        pub fn feed(s: *Self, c: *Conn, bytes: []const u8) usize {
            if (bytes.len > limits.in_buffer - c.in_len) c.compactInput();
            const accepted = @min(bytes.len, limits.in_buffer - c.in_len);
            @memcpy(c.in[c.in_len..][0..accepted], bytes[0..accepted]);
            c.in_len += accepted;
            s.pump(c);
            return accepted;
        }

        /// Answers as much of the buffered input as it can, writing as it goes.
        ///
        /// The two steps have to alternate. Filling the output buffer stops the
        /// message loop, and flushing it is what makes room for the next
        /// answer, so a single pass leaves pipelined requests sitting unread
        /// even though the socket has just gone empty — which a client
        /// experiences as one stalled operation per round trip, not as an
        /// error. Looping until nothing moves is what keeps a client with a
        /// large credit window at full speed.
        fn pump(s: *Self, c: *Conn) void {
            while (!c.closing) {
                const consumed = s.answerBuffered(c);
                s.flush(c);
                if (consumed == 0) break; // no complete message, or output is stuck
            }
        }

        /// One pass over the input buffer. Returns how many bytes it consumed,
        /// stopping at the first message it cannot answer for lack of room.
        fn answerBuffered(s: *Self, c: *Conn) usize {
            var consumed: usize = 0;
            while (!c.closing) {
                const rest = c.in[c.in_start..c.in_len];
                const length = hdr.frameLength(rest) catch {
                    log.warn("connection {d}: bad transport framing", .{c.token});
                    c.closing = true;
                    break;
                } orelse break;
                if (length == 0 or length > limits.in_buffer - hdr.transport_header_size) {
                    log.warn("connection {d}: framed length {d} is out of range", .{ c.token, length });
                    c.closing = true;
                    break;
                }
                if (rest.len < hdr.transport_header_size + length) break; // not all here yet
                if (c.out_len + response_reserve > limits.out_buffer) break; // no room to answer

                const message = rest[hdr.transport_header_size..][0..length];
                s.handleFrame(c, message);
                c.in_start += hdr.transport_header_size + length;
                consumed += hdr.transport_header_size + length;
            }

            if (c.in_start == c.in_len) {
                c.in_start = 0;
                c.in_len = 0;
            }
            return consumed;
        }

        fn flush(s: *Self, c: *Conn) void {
            // A connection with no socket keeps its output buffered: that is
            // what the in-process client and its tests are, and treating a
            // missing fd as a write failure would tear them down.
            if (c.fd == socket.invalid) return;
            while (c.outPending() > 0) {
                switch (socket.write(c.fd, c.out[c.out_sent..c.out_len])) {
                    .wrote => |n| {
                        c.out_sent += n;
                        if (n == 0) break;
                    },
                    .status => |st| switch (st) {
                        .would_block => break,
                        .eof, .failed => {
                            s.closeConn(c);
                            return;
                        },
                    },
                }
            }
            if (c.out_sent == c.out_len) {
                c.out_sent = 0;
                c.out_len = 0;
            } else if (c.out_sent > limits.out_buffer / 2) {
                // Reclaim the sent prefix so a long-lived connection does not
                // creep toward the end of its buffer.
                std.mem.copyForwards(u8, c.out[0..], c.out[c.out_sent..c.out_len]);
                c.out_len -= c.out_sent;
                c.out_sent = 0;
            }
        }

        // --------------------------------------------------------- dispatch

        /// One transport frame: either an SMB1 multi-protocol negotiate (which
        /// gets exactly one SMB2 answer) or a chain of SMB2 requests.
        ///
        /// Everything written here goes out under one 4-byte transport header
        /// covering the whole chain — a compounded response is one frame, not
        /// one per message.
        pub fn handleFrame(s: *Self, c: *Conn, message: []const u8) void {
            var w = wire.Writer.init(c.out[0..limits.out_buffer]);
            w.pos = c.out_len;

            const frame_at = w.pos;
            w.zeroes(hdr.transport_header_size) catch {
                c.closing = true;
                return;
            };
            defer closeFrame(c, &w, frame_at);

            if (!c.negotiated and hdr.isSmb1(message)) {
                s.answerSmb1Negotiate(c, &w);
                return;
            }

            var offset: usize = 0;
            var chain: Chain = .{};
            while (true) {
                const remaining = message[offset..];
                const head = hdr.parse(remaining) catch {
                    log.warn("connection {d}: not an SMB2 message", .{c.token});
                    c.closing = true;
                    break;
                };
                const length: usize = if (head.next_command != 0)
                    @min(head.next_command, remaining.len)
                else
                    remaining.len;
                if (length < hdr.header_size) {
                    c.closing = true;
                    break;
                }

                s.handleRequest(c, head, remaining[0..length], &w, &chain);

                if (head.next_command == 0 or offset + head.next_command >= message.len) break;
                offset += head.next_command;
            }
        }

        /// Stamps the transport length over the placeholder, or drops the frame
        /// entirely when nothing was written — a CANCEL is answered with
        /// silence, not with an empty frame.
        fn closeFrame(c: *Conn, w: *wire.Writer, frame_at: usize) void {
            const payload = w.pos - frame_at - hdr.transport_header_size;
            if (payload == 0) {
                w.pos = frame_at;
            } else {
                hdr.writeFrameLength(w.buf[frame_at..][0..4], @intCast(payload));
            }
            c.out_len = w.pos;
        }

        /// Carried across one compound chain: a related request inherits the
        /// previous one's session, tree and file, and inherits its failure.
        const Chain = struct {
            session_id: u64 = 0,
            tree_id: u32 = 0,
            file_id: [16]u8 = @splat(0),
            has_file: bool = false,
            failed: u32 = status.SUCCESS,
        };

        const Ctx = struct {
            server: *Self,
            conn: *Conn,
            head: hdr.Header,
            msg: []const u8,
            body: []const u8,
            session: ?*Session,
            tree: ?*Tree,
            chain: *Chain,
            w: *wire.Writer,
            start: usize,

            /// Offset of the write cursor within this response message, which
            /// is what every SMB2 offset field is measured against.
            fn rel(ctx: *const Ctx) u16 {
                return @intCast(ctx.w.pos - ctx.start);
            }
            fn share(ctx: *const Ctx) ?Share {
                const tree = ctx.tree orelse return null;
                return ctx.server.shares[tree.share];
            }
        };

        fn handleRequest(s: *Self, c: *Conn, head: hdr.Header, msg: []const u8, w: *wire.Writer, chain: *Chain) void {
            const start = w.pos;
            if (w.space() < response_reserve) {
                log.warn("connection {d}: no room to answer; dropping", .{c.token});
                c.closing = true;
                return;
            }

            // CANCEL is the one request with no reply at all.
            if (head.command == .cancel) return;

            var response_head: hdr.Header = .{
                .credit_charge = head.credit_charge,
                .command = head.command,
                .credits = grantCredits(head.credits, head.credit_charge, s.config.max_credits),
                .flags = hdr.flags.SERVER_TO_REDIR,
                .message_id = head.message_id,
                .tree_id = head.tree_id,
                .session_id = head.session_id,
            };

            const session_id = if (head.isRelated() and chain.session_id != 0) chain.session_id else head.session_id;
            const tree_id = if (head.isRelated() and chain.tree_id != 0) chain.tree_id else head.tree_id;
            response_head.session_id = session_id;
            response_head.tree_id = tree_id;

            hdr.write(w, response_head) catch {
                c.closing = true;
                return;
            };

            var ctx: Ctx = .{
                .server = s,
                .conn = c,
                .head = head,
                .msg = msg,
                .body = msg[hdr.header_size..],
                .session = null,
                .tree = null,
                .chain = chain,
                .w = w,
                .start = start,
            };

            const result = s.route(&ctx, session_id, tree_id);
            const code = if (chain.failed != status.SUCCESS and head.isRelated())
                chain.failed
            else
                result;

            if (code != status.SUCCESS and !isInformational(code)) {
                // Discard whatever the handler managed to write: an error
                // response carries a fixed body, never a partial one.
                w.pos = start + hdr.header_size;
                writeErrorBody(w) catch {
                    c.closing = true;
                    return;
                };
                // Anything chained onto a failed request fails with it — the
                // handle or tree it was going to use never came into being.
                chain.failed = code;
            } else if (!isInformational(code)) {
                chain.failed = status.SUCCESS;
            }
            w.patchInt(u32, start + 8, code) catch {};

            // Pad the message so the next one in the chain starts 8-aligned.
            const aligned = std.mem.alignForward(usize, w.pos - start, 8);
            w.zeroes(aligned - (w.pos - start)) catch {};
            const more_to_come = head.next_command != 0;
            if (more_to_come) w.patchInt(u32, start + 20, @intCast(w.pos - start)) catch {};

            log.debug("connection {d}: {s} -> 0x{x:0>8} ({d} bytes)", .{
                c.token, @tagName(head.command), code, w.pos - start,
            });
            s.signResponse(&ctx, w.buf[start..w.pos]);

            if (ctx.session) |session| {
                if (session.logoff_pending) s.endSession(session);
            }
        }

        /// Credits are how a client decides how many requests it may have in
        /// flight, and a request that asks for a lot of data spends several of
        /// them: CreditCharge is one credit per 64 KiB of the larger of the
        /// request and its answer.
        ///
        /// So the grant has two floors. The charge, because granting less than
        /// a request consumed shrinks the client's window until it reaches zero
        /// and the client stops sending — with a 1 MiB read that takes exactly
        /// one request, and the mount hangs with no error anywhere. And a small
        /// constant, because a client that asks for one credit at a time would
        /// otherwise never get more than one request in flight.
        ///
        /// The backpressure that actually protects this server is the
        /// output-buffer check in `pump`, not the credit count.
        fn grantCredits(requested: u16, charge: u16, maximum: u16) u16 {
            return @max(1, @min(@max(requested, @max(charge, 8)), maximum));
        }

        fn isInformational(code: u32) bool {
            // A few statuses are failures to the client but still carry a real
            // response body we must not throw away.
            return code == status.MORE_PROCESSING_REQUIRED or code == status.BUFFER_OVERFLOW;
        }

        fn writeErrorBody(w: *wire.Writer) wire.Error!void {
            try w.u16_(9); // StructureSize
            try w.u8_(0); // ErrorContextCount
            try w.u8_(0); // Reserved
            try w.u32_(0); // ByteCount
            try w.u8_(0); // one byte of ErrorData, as the structure size implies
        }

        fn signResponse(s: *Self, ctx: *Ctx, message: []u8) void {
            _ = s;
            const session = ctx.session orelse return;
            if (!session.established) return;
            if (!session.sign_required and !ctx.head.isSigned()) return;
            signing.sign(signing.algorithmFor(ctx.conn.dialect), session.session_key, message);
        }

        fn route(s: *Self, ctx: *Ctx, session_id: u64, tree_id: u32) u32 {
            const command = ctx.head.command;

            if (command == .negotiate) return s.handleNegotiate(ctx);
            if (!ctx.conn.negotiated) return status.INVALID_PARAMETER;

            if (command == .session_setup) return s.handleSessionSetup(ctx, session_id);

            ctx.session = s.findSession(ctx.conn, session_id) orelse return status.USER_SESSION_DELETED;
            const session = ctx.session.?;
            if (!session.established) return status.USER_SESSION_DELETED;

            // Every message after authentication is verified if it claims to be
            // signed, and required to be signed if the session says so.
            if (ctx.head.isSigned()) {
                if (!signing.verify(signing.algorithmFor(ctx.conn.dialect), session.session_key, ctx.msg)) {
                    log.warn("connection {d}: bad signature on {s}", .{ ctx.conn.token, @tagName(command) });
                    return status.ACCESS_DENIED;
                }
            } else if (session.sign_required and command != .session_setup) {
                log.warn("connection {d}: unsigned {s} on a signed session", .{ ctx.conn.token, @tagName(command) });
                return status.ACCESS_DENIED;
            }

            ctx.chain.session_id = session_id;

            switch (command) {
                .logoff => return s.handleLogoff(ctx),
                .tree_connect => return s.handleTreeConnect(ctx),
                .echo => return writeEcho(ctx),
                else => {},
            }

            ctx.tree = findTree(session, tree_id) orelse return status.SMB_BAD_TID;
            ctx.chain.tree_id = tree_id;

            if (ctx.tree.?.share == ipc_share) {
                return switch (command) {
                    .tree_disconnect => s.handleTreeDisconnect(ctx),
                    // Every named pipe a client might ask for (srvsvc, wkssvc,
                    // lsarpc) would be an RPC endpoint we do not implement.
                    .create => status.ACCESS_DENIED,
                    else => status.NOT_SUPPORTED,
                };
            }

            return switch (command) {
                .tree_disconnect => s.handleTreeDisconnect(ctx),
                .create => s.handleCreate(ctx),
                .close => s.handleClose(ctx),
                .flush => s.handleFlush(ctx),
                .read => s.handleRead(ctx),
                .write => s.handleWrite(ctx),
                .query_directory => s.handleQueryDirectory(ctx),
                .query_info => s.handleQueryInfo(ctx),
                .set_info => s.handleSetInfo(ctx),
                .lock => writeLock(ctx),
                // Not supported, and saying so plainly is the point: a client
                // that is told "no" falls back, a client left waiting hangs.
                .ioctl, .change_notify, .oplock_break => status.NOT_SUPPORTED,
                else => status.NOT_IMPLEMENTED,
            };
        }

        // ------------------------------------------------------- negotiate

        fn answerSmb1Negotiate(s: *Self, c: *Conn, w: *wire.Writer) void {
            // A client that opens with the old multi-protocol negotiate is told
            // "SMB2, wildcard dialect" and asks again properly. Nothing else in
            // this server parses SMB1.
            const start = w.pos;
            hdr.write(w, .{
                .command = .negotiate,
                .credits = 1,
                .flags = hdr.flags.SERVER_TO_REDIR,
                .message_id = 0,
            }) catch return;
            s.writeNegotiateBody(c, w, start, .wildcard) catch {
                w.pos = start;
            };
        }

        fn handleNegotiate(s: *Self, ctx: *Ctx) u32 {
            if (ctx.conn.negotiated) return status.INVALID_PARAMETER;
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 36) return status.INVALID_PARAMETER;
            const dialect_count = r.u16_() catch return status.INVALID_PARAMETER;
            const security_mode = r.u16_() catch return status.INVALID_PARAMETER;
            _ = r.u16_() catch return status.INVALID_PARAMETER; // Reserved
            _ = r.u32_() catch return status.INVALID_PARAMETER; // Capabilities
            _ = r.take(16) catch return status.INVALID_PARAMETER; // ClientGuid
            _ = r.u64_() catch return status.INVALID_PARAMETER; // ClientStartTime / contexts

            var best: ?hdr.Dialect = null;
            var i: usize = 0;
            while (i < dialect_count) : (i += 1) {
                const raw = r.u16_() catch break;
                const dialect: hdr.Dialect = @enumFromInt(raw);
                switch (dialect) {
                    .smb_2_0_2, .smb_2_1 => {
                        if (best == null or @intFromEnum(dialect) > @intFromEnum(best.?)) best = dialect;
                    },
                    else => {},
                }
            }
            const chosen = best orelse {
                log.warn("connection {d}: no dialect in common (client offered {d})", .{ ctx.conn.token, dialect_count });
                return status.NOT_SUPPORTED;
            };

            ctx.conn.dialect = chosen;
            ctx.conn.negotiated = true;
            ctx.conn.client_signing_required = security_mode & hdr.security_mode.SIGNING_REQUIRED != 0;

            s.writeNegotiateBody(ctx.conn, ctx.w, ctx.start, chosen) catch return status.INSUFF_SERVER_RESOURCES;
            log.info("connection {d}: dialect {s}{s}", .{
                ctx.conn.token,
                @tagName(chosen),
                if (ctx.conn.client_signing_required) ", client requires signing" else "",
            });
            return status.SUCCESS;
        }

        fn writeNegotiateBody(s: *Self, c: *Conn, w: *wire.Writer, start: usize, dialect: hdr.Dialect) !void {
            _ = c;
            var mode: u16 = hdr.security_mode.SIGNING_ENABLED;
            if (s.config.require_signing) mode |= hdr.security_mode.SIGNING_REQUIRED;

            try w.u16_(65); // StructureSize
            try w.u16_(mode);
            try w.u16_(@intFromEnum(dialect));
            try w.u16_(0); // NegotiateContextCount (3.1.1 only)
            try w.blob(&s.guid);
            try w.u32_(hdr.capabilities.LARGE_MTU);
            try w.u32_(limits.max_transact);
            try w.u32_(limits.max_read);
            try w.u32_(limits.max_write);
            try w.u64_(filetime.now());
            try w.u64_(s.start_time);

            const offset_at = w.pos;
            try w.u16_(0); // SecurityBufferOffset, patched below
            try w.u16_(0); // SecurityBufferLength
            try w.u32_(0); // NegotiateContextOffset

            const blob_at = w.pos;
            const blob = try spnego.buildNegTokenInit(try w.reserve(64));
            w.pos = blob_at + blob.len;
            try w.patchInt(u16, offset_at, @intCast(blob_at - start));
            try w.patchInt(u16, offset_at + 2, @intCast(blob.len));
        }

        // ---------------------------------------------------- session setup

        fn handleSessionSetup(s: *Self, ctx: *Ctx, session_id: u64) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 25) return status.INVALID_PARAMETER;
            _ = r.u8_() catch return status.INVALID_PARAMETER; // Flags
            const security_mode = r.u8_() catch return status.INVALID_PARAMETER;
            _ = r.u32_() catch return status.INVALID_PARAMETER; // Capabilities
            _ = r.u32_() catch return status.INVALID_PARAMETER; // Channel
            const blob_offset = r.u16_() catch return status.INVALID_PARAMETER;
            const blob_length = r.u16_() catch return status.INVALID_PARAMETER;
            _ = r.u64_() catch return status.INVALID_PARAMETER; // PreviousSessionId

            const request = wire.Reader.init(ctx.msg);
            const blob = request.sliceAt(blob_offset, blob_length) catch return status.INVALID_PARAMETER;
            const token = spnego.findNtlmToken(blob) orelse return status.LOGON_FAILURE;

            return switch (ntlm.messageType(token) orelse return status.LOGON_FAILURE) {
                .negotiate => s.beginAuth(ctx, token, blob, security_mode),
                .authenticate => s.finishAuth(ctx, token, session_id),
                else => status.LOGON_FAILURE,
            };
        }

        fn beginAuth(s: *Self, ctx: *Ctx, token: []const u8, blob: []const u8, security_mode: u8) u32 {
            // A client that restarts the exchange reuses its half-built session
            // rather than burning another slot; otherwise repeating the first
            // message a few times is enough to exhaust the table.
            const session = s.reusableSession(ctx.conn, ctx.head.session_id) orelse
                s.allocSession(ctx.conn) orelse
                return status.INSUFF_SERVER_RESOURCES;
            session.* = .{ .active = true, .id = s.nextId() };
            session.raw_ntlm = ntlm.isNtlmssp(blob);
            session.sign_required = s.config.require_signing or
                security_mode & hdr.security_mode.SIGNING_REQUIRED != 0;

            if (token.len <= session.negotiate_msg.len) {
                @memcpy(session.negotiate_msg[0..token.len], token);
                session.negotiate_len = token.len;
            }

            random.fill(&session.challenge);
            const client_flags = ntlm.parseNegotiateFlags(token) catch 0;
            const challenge = ntlm.buildChallenge(&session.challenge_msg, .{
                .challenge = session.challenge,
                .netbios_name = s.config.netbios_name,
                .domain = s.config.domain,
                .client_flags = client_flags,
            }) catch {
                s.endSession(session);
                return status.INSUFF_SERVER_RESOURCES;
            };
            session.challenge_len = challenge.len;

            ctx.session = session;
            // The response carries the session id the client must quote from
            // here on, even though the session is not usable yet.
            ctx.w.patchInt(u64, ctx.start + 40, session.id) catch {};

            var wrapped: [1024]u8 = undefined;
            const payload = if (session.raw_ntlm)
                challenge
            else
                spnego.buildNegTokenResp(&wrapped, .accept_incomplete, true, challenge) catch {
                    s.endSession(session);
                    return status.INSUFF_SERVER_RESOURCES;
                };

            writeSessionSetupBody(ctx, payload, 0) catch {
                s.endSession(session);
                return status.INSUFF_SERVER_RESOURCES;
            };
            return status.MORE_PROCESSING_REQUIRED;
        }

        fn finishAuth(s: *Self, ctx: *Ctx, token: []const u8, session_id: u64) u32 {
            const session = s.findSession(ctx.conn, session_id) orelse return status.USER_SESSION_DELETED;
            if (session.established) return status.INVALID_PARAMETER;

            var names: ntlm.Names = .{};
            const auth = ntlm.parseAuthenticate(token, &names) catch {
                s.endSession(session);
                return status.LOGON_FAILURE;
            };

            const account = s.auth.lookup(auth.user, auth.domain) orelse {
                log.warn("logon refused: no account for '{s}'", .{auth.user});
                s.endSession(session);
                return status.LOGON_FAILURE;
            };

            const verified = ntlm.verify(.{
                .nt_hash = account.nt_hash,
                .server_challenge = session.challenge,
                .auth = auth,
                .negotiate_message = session.negotiate_msg[0..session.negotiate_len],
                .challenge_message = session.challenge_msg[0..session.challenge_len],
                .authenticate_message = token,
            }) catch {
                log.warn("logon refused: bad credentials for '{s}'", .{auth.user});
                s.endSession(session);
                return status.LOGON_FAILURE;
            };

            session.session_key = verified.session_key;
            session.account = account;
            session.established = true;
            s.markAuthenticated(ctx.conn);
            const name_len = @min(auth.user.len, session.user.len);
            @memcpy(session.user[0..name_len], auth.user[0..name_len]);
            session.user_len = name_len;
            // Nothing needs the NTLM transcript once the session key exists,
            // and it is keying material for anyone who reads this memory later.
            std.crypto.secureZero(u8, &session.negotiate_msg);
            std.crypto.secureZero(u8, &session.challenge_msg);
            session.negotiate_len = 0;
            session.challenge_len = 0;

            ctx.session = session;
            ctx.w.patchInt(u64, ctx.start + 40, session.id) catch {};

            var wrapped: [64]u8 = undefined;
            const payload = if (session.raw_ntlm)
                &[_]u8{}
            else
                spnego.buildNegTokenResp(&wrapped, .accept_completed, false, &.{}) catch &[_]u8{};

            writeSessionSetupBody(ctx, payload, 0) catch return status.INSUFF_SERVER_RESOURCES;
            log.info("connection {d}: '{s}' authenticated{s}", .{
                ctx.conn.token,
                session.user_(),
                if (account.read_only) " (read-only)" else "",
            });
            return status.SUCCESS;
        }

        fn writeSessionSetupBody(ctx: *Ctx, payload: []const u8, session_flags: u16) !void {
            try ctx.w.u16_(9); // StructureSize
            try ctx.w.u16_(session_flags);
            const offset_at = ctx.w.pos;
            try ctx.w.u16_(0);
            try ctx.w.u16_(0);
            if (payload.len == 0) {
                try ctx.w.u8_(0); // the byte the structure size accounts for
                return;
            }
            const at = ctx.rel();
            try ctx.w.blob(payload);
            try ctx.w.patchInt(u16, offset_at, at);
            try ctx.w.patchInt(u16, offset_at + 2, @intCast(payload.len));
        }

        fn handleLogoff(s: *Self, ctx: *Ctx) u32 {
            _ = s;
            ctx.session.?.logoff_pending = true;
            ctx.w.u16_(4) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        /// The session this SESSION_SETUP is restarting, if it names one that
        /// exists and has not finished authenticating.
        fn reusableSession(s: *Self, c: *Conn, id: u64) ?*Session {
            const session = s.findSession(c, id) orelse return null;
            return if (session.established) null else session;
        }

        fn allocSession(s: *Self, c: *Conn) ?*Session {
            _ = s;
            for (&c.sessions) |*session| {
                if (!session.active) return session;
            }
            return null;
        }

        fn findSession(s: *Self, c: *Conn, id: u64) ?*Session {
            _ = s;
            if (id == 0) return null;
            for (&c.sessions) |*session| {
                if (session.active and session.id == id) return session;
            }
            return null;
        }

        fn endSession(s: *Self, session: *Session) void {
            for (&session.opens) |*open| {
                if (open.active) s.closeOpen(session, open);
            }
            std.crypto.secureZero(u8, &session.session_key);
            std.crypto.secureZero(u8, &session.negotiate_msg);
            std.crypto.secureZero(u8, &session.challenge_msg);
            session.active = false;
            session.established = false;
        }

        // -------------------------------------------------------------- tree

        fn handleTreeConnect(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 9) return status.INVALID_PARAMETER;
            _ = r.u16_() catch return status.INVALID_PARAMETER; // Flags/Reserved
            const path_offset = r.u16_() catch return status.INVALID_PARAMETER;
            const path_length = r.u16_() catch return status.INVALID_PARAMETER;

            const request = wire.Reader.init(ctx.msg);
            const raw = request.sliceAt(path_offset, path_length) catch return status.INVALID_PARAMETER;
            var utf8: [512]u8 = undefined;
            const path = unicode.toUtf8(&utf8, raw) catch return status.OBJECT_PATH_NOT_FOUND;

            // "\\server\share" — only the last component identifies the share.
            const name = if (std.mem.lastIndexOfScalar(u8, path, '\\')) |i| path[i + 1 ..] else path;
            const is_ipc = unicode.eqlIgnoreCase(name, ipc_name);
            const share_index = if (is_ipc) ipc_share else s.findShare(name) orelse {
                log.warn("connection {d}: no share named '{s}'", .{ ctx.conn.token, name });
                return status.BAD_NETWORK_NAME;
            };

            const session = ctx.session.?;
            const tree = for (&session.trees) |*t| {
                if (!t.active) break t;
            } else return status.INSUFF_SERVER_RESOURCES;

            tree.* = .{ .active = true, .id = @intCast(s.nextId() & 0xFFFF_FFFF), .share = share_index };
            if (tree.id == 0) tree.id = 1;

            const writable = !is_ipc and !s.shares[share_index].read_only and !session.account.read_only;

            ctx.w.patchInt(u32, ctx.start + 36, tree.id) catch {};
            ctx.w.u16_(16) catch return status.INSUFF_SERVER_RESOURCES; // StructureSize
            ctx.w.u8_(if (is_ipc) 2 else 1) catch return status.INSUFF_SERVER_RESOURCES; // PIPE or DISK
            ctx.w.u8_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // ShareFlags
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Capabilities
            ctx.w.u32_(if (writable) access.full else access.read_only) catch return status.INSUFF_SERVER_RESOURCES;

            log.info("connection {d}: '{s}' connected to \\\\{s}\\{s}{s}", .{
                ctx.conn.token,     session.user_(),
                s.config.netbios_name, if (is_ipc) ipc_name else s.shares[share_index].name,
                if (writable) "" else " (read-only)",
            });
            return status.SUCCESS;
        }

        fn handleTreeDisconnect(s: *Self, ctx: *Ctx) u32 {
            const session = ctx.session.?;
            const tree = ctx.tree.?;
            for (&session.opens) |*open| {
                if (open.active and open.tree_id == tree.id) s.closeOpen(session, open);
            }
            tree.active = false;
            ctx.w.u16_(4) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        fn findTree(session: *Session, id: u32) ?*Tree {
            if (id == 0) return null;
            for (&session.trees) |*tree| {
                if (tree.active and tree.id == id) return tree;
            }
            return null;
        }

        // ------------------------------------------------------------ opens

        /// A FileId carries its own slot in the low bits and a generation
        /// counter above it, so looking one up is an index rather than a scan
        /// of the handle table — READ and WRITE do this on every request.
        ///
        /// The generation is what makes that safe: a client that reuses a
        /// FileId after closing it lands on the right slot with the wrong
        /// generation, and is refused rather than handed whoever holds the slot
        /// now.
        const slot_bits = 16;
        const slot_mask: u64 = (1 << slot_bits) - 1;

        comptime {
            if (limits.opens_per_session > slot_mask) @compileError("opens_per_session must fit a FileId slot");
        }

        fn allocOpen(s: *Self, session: *Session) ?*Open {
            for (&session.opens, 0..) |*open, index| {
                if (!open.active) {
                    s.id_counter += 1;
                    open.* = .{ .active = true, .id = (s.id_counter << slot_bits) | index };
                    return open;
                }
            }
            return null;
        }

        fn findOpen(ctx: *Ctx, raw_id: []const u8) ?*Open {
            const session = ctx.session orelse return null;
            var id_bytes: [16]u8 = undefined;
            if (std.mem.eql(u8, raw_id, &chained_file_id)) {
                if (!ctx.chain.has_file) return null;
                id_bytes = ctx.chain.file_id;
            } else {
                if (raw_id.len != 16) return null;
                @memcpy(&id_bytes, raw_id);
            }
            const id = std.mem.readInt(u64, id_bytes[0..8], .little);
            const index = id & slot_mask;
            if (index >= session.opens.len) return null;
            const open = &session.opens[@intCast(index)];
            if (!open.active or open.id != id) return null;
            // A handle belongs to the tree it was opened on. Using it through
            // another one is not an escalation here — the handle carries its
            // own share — but it is not something a client is allowed to do.
            if (ctx.tree) |tree| {
                if (open.tree_id != tree.id) return null;
            }
            return open;
        }

        fn closeOpen(s: *Self, session: *Session, open: *Open) void {
            _ = session;
            const share = s.shares[open.share];
            if (open.delete_on_close) {
                share.remove(open.handle) catch |err| {
                    log.warn("delete-on-close failed for '{s}': {s}", .{ open.path_(), @errorName(err) });
                };
            }
            share.close(open.handle);
            open.active = false;
        }

        fn writeFileId(w: *wire.Writer, id: u64) !void {
            // Persistent and volatile halves are the same value: this server
            // has no durable handles, so there is nothing for them to differ on.
            try w.u64_(id);
            try w.u64_(id);
        }

        // ----------------------------------------------------------- create

        fn handleCreate(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 57) return status.INVALID_PARAMETER;
            _ = r.u8_() catch return status.INVALID_PARAMETER; // SecurityFlags
            _ = r.u8_() catch return status.INVALID_PARAMETER; // RequestedOplockLevel
            _ = r.u32_() catch return status.INVALID_PARAMETER; // ImpersonationLevel
            _ = r.u64_() catch return status.INVALID_PARAMETER; // SmbCreateFlags
            _ = r.u64_() catch return status.INVALID_PARAMETER; // Reserved
            const desired_access = r.u32_() catch return status.INVALID_PARAMETER;
            const file_attributes = r.u32_() catch return status.INVALID_PARAMETER;
            _ = r.u32_() catch return status.INVALID_PARAMETER; // ShareAccess
            const disposition = r.u32_() catch return status.INVALID_PARAMETER;
            const options = r.u32_() catch return status.INVALID_PARAMETER;
            const name_offset = r.u16_() catch return status.INVALID_PARAMETER;
            const name_length = r.u16_() catch return status.INVALID_PARAMETER;

            const request = wire.Reader.init(ctx.msg);
            const raw_name = request.sliceAt(name_offset, name_length) catch return status.INVALID_PARAMETER;
            var utf8: [unicode.max_path]u8 = undefined;
            const wire_name = unicode.toUtf8(&utf8, raw_name) catch return status.OBJECT_NAME_INVALID;
            var path_buf: [unicode.max_path]u8 = undefined;
            const path = unicode.normalizePath(&path_buf, wire_name) catch |err| return switch (err) {
                error.BadPath => status.OBJECT_NAME_INVALID,
                else => status.OBJECT_PATH_NOT_FOUND,
            };
            if (path.len > limits.path_bytes) return status.OBJECT_NAME_INVALID;

            const session = ctx.session.?;
            const share = ctx.share().?;
            const wants_write = access.wantsWrite(desired_access);
            const wants_delete = access.wantsDelete(desired_access) or options & create_options.DELETE_ON_CLOSE != 0;
            if ((wants_write or wants_delete) and session.account.read_only) return status.ACCESS_DENIED;

            const disp: Share.Disposition = switch (disposition) {
                0 => .supersede,
                1 => .open,
                2 => .create,
                3 => .open_if,
                4 => .overwrite,
                5 => .overwrite_if,
                else => return status.INVALID_PARAMETER,
            };
            var directory: ?bool = null;
            if (options & create_options.DIRECTORY_FILE != 0) directory = true;
            if (options & create_options.NON_DIRECTORY_FILE != 0) directory = false;

            const opened = share.open(path, .{
                .read = access.wantsRead(desired_access) or !wants_write,
                .write = wants_write,
                .delete = wants_delete,
                .disposition = disp,
                .directory = directory,
                .attributes = @bitCast(file_attributes & 0x27), // read-only, hidden, system, archive
            }) catch |err| return Share.statusFor(err);

            const open = s.allocOpen(session) orelse {
                share.close(opened.handle);
                return status.INSUFF_SERVER_RESOURCES;
            };
            open.tree_id = ctx.tree.?.id;
            open.share = ctx.tree.?.share;
            open.handle = opened.handle;
            open.is_dir = opened.meta.isDir();
            // Same rule the adapter was opened with, so a handle that was never
            // granted read access is refused rather than quietly allowed.
            open.can_read = access.wantsRead(desired_access) or !wants_write;
            open.can_write = wants_write;
            open.delete_on_close = options & create_options.DELETE_ON_CLOSE != 0;
            @memcpy(open.path[0..path.len], path);
            open.path_len = path.len;

            ctx.chain.file_id = @splat(0);
            std.mem.writeInt(u64, ctx.chain.file_id[0..8], open.id, .little);
            std.mem.writeInt(u64, ctx.chain.file_id[8..16], open.id, .little);
            ctx.chain.has_file = true;

            const meta = opened.meta;
            ctx.w.u16_(89) catch return status.INSUFF_SERVER_RESOURCES; // StructureSize
            ctx.w.u8_(0) catch return status.INSUFF_SERVER_RESOURCES; // OplockLevel: none granted
            ctx.w.u8_(0) catch return status.INSUFF_SERVER_RESOURCES; // Flags
            ctx.w.u32_(@intFromEnum(opened.action)) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(meta.created) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(meta.accessed) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(meta.modified) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(meta.changed) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(meta.alloc_size) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(meta.size) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(meta.attributes.wire()) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved2
            writeFileId(ctx.w, open.id) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // CreateContextsOffset
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // CreateContextsLength
            return status.SUCCESS;
        }

        fn handleClose(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 24) return status.INVALID_PARAMETER;
            const flags = r.u16_() catch return status.INVALID_PARAMETER;
            _ = r.u32_() catch return status.INVALID_PARAMETER; // Reserved
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            const share = s.shares[open.share];
            const meta = share.stat(open.handle) catch Share.Meta{};
            s.closeOpen(ctx.session.?, open);
            if (ctx.chain.has_file and std.mem.readInt(u64, ctx.chain.file_id[0..8], .little) == open.id) {
                ctx.chain.has_file = false;
            }

            const post_query = flags & 0x0001 != 0;
            ctx.w.u16_(60) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(flags) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(if (post_query) meta.created else 0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(if (post_query) meta.accessed else 0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(if (post_query) meta.modified else 0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(if (post_query) meta.changed else 0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(if (post_query) meta.alloc_size else 0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u64_(if (post_query) meta.size else 0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(if (post_query) meta.attributes.wire() else 0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        fn handleFlush(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 24) return status.INVALID_PARAMETER;
            _ = r.u16_() catch return status.INVALID_PARAMETER;
            _ = r.u32_() catch return status.INVALID_PARAMETER;
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            s.shares[open.share].flush(open.handle) catch |err| return Share.statusFor(err);
            ctx.w.u16_(4) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        // ------------------------------------------------------- read/write

        fn handleRead(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 49) return status.INVALID_PARAMETER;
            _ = r.u8_() catch return status.INVALID_PARAMETER; // Padding
            _ = r.u8_() catch return status.INVALID_PARAMETER; // Flags
            const length = r.u32_() catch return status.INVALID_PARAMETER;
            const offset = r.u64_() catch return status.INVALID_PARAMETER;
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;
            const minimum = r.u32_() catch return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            if (open.is_dir) return status.INVALID_DEVICE_REQUEST;
            if (!open.can_read) return status.ACCESS_DENIED;
            if (length > limits.max_read) return status.INVALID_PARAMETER;

            ctx.w.u16_(17) catch return status.INSUFF_SERVER_RESOURCES;
            const data_offset_at = ctx.w.pos;
            ctx.w.u8_(0) catch return status.INSUFF_SERVER_RESOURCES; // DataOffset, patched below
            ctx.w.u8_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved
            const length_at = ctx.w.pos;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // DataLength
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // DataRemaining
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved2
            // Every SMB2 offset is measured from the start of the message, so
            // this can only be filled in once the fixed part is behind us.
            ctx.w.patch(data_offset_at, &.{@intCast(ctx.rel())}) catch {};

            const target = ctx.w.reserve(@min(length, ctx.w.space())) catch return status.INSUFF_SERVER_RESOURCES;
            const got = if (length == 0) 0 else s.shares[open.share].read(open.handle, offset, target) catch |err| {
                return Share.statusFor(err);
            };
            ctx.w.pos -= target.len - got;

            // Asking for nothing and getting nothing is a success; asking for
            // something and getting nothing is the end of the file.
            if (length == 0) return status.SUCCESS;
            if (got == 0 or got < minimum) return status.END_OF_FILE;
            ctx.w.patchInt(u32, length_at, @intCast(got)) catch {};
            return status.SUCCESS;
        }

        fn handleWrite(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 49) return status.INVALID_PARAMETER;
            const data_offset = r.u16_() catch return status.INVALID_PARAMETER;
            const length = r.u32_() catch return status.INVALID_PARAMETER;
            const offset = r.u64_() catch return status.INVALID_PARAMETER;
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            if (open.is_dir) return status.INVALID_DEVICE_REQUEST;
            if (!open.can_write) return status.ACCESS_DENIED;
            if (length > limits.max_write) return status.INVALID_PARAMETER;

            const request = wire.Reader.init(ctx.msg);
            const data = request.sliceAt(data_offset, length) catch return status.INVALID_PARAMETER;
            const wrote = s.shares[open.share].write(open.handle, offset, data) catch |err| return Share.statusFor(err);

            ctx.w.u16_(17) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved
            ctx.w.u32_(@intCast(wrote)) catch return status.INSUFF_SERVER_RESOURCES; // Count
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Remaining
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES; // WriteChannelInfoOffset
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES; // WriteChannelInfoLength
            ctx.w.u8_(0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        // -------------------------------------------------- query directory

        fn handleQueryDirectory(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 33) return status.INVALID_PARAMETER;
            const class: info.FileClass = @enumFromInt(r.u8_() catch return status.INVALID_PARAMETER);
            const flags = r.u8_() catch return status.INVALID_PARAMETER;
            _ = r.u32_() catch return status.INVALID_PARAMETER; // FileIndex
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;
            const name_offset = r.u16_() catch return status.INVALID_PARAMETER;
            const name_length = r.u16_() catch return status.INVALID_PARAMETER;
            const output_length = r.u32_() catch return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            if (!open.is_dir) return status.INVALID_PARAMETER;

            switch (class) {
                .directory, .full_directory, .both_directory, .id_both_directory, .id_full_directory, .names => {},
                else => return status.INVALID_INFO_CLASS,
            }

            if (name_length > 0) {
                const request = wire.Reader.init(ctx.msg);
                const raw = request.sliceAt(name_offset, name_length) catch return status.INVALID_PARAMETER;
                var utf8: [unicode.max_name]u8 = undefined;
                const pattern = unicode.toUtf8(&utf8, raw) catch return status.INVALID_PARAMETER;
                if (pattern.len > open.pattern.len) return status.INVALID_PARAMETER;
                @memcpy(open.pattern[0..pattern.len], pattern);
                open.pattern_len = pattern.len;
            }
            if (flags & (query_dir_flags.RESTART_SCANS | query_dir_flags.REOPEN) != 0) {
                open.dir_phase = .dot;
                open.cursor = .{};
                open.dir_matched = false;
            }
            if (open.dir_phase == .done) {
                open.dir_phase = .dot;
                open.cursor = .{};
                return status.NO_MORE_FILES;
            }

            const share = s.shares[open.share];
            const pattern = if (open.pattern_len == 0) "*" else open.pattern_();
            const dir_meta = share.stat(open.handle) catch Share.Meta{ .attributes = .{ .directory = true } };

            ctx.w.u16_(9) catch return status.INSUFF_SERVER_RESOURCES;
            const offset_at = ctx.w.pos;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES; // OutputBufferOffset
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // OutputBufferLength
            const buffer_at = ctx.rel();
            const budget = @min(@as(usize, output_length), @min(ctx.w.space(), limits.max_transact));

            // The entry writer needs a cursor over the output area alone: both
            // NextEntryOffset and the 8-byte alignment are relative to it.
            var area = wire.Writer.init(ctx.w.buf[ctx.w.pos..][0..budget]);
            var written: usize = 0;
            var index: u32 = 0;
            var last_start: usize = 0;

            while (true) {
                var name_buf: [unicode.max_name]u8 = undefined;
                var entry: Share.DirEntry = undefined;
                const saved_cursor = open.cursor;
                const saved_phase = open.dir_phase;
                const have = switch (open.dir_phase) {
                    .dot => blk: {
                        open.dir_phase = .dotdot;
                        entry = .{ .name = ".", .meta = dir_meta };
                        break :blk true;
                    },
                    .dotdot => blk: {
                        open.dir_phase = .entries;
                        entry = .{ .name = "..", .meta = dir_meta };
                        break :blk true;
                    },
                    .entries => share.readDir(open.handle, &open.cursor, &name_buf, &entry) catch |err| {
                        return Share.statusFor(err);
                    },
                    .done => false,
                };
                if (!have) {
                    open.dir_phase = .done;
                    break;
                }
                if (!unicode.matchWildcard(pattern, entry.name)) continue;

                const before = area.pos;
                const fits = info.writeDirEntry(&area, class, index, entry, true) catch {
                    return status.INSUFF_SERVER_RESOURCES;
                };
                if (!fits) {
                    // Put the entry back: the next request must see it first.
                    // The cursor is the adapter's own bookmark and nothing says
                    // it counts by one, so rewinding means restoring it.
                    open.cursor = saved_cursor;
                    open.dir_phase = saved_phase;
                    break;
                }
                if (written > 0) area.patchInt(u32, last_start, @intCast(before - last_start)) catch {};
                last_start = before;
                written += 1;
                index += 1;
                open.dir_matched = true;
                if (flags & query_dir_flags.RETURN_SINGLE_ENTRY != 0) break;
            }

            if (written == 0) {
                if (!open.dir_matched) return status.NO_SUCH_FILE;
                open.dir_phase = .dot;
                open.cursor = .{};
                open.dir_matched = false;
                return status.NO_MORE_FILES;
            }

            ctx.w.pos += area.pos;
            ctx.w.patchInt(u16, offset_at, buffer_at) catch {};
            ctx.w.patchInt(u32, offset_at + 2, @intCast(area.pos)) catch {};
            return status.SUCCESS;
        }

        // ------------------------------------------------------------- info

        fn handleQueryInfo(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 41) return status.INVALID_PARAMETER;
            const info_type: info.InfoType = @enumFromInt(r.u8_() catch return status.INVALID_PARAMETER);
            const class = r.u8_() catch return status.INVALID_PARAMETER;
            const output_length = r.u32_() catch return status.INVALID_PARAMETER;
            _ = r.u16_() catch return status.INVALID_PARAMETER; // InputBufferOffset
            _ = r.u16_() catch return status.INVALID_PARAMETER; // Reserved
            _ = r.u32_() catch return status.INVALID_PARAMETER; // InputBufferLength
            const additional = r.u32_() catch return status.INVALID_PARAMETER;
            _ = r.u32_() catch return status.INVALID_PARAMETER; // Flags
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            const share = s.shares[open.share];

            ctx.w.u16_(9) catch return status.INSUFF_SERVER_RESOURCES;
            const offset_at = ctx.w.pos;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES;
            const buffer_at = ctx.rel();
            const budget = @min(@as(usize, output_length), @min(ctx.w.space(), limits.max_transact));
            var area = wire.Writer.init(ctx.w.buf[ctx.w.pos..][0..budget]);

            switch (info_type) {
                .file => {
                    const meta = share.stat(open.handle) catch |err| return Share.statusFor(err);
                    var name_buf: [limits.path_bytes + 1]u8 = undefined;
                    const name = wireName(&name_buf, open.path_());
                    info.writeFileInfo(&area, @enumFromInt(class), meta, name, open.delete_on_close) catch |err| {
                        return switch (err) {
                            error.NoSpace => status.INFO_LENGTH_MISMATCH,
                            error.BadEncoding => status.INVALID_INFO_CLASS,
                            else => status.INVALID_PARAMETER,
                        };
                    };
                },
                .filesystem => {
                    const fs = share.statFs() catch |err| return Share.statusFor(err);
                    info.writeFsInfo(&area, @enumFromInt(class), fs) catch |err| {
                        return switch (err) {
                            error.NoSpace => status.INFO_LENGTH_MISMATCH,
                            error.BadEncoding => status.INVALID_INFO_CLASS,
                            else => status.INVALID_PARAMETER,
                        };
                    };
                },
                .security => {
                    info.writeSecurityDescriptor(&area, additional) catch {
                        return status.BUFFER_TOO_SMALL;
                    };
                },
                else => return status.INVALID_INFO_CLASS,
            }

            ctx.w.pos += area.pos;
            ctx.w.patchInt(u16, offset_at, buffer_at) catch {};
            ctx.w.patchInt(u32, offset_at + 2, @intCast(area.pos)) catch {};
            if (area.pos == 0) ctx.w.u8_(0) catch {};
            return status.SUCCESS;
        }

        /// The name a handle reports back: the share-relative path in Windows
        /// form, always starting with a backslash, `\` for the share root.
        ///
        /// Not decoration. FileAllInformation ends in a variable-length name,
        /// and the Linux client rejects the whole record if it is one byte
        /// shorter than the structure it expects — an empty name is exactly one
        /// byte short, and the mount fails with nothing but "get root inode
        /// failed" to go on.
        fn wireName(out: []u8, path: []const u8) []const u8 {
            out[0] = '\\';
            for (path, 0..) |ch, i| out[i + 1] = if (ch == '/') '\\' else ch;
            return out[0 .. path.len + 1];
        }

        fn handleSetInfo(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 33) return status.INVALID_PARAMETER;
            const info_type: info.InfoType = @enumFromInt(r.u8_() catch return status.INVALID_PARAMETER);
            const class: info.FileClass = @enumFromInt(r.u8_() catch return status.INVALID_PARAMETER);
            const buffer_length = r.u32_() catch return status.INVALID_PARAMETER;
            const buffer_offset = r.u16_() catch return status.INVALID_PARAMETER;

            if (info_type != .file) return status.INVALID_INFO_CLASS;
            const request = wire.Reader.init(ctx.msg);
            const buffer = request.sliceAt(buffer_offset, buffer_length) catch return status.INVALID_PARAMETER;

            // FileId follows Reserved and AdditionalInformation, at body offset 16.
            const raw_id = blk: {
                var at_id = wire.Reader.init(ctx.body);
                at_id.skip(16) catch return status.INVALID_PARAMETER;
                break :blk at_id.take(16) catch return status.INVALID_PARAMETER;
            };
            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            const session = ctx.session.?;
            if (session.account.read_only) return status.ACCESS_DENIED;
            const share = s.shares[open.share];

            switch (class) {
                .basic => {
                    const changes = info.parseBasic(buffer) catch return status.INFO_LENGTH_MISMATCH;
                    share.setMeta(open.handle, changes) catch |err| return Share.statusFor(err);
                },
                .disposition => {
                    const delete = info.parseDisposition(buffer) catch return status.INFO_LENGTH_MISMATCH;
                    if (delete and share.read_only) return status.ACCESS_DENIED;
                    open.delete_on_close = delete;
                },
                .end_of_file, .allocation => {
                    if (!open.can_write) return status.ACCESS_DENIED;
                    const size = info.parseEndOfFile(buffer) catch return status.INFO_LENGTH_MISMATCH;
                    share.truncate(open.handle, size) catch |err| return Share.statusFor(err);
                },
                .rename => {
                    const rename = info.parseRename(buffer) catch return status.INFO_LENGTH_MISMATCH;
                    var utf8: [unicode.max_path]u8 = undefined;
                    const wire_name = unicode.toUtf8(&utf8, rename.name_utf16) catch return status.OBJECT_NAME_INVALID;
                    var path_buf: [unicode.max_path]u8 = undefined;
                    const path = unicode.normalizePath(&path_buf, wire_name) catch return status.OBJECT_NAME_INVALID;
                    if (path.len == 0 or path.len > limits.path_bytes) return status.OBJECT_NAME_INVALID;
                    share.rename(open.handle, path, rename.replace) catch |err| return Share.statusFor(err);
                    @memcpy(open.path[0..path.len], path);
                    open.path_len = path.len;
                },
                else => return status.INVALID_INFO_CLASS,
            }

            ctx.w.u16_(2) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        // ------------------------------------------------------------ small

        fn writeEcho(ctx: *Ctx) u32 {
            ctx.w.u16_(4) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        /// Byte-range locks are acknowledged but not enforced: this server has
        /// one client's view of a share at a time and no way to arbitrate
        /// between a lock and a change made underneath it. Refusing locks
        /// outright breaks clients that take one before every write, so the
        /// honest-but-workable answer is to say yes and document that it means
        /// nothing.
        fn writeLock(ctx: *Ctx) u32 {
            ctx.w.u16_(4) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }
    };
}
