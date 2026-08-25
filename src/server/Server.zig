//! The SMB2 server: one poll loop, one thread, no heap.
//!
//! Everything is a fixed table inside one `Server` value — connections, the
//! sessions on each connection, the trees on each session, the open handles on
//! each tree. Sizing is a compile-time decision, so a deployment's memory
//! ceiling is knowable before it runs rather than discovered under load.
//!
//! What it speaks: SMB 2.0.2 and 2.1, NTLMv2 authentication (never guest,
//! never anonymous), HMAC-SHA256 signing, compounded requests, byte-range locks
//! that are actually enforced against reads and writes, and read caching —
//! leases for a 2.1 client, level-II oplocks for an older one — taken back with
//! a break the moment somebody changes the file. Change notification is
//! answered asynchronously, which is the one place a request outlives the frame
//! that carried it, and a copy inside a share is done by the server rather than
//! dragged through the client. What it deliberately does not: write or handle
//! caching
//! (both need a request parked half-answered while a client writes back or
//! closes, and there is nowhere to park one), DFS, and SMB3 — the dialect list
//! stops at 2.1 because
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
    /// Read leases and level-II oplocks handed out at once. A client that
    /// cannot have one is simply told so and asks the server every time, so
    /// this is a cache size, not a correctness limit.
    max_oplocks: usize = 64,
    /// Scratch for a server-side copy. A copy of any size loops through it, so
    /// this is how much moves per read and write, not how much can be copied.
    copy_buffer: usize = 64 * 1024,
    /// Directories being watched for changes at once. A client watches one
    /// directory per window it has open, so this is roughly how many folders
    /// may be on screen across every client.
    max_watches: usize = 32,
    /// Byte-range locks held anywhere on the server at once. One shared table
    /// rather than a slice of every connection's ceiling: locks are rare, and a
    /// lock has to be visible to every handle on the file, not just its own.
    max_locks: usize = 128,
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
        /// Byte-range locks, densely packed: `locks[0..lock_count]` are the
        /// live ones and releasing one swaps the last into the hole. Dense
        /// because every read and write walks it, and because a table nobody
        /// has locked anything in should stay memory the process never touched.
        locks: [limits.max_locks]Lock = undefined,
        lock_count: usize = 0,
        /// Read caching handed out to clients, and the breaks owed to them.
        /// Both are dense, for the same reason the lock table is: every write
        /// walks the grants, and a server nobody has cached anything from
        /// should not have touched either table.
        grants: [limits.max_oplocks]Grant = undefined,
        grant_count: usize = 0,
        breaks: [limits.max_oplocks]PendingBreak = undefined,
        break_count: usize = 0,
        /// Change notifications a client is waiting on. A watch exists only
        /// while its request is outstanding: the client asks, the server says
        /// "not yet", and the entry is what that promise is made of.
        watches: [limits.max_watches]Watch = undefined,
        watch_count: usize = 0,
        /// Where a server-side copy passes through. One thread, one copy at a
        /// time, so one buffer.
        copy: [limits.copy_buffer]u8 = undefined,
        /// Mixed into the key that names a handle to a copy. A key is quoted
        /// back to the server by a client, so it must not be guessable from the
        /// handle alone.
        resume_salt: [8]u8 = @splat(0),
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
            /// The path, hashed, so a lock can name the file it belongs to
            /// without a copy of the path per lock. Two paths that collided
            /// would lock each other out, never let each other through.
            path_hash: u64 = 0,
            /// The lease this handle was opened under, if any. A client uses
            /// one key for every handle it opens on a file, which is how it
            /// says "these are all me" — writing through one of them must not
            /// break the caching it is doing through another.
            lease_key: [16]u8 = @splat(0),
            has_lease: bool = false,
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

        /// One granted byte-range lock. The file is named by its share and
        /// the hash of its path rather than by the handle that took the lock,
        /// because the whole point of a lock is that the *other* handles on
        /// that file — including handles another session opened — see it.
        pub const Lock = struct {
            share: usize = 0,
            path_hash: u64 = 0,
            /// The `Open.id` that took it, and the only one that may drop it.
            owner: u64 = 0,
            offset: u64 = 0,
            length: u64 = 0,
            exclusive: bool = false,
        };

        /// Read caching a client was granted on a file, and everything needed
        /// to take it back without going looking for the handle it belongs to.
        pub const Grant = struct {
            share: usize = 0,
            path_hash: u64 = 0,
            owner: u64 = 0,
            conn: poller_mod.Token = 0,
            session_id: u64 = 0,
            tree_id: u32 = 0,
            /// Zero for a level-II oplock, which names the handle instead.
            lease_key: [16]u8 = @splat(0),
            is_lease: bool = false,
        };

        /// A break that has been decided but not yet written. Breaks are not
        /// sent where they are discovered: the discovery happens in the middle
        /// of composing a response, and the connection being broken may be the
        /// one that response is being written into.
        pub const PendingBreak = struct {
            conn: poller_mod.Token = 0,
            session_id: u64 = 0,
            tree_id: u32 = 0,
            file_id: u64 = 0,
            lease_key: [16]u8 = @splat(0),
            is_lease: bool = false,
        };

        /// A CHANGE_NOTIFY that has been accepted and not yet answered.
        pub const Watch = struct {
            conn: poller_mod.Token = 0,
            session_id: u64 = 0,
            /// The request this is the other half of.
            message_id: u64 = 0,
            async_id: u64 = 0,
            /// The directory handle it was asked on. Closing that handle ends
            /// the wait, which is how a client stops watching.
            owner: u64 = 0,
            share: usize = 0,
            /// The watched directory itself, not a hash of it: telling whether
            /// a change happened inside it means comparing the paths.
            path: [limits.path_bytes]u8 = undefined,
            path_len: usize = 0,
            watch_tree: bool = false,
            filter: u32 = 0,
            output_limit: u32 = 0,

            /// What it is waiting to say, once there is something to say.
            fired: bool = false,
            fired_status: u32 = 0,
            action: u32 = 0,
            name: [limits.path_bytes]u8 = undefined,
            name_len: usize = 0,

            fn path_(w: *const Watch) []const u8 {
                return w.path[0..w.path_len];
            }
            fn name_(w: *const Watch) []const u8 {
                return w.name[0..w.name_len];
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
            s.lock_count = 0;
            s.grant_count = 0;
            s.break_count = 0;
            s.watch_count = 0;
            random.fill(&s.resume_salt);
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

        /// Tears a connection down and hands its slot back. Public because a
        /// server embedded in another program has to be able to drop a client.
        pub fn closeConn(s: *Self, c: *Conn) void {
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
            // Nothing is owed to a connection that has gone, including the
            // answers its own teardown just decided on.
            s.dropWatches(c.token);
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
        /// One transport frame in, one out — and then whatever breaks
        /// answering it owed to other clients.
        pub fn handleFrame(s: *Self, c: *Conn, message: []const u8) void {
            s.answerFrame(c, message);
            s.deliverBreaks();
            s.deliverNotifications();
        }

        fn answerFrame(s: *Self, c: *Conn, message: []const u8) void {
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

        /// Sends the breaks that answering a frame decided on.
        ///
        /// They are sent here and not where they were discovered, because
        /// discovery happens halfway through composing a response: a break for
        /// a handle on the same connection would land inside that response, and
        /// one for another connection would be a second writer into a buffer
        /// the first still holds a cursor into.
        fn deliverBreaks(s: *Self) void {
            const owed = s.break_count;
            s.break_count = 0;
            for (s.breaks[0..owed]) |pending| {
                const c = &s.conns[pending.conn];
                if (!c.active or c.closing) continue;
                s.sendBreak(c, pending);
                s.flush(c);
            }
        }

        /// One break notification, unsolicited: no request produced it and no
        /// acknowledgement is asked for. Nothing but read caching is ever
        /// granted, so there is nothing for a client to write back before it
        /// lets go — it drops what it cached and carries on.
        fn sendBreak(s: *Self, c: *Conn, pending: PendingBreak) void {
            const body_size: usize = if (pending.is_lease) 44 else 24;
            if (limits.out_buffer - c.out_len < hdr.transport_header_size + hdr.header_size + body_size) {
                // Nowhere to put it. A client must not go on caching a file
                // that has changed, and the only other way to tell it so is to
                // take the connection away: it revalidates when it comes back.
                log.warn("connection {d}: no room for a break, dropping the connection", .{c.token});
                c.closing = true;
                return;
            }

            var w = wire.Writer.init(c.out[0..limits.out_buffer]);
            w.pos = c.out_len;
            const frame_at = w.pos;
            w.zeroes(hdr.transport_header_size) catch return;
            const start = w.pos;
            hdr.write(&w, .{
                .command = .oplock_break,
                .credits = 0,
                .flags = hdr.flags.SERVER_TO_REDIR,
                // The message id that means "this answers nothing".
                .message_id = std.math.maxInt(u64),
                .session_id = pending.session_id,
                .tree_id = pending.tree_id,
            }) catch return;

            if (pending.is_lease) {
                w.u16_(44) catch return; // StructureSize
                w.u16_(0) catch return; // NewEpoch: a version 1 lease has none
                w.u32_(0) catch return; // Flags: no acknowledgement required
                w.blob(&pending.lease_key) catch return;
                w.u32_(lease_state.read_caching) catch return; // CurrentLeaseState
                w.u32_(0) catch return; // NewLeaseState: nothing is left
                w.u32_(0) catch return; // BreakReason
                w.u32_(0) catch return; // AccessMaskHint
                w.u32_(0) catch return; // ShareMaskHint
            } else {
                w.u16_(24) catch return; // StructureSize
                w.u8_(oplock_level.none) catch return;
                w.u8_(0) catch return; // Reserved
                w.u32_(0) catch return; // Reserved2
                writeFileId(&w, pending.file_id) catch return;
            }

            const message = w.buf[start..w.pos];
            s.signBreak(c, pending.session_id, message);
            hdr.writeFrameLength(w.buf[frame_at..][0..4], @intCast(message.len));
            c.out_len = w.pos;
            log.debug("connection {d}: break sent", .{c.token});
        }

        /// A break carries no request to take its cue from, so the session's
        /// own rule decides: a client that demanded signing would throw away an
        /// unsigned message, which is the one thing a break must not be.
        fn signBreak(s: *Self, c: *Conn, session_id: u64, message: []u8) void {
            const session = s.findSession(c, session_id) orelse return;
            if (!session.established or !session.sign_required) return;
            signing.sign(signing.algorithmFor(c.dialect), session.session_key, message);
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
            /// Set by a handler that cannot answer yet, and stamped into the
            /// half-answer so the client can cancel it by name.
            async_id: u64 = 0,

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

            // CANCEL is the one request with no reply at all. What it cancels
            // is answered instead, and separately.
            if (head.command == .cancel) {
                s.cancelWatch(c, head);
                return;
            }

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
                // A half-answer is not a failure: the request is still alive.
                if (code != status.PENDING) chain.failed = code;
            } else if (!isInformational(code)) {
                chain.failed = status.SUCCESS;
            }
            w.patchInt(u32, start + 8, code) catch {};
            if (code == status.PENDING) {
                // Not an answer yet. The flag is what tells the client so, and
                // the id is the name it cancels the request by.
                w.patchInt(u32, start + 16, hdr.flags.SERVER_TO_REDIR | hdr.flags.ASYNC_COMMAND) catch {};
                w.patchInt(u64, start + 32, ctx.async_id) catch {};
            }

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
                // A break acknowledgement is not about a tree, and a client
                // that sends one may not put a tree id on it.
                .oplock_break => return writeBreakAck(ctx),
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
                .lock => s.handleLock(ctx),
                // Not supported, and saying so plainly is the point: a client
                // that is told "no" falls back, a client left waiting hangs.
                .change_notify => s.handleChangeNotify(ctx),
                .ioctl => s.handleIoctl(ctx),
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
            // Leases are a 2.1 feature, and a client only asks for one if the
            // server said it does them. A 2.0.2 client is offered the older
            // oplock instead, which it asks for without being invited.
            var caps: u32 = hdr.capabilities.LARGE_MTU;
            if (dialect == .smb_2_1) caps |= hdr.capabilities.LEASING;
            try w.u32_(caps);
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
                ctx.conn.token,                       session.user_(),
                s.config.netbios_name,                if (is_ipc) ipc_name else s.shares[share_index].name,
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
            s.releaseLocks(open.id);
            s.releaseGrant(open.id);
            s.endWatches(open.id);
            const share = s.shares[open.share];
            if (open.delete_on_close) {
                s.breakGrants(open);
                s.noteOpenChange(
                    open,
                    notify_action.removed,
                    if (open.is_dir) notify_filter.dir_name else notify_filter.file_name,
                );
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
            const requested_oplock = r.u8_() catch return status.INVALID_PARAMETER;
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
            const contexts_offset = r.u32_() catch return status.INVALID_PARAMETER;
            const contexts_length = r.u32_() catch return status.INVALID_PARAMETER;

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
            open.path_hash = std.hash.Wyhash.hash(0, path);

            const granted = s.grantCaching(
                ctx,
                open,
                requested_oplock,
                findLeaseContext(ctx.msg, contexts_offset, contexts_length),
            );
            // Opening a file in a way that throws its contents away is a change
            // to it, so whoever was caching those contents has to hear about it.
            if (opened.action == .superseded or opened.action == .overwritten) {
                s.breakGrants(open);
                s.noteOpenChange(open, notify_action.modified, notify_filter.size | notify_filter.last_write);
            }
            if (opened.action == .created) s.noteOpenChange(
                open,
                notify_action.added,
                if (open.is_dir) notify_filter.dir_name else notify_filter.file_name,
            );

            ctx.chain.file_id = @splat(0);
            std.mem.writeInt(u64, ctx.chain.file_id[0..8], open.id, .little);
            std.mem.writeInt(u64, ctx.chain.file_id[8..16], open.id, .little);
            ctx.chain.has_file = true;

            const meta = opened.meta;
            ctx.w.u16_(89) catch return status.INSUFF_SERVER_RESOURCES; // StructureSize
            ctx.w.u8_(granted) catch return status.INSUFF_SERVER_RESOURCES; // OplockLevel
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
            const contexts_at = ctx.w.pos;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // CreateContextsOffset
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // CreateContextsLength

            if (granted == oplock_level.lease) {
                const at = ctx.rel();
                writeLeaseContext(ctx.w, open.lease_key) catch return status.INSUFF_SERVER_RESOURCES;
                ctx.w.patchInt(u32, contexts_at, at) catch {};
                ctx.w.patchInt(u32, contexts_at + 4, @intCast(ctx.rel() - at)) catch {};
            }
            return status.SUCCESS;
        }

        /// The granted lease, echoed back in the shape it arrived in. The key
        /// is the client's own; the state is what it actually got, which is
        /// read caching and nothing else.
        fn writeLeaseContext(w: *wire.Writer, key: [16]u8) wire.Error!void {
            try w.u32_(0); // Next: the only context in the answer
            try w.u16_(create_context_header); // NameOffset
            try w.u16_(lease_context_name.len); // NameLength
            try w.u16_(0); // Reserved
            try w.u16_(create_context_header + 8); // DataOffset, past the padded name
            try w.u32_(lease_data_size); // DataLength
            try w.blob(lease_context_name);
            try w.zeroes(4); // padding to the 8-aligned data
            try w.blob(&key);
            try w.u32_(lease_state.read_caching);
            try w.u32_(0); // LeaseFlags
            try w.u64_(0); // LeaseDuration
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
            if (s.lockedAgainst(open, offset, length, false)) return status.FILE_LOCK_CONFLICT;

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
            if (s.lockedAgainst(open, offset, length, true)) return status.FILE_LOCK_CONFLICT;

            const request = wire.Reader.init(ctx.msg);
            const data = request.sliceAt(data_offset, length) catch return status.INVALID_PARAMETER;
            const wrote = s.shares[open.share].write(open.handle, offset, data) catch |err| return Share.statusFor(err);
            s.breakGrants(open);
            s.noteOpenChange(open, notify_action.modified, notify_filter.last_write | notify_filter.size);

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
                    s.noteOpenChange(open, notify_action.modified, notify_filter.attributes | notify_filter.last_write);
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
                    s.breakGrants(open);
                    s.noteOpenChange(open, notify_action.modified, notify_filter.size);
                },
                .rename => {
                    const rename = info.parseRename(buffer) catch return status.INFO_LENGTH_MISMATCH;
                    var utf8: [unicode.max_path]u8 = undefined;
                    const wire_name = unicode.toUtf8(&utf8, rename.name_utf16) catch return status.OBJECT_NAME_INVALID;
                    var path_buf: [unicode.max_path]u8 = undefined;
                    const path = unicode.normalizePath(&path_buf, wire_name) catch return status.OBJECT_NAME_INVALID;
                    if (path.len == 0 or path.len > limits.path_bytes) return status.OBJECT_NAME_INVALID;
                    share.rename(open.handle, path, rename.replace) catch |err| return Share.statusFor(err);
                    // Both names changed: whoever was caching the old one is
                    // now caching a file that is not there, and whoever was
                    // caching the new one is caching what this just replaced.
                    s.breakGrants(open);
                    const named = if (open.is_dir) notify_filter.dir_name else notify_filter.file_name;
                    s.noteOpenChange(open, notify_action.renamed_old, named);
                    @memcpy(open.path[0..path.len], path);
                    open.path_len = path.len;
                    s.renameOpen(open, std.hash.Wyhash.hash(0, path));
                    s.breakGrants(open);
                    s.noteOpenChange(open, notify_action.renamed_new, named);
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

        // -------------------------------------------------- leases and oplocks

        const oplock_level = struct {
            const none: u8 = 0x00;
            const level2: u8 = 0x01;
            const exclusive: u8 = 0x08;
            const batch: u8 = 0x09;
            const lease: u8 = 0xFF;
        };

        const lease_state = struct {
            const read_caching: u32 = 0x0000_0001;
            const handle_caching: u32 = 0x0000_0002;
            const write_caching: u32 = 0x0000_0004;
        };

        /// The lease a client asked for in its CREATE.
        const LeaseRequest = struct {
            key: [16]u8,
            state: u32,
        };

        const lease_context_name = "RqLs";
        /// Next, NameOffset, NameLength, Reserved, DataOffset, DataLength.
        const create_context_header = 16;
        /// A version 1 lease: key, state, flags, duration.
        const lease_data_size = 32;

        /// Finds the lease a CREATE asked for among its create contexts. Every
        /// other context — durable handles, allocation hints, the security
        /// descriptor — is skipped rather than refused: a client sends what it
        /// has and expects a server to answer for the parts it understands.
        fn findLeaseContext(msg: []const u8, offset: u32, length: u32) ?LeaseRequest {
            if (length < create_context_header) return null;
            const request = wire.Reader.init(msg);
            const blob = request.sliceAt(offset, length) catch return null;

            var at: usize = 0;
            while (at + create_context_header <= blob.len) {
                const chunk = blob[at..];
                const next = std.mem.readInt(u32, chunk[0..4], .little);
                const name_offset = std.mem.readInt(u16, chunk[4..6], .little);
                const name_length = std.mem.readInt(u16, chunk[6..8], .little);
                const data_offset = std.mem.readInt(u16, chunk[10..12], .little);
                const data_length = std.mem.readInt(u32, chunk[12..16], .little);

                const named = @as(usize, name_offset) + name_length <= chunk.len and
                    name_length == lease_context_name.len and
                    std.mem.eql(u8, chunk[name_offset..][0..lease_context_name.len], lease_context_name);
                if (named) {
                    if (@as(usize, data_offset) + data_length > chunk.len) return null;
                    if (data_length < lease_data_size) return null;
                    const data = chunk[data_offset..];
                    return .{
                        .key = data[0..16].*,
                        .state = std.mem.readInt(u32, data[16..20], .little),
                    };
                }
                // A Next that does not move past the header it just described
                // would be a loop, and a chain of contexts always ends in zero.
                if (next < create_context_header) break;
                at += next;
            }
            return null;
        }

        /// Decides what caching a new handle gets, which is never more than the
        /// right to keep reading what it has already read.
        ///
        /// Write caching would mean the newest copy of a file living in a
        /// client's memory, and handing it to the next reader means waiting for
        /// that client to write it back — a request this server would have to
        /// park half-answered, which it has nowhere to do. Read caching needs
        /// none of that: taking it back is a message the client does not answer.
        fn grantCaching(s: *Self, ctx: *Ctx, open: *Open, requested: u8, lease: ?LeaseRequest) u8 {
            if (lease) |request| {
                // Remembered even when nothing is granted: it is how this
                // client's other handles on the file are recognised as its own.
                open.lease_key = request.key;
                open.has_lease = true;
                if (request.state & lease_state.read_caching == 0) return oplock_level.none;
            } else if (requested == oplock_level.none) {
                return oplock_level.none;
            }
            // A directory lease is an SMB 3.x feature, and a client that gets
            // one for 2.1 would be caching a listing on a promise never made.
            if (open.is_dir) return oplock_level.none;
            if (s.grant_count == limits.max_oplocks) return oplock_level.none;

            s.grants[s.grant_count] = .{
                .share = open.share,
                .path_hash = open.path_hash,
                .owner = open.id,
                .conn = ctx.conn.token,
                .session_id = ctx.session.?.id,
                .tree_id = ctx.tree.?.id,
                .lease_key = if (lease) |request| request.key else @splat(0),
                .is_lease = lease != null,
            };
            s.grant_count += 1;
            const level = if (lease != null) oplock_level.lease else oplock_level.level2;
            log.debug("connection {d}: caching 0x{x} asked for, 0x{x} granted on '{s}'", .{
                ctx.conn.token, requested, level, open.path_(),
            });
            return level;
        }

        /// Takes back every grant on this file except the ones belonging to
        /// whoever is changing it. A client that opened the same file twice
        /// under one lease key is one client, and breaking its own cache
        /// because of its own write would be round trips for nothing.
        fn breakGrants(s: *Self, open: *const Open) void {
            if (s.grant_count == 0) return;
            var index = s.grant_count;
            while (index > 0) {
                index -= 1;
                const grant = s.grants[index];
                if (grant.share != open.share or grant.path_hash != open.path_hash) continue;
                if (grant.owner == open.id) continue;
                if (grant.is_lease and open.has_lease and
                    std.mem.eql(u8, &grant.lease_key, &open.lease_key)) continue;

                if (s.break_count < limits.max_oplocks) {
                    s.breaks[s.break_count] = .{
                        .conn = grant.conn,
                        .session_id = grant.session_id,
                        .tree_id = grant.tree_id,
                        .file_id = grant.owner,
                        .lease_key = grant.lease_key,
                        .is_lease = grant.is_lease,
                    };
                    s.break_count += 1;
                } else {
                    // Unreachable by construction — a grant is dropped as it is
                    // queued, so the queue can hold every grant at once. If it
                    // ever were not, a client has to lose its connection rather
                    // than go on caching a file that has changed underneath it.
                    s.conns[grant.conn].closing = true;
                }
                s.grant_count -= 1;
                s.grants[index] = s.grants[s.grant_count];
            }
        }

        /// Moves a handle, and everything keyed to where it used to be, onto
        /// its new name. A lock or a grant left behind on the old path would
        /// guard a name nothing answers to any more.
        fn renameOpen(s: *Self, open: *Open, path_hash: u64) void {
            open.path_hash = path_hash;
            for (s.locks[0..s.lock_count]) |*lock| {
                if (lock.owner == open.id) lock.path_hash = path_hash;
            }
            for (s.grants[0..s.grant_count]) |*grant| {
                if (grant.owner == open.id) grant.path_hash = path_hash;
            }
        }

        /// A handle's grant goes when the handle does. Nothing is sent: the
        /// client asking for the close is the one that held it.
        fn releaseGrant(s: *Self, owner: u64) void {
            if (s.grant_count == 0) return;
            var index = s.grant_count;
            while (index > 0) {
                index -= 1;
                if (s.grants[index].owner != owner) continue;
                s.grant_count -= 1;
                s.grants[index] = s.grants[s.grant_count];
            }
        }

        /// A client acknowledging a break it was never asked to acknowledge.
        /// Nothing this server grants requires one, so there is nothing to
        /// undo; the answer exists so the client stops waiting for it.
        fn writeBreakAck(ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            switch (structure_size) {
                24 => {
                    r.skip(6) catch return status.INVALID_PARAMETER; // OplockLevel, Reserved
                    const raw_id = r.take(16) catch return status.INVALID_PARAMETER;
                    ctx.w.u16_(24) catch return status.INSUFF_SERVER_RESOURCES;
                    ctx.w.u8_(oplock_level.none) catch return status.INSUFF_SERVER_RESOURCES;
                    ctx.w.u8_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved
                    ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved2
                    ctx.w.blob(raw_id) catch return status.INSUFF_SERVER_RESOURCES;
                },
                36 => {
                    r.skip(6) catch return status.INVALID_PARAMETER; // Reserved, Flags
                    const key = r.take(16) catch return status.INVALID_PARAMETER;
                    ctx.w.u16_(36) catch return status.INSUFF_SERVER_RESOURCES;
                    ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved
                    ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Flags
                    ctx.w.blob(key) catch return status.INSUFF_SERVER_RESOURCES;
                    ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // LeaseState: none
                    ctx.w.u64_(0) catch return status.INSUFF_SERVER_RESOURCES; // LeaseDuration
                },
                else => return status.INVALID_PARAMETER,
            }
            return status.SUCCESS;
        }

        // ------------------------------------------------------ server-side copy

        const fsctl = struct {
            const request_resume_key: u32 = 0x0014_0078;
            const copychunk: u32 = 0x0014_40F2;
            const copychunk_write: u32 = 0x0014_80F2;
        };

        /// What one server-side copy may ask for. These are the numbers Windows
        /// uses, so a client sized for a Windows server never exceeds them.
        const copychunk_limits = struct {
            const chunks: u32 = 16;
            const chunk_bytes: u64 = 1024 * 1024;
            const total_bytes: u64 = 16 * 1024 * 1024;
        };

        const resume_key_size = 24;
        const copychunk_header = 32;
        const copychunk_element = 24;

        /// Control codes, of which this server implements the two that matter:
        /// the pair that lets a client copy a file without the bytes leaving
        /// the machine. Everything else is refused rather than half-answered.
        fn handleIoctl(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 57) return status.INVALID_PARAMETER;
            _ = r.u16_() catch return status.INVALID_PARAMETER; // Reserved
            const code = r.u32_() catch return status.INVALID_PARAMETER;
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;
            const input_offset = r.u32_() catch return status.INVALID_PARAMETER;
            const input_count = r.u32_() catch return status.INVALID_PARAMETER;

            switch (code) {
                fsctl.request_resume_key, fsctl.copychunk, fsctl.copychunk_write => {},
                // Said plainly, because a client that is told no falls back to
                // reading and writing the bytes itself, which always works.
                else => return status.NOT_SUPPORTED,
            }

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;

            ctx.w.u16_(49) catch return status.INSUFF_SERVER_RESOURCES; // StructureSize
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved
            ctx.w.u32_(code) catch return status.INSUFF_SERVER_RESOURCES;
            writeFileId(ctx.w, open.id) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // InputOffset
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // InputCount
            const output_at = ctx.w.pos;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // OutputOffset, patched below
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // OutputCount, patched below
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Flags
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Reserved2

            const buffer_at = ctx.rel();
            const result = switch (code) {
                fsctl.request_resume_key => s.writeResumeKey(ctx, open),
                else => s.copyChunks(ctx, open, input_offset, input_count),
            };
            if (result != status.SUCCESS) return result;

            ctx.w.patchInt(u32, output_at, buffer_at) catch {};
            ctx.w.patchInt(u32, output_at + 4, ctx.rel() - buffer_at) catch {};
            return status.SUCCESS;
        }

        /// Names an open handle so a later copy can quote it as the source. The
        /// name is the handle plus a secret this server made at startup, so it
        /// cannot be worked out from a FileId a client has seen.
        fn writeResumeKey(s: *Self, ctx: *Ctx, open: *const Open) u32 {
            var key: [resume_key_size]u8 = @splat(0);
            std.mem.writeInt(u64, key[0..8], open.id, .little);
            @memcpy(key[8..16], &s.resume_salt);
            ctx.w.blob(&key) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // ContextLength
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // Context
            return status.SUCCESS;
        }

        /// The handle a resume key names, if it is one this session opened.
        /// Another session's handle is not reachable this way: a copy is a read
        /// and a write, and both have to be things this client may do.
        fn openForResumeKey(s: *const Self, session: *Session, key: []const u8) ?*Open {
            if (key.len < resume_key_size) return null;
            if (!std.mem.eql(u8, key[8..16], &s.resume_salt)) return null;
            const id = std.mem.readInt(u64, key[0..8], .little);
            const index = id & slot_mask;
            if (index >= session.opens.len) return null;
            const open = &session.opens[@intCast(index)];
            if (!open.active or open.id != id) return null;
            return open;
        }

        /// Copies ranges from one open file to another without the bytes ever
        /// leaving this machine. macOS asks for this on every copy inside a
        /// share; refusing it means the client reads a gigabyte over the
        /// network and writes it straight back.
        fn copyChunks(s: *Self, ctx: *Ctx, target: *Open, input_offset: u32, input_count: u32) u32 {
            const request = wire.Reader.init(ctx.msg);
            const input = request.sliceAt(input_offset, input_count) catch return status.INVALID_PARAMETER;
            if (input.len < copychunk_header) return status.INVALID_PARAMETER;

            const session = ctx.session.?;
            const source = openForResumeKey(s, session, input[0..resume_key_size]) orelse
                return status.OBJECT_NAME_NOT_FOUND;

            const count = std.mem.readInt(u32, input[24..28], .little);
            if (count == 0 or count > copychunk_limits.chunks) return status.INVALID_PARAMETER;
            if (input.len < copychunk_header + count * copychunk_element) return status.INVALID_PARAMETER;

            if (session.account.read_only) return status.ACCESS_DENIED;
            if (target.is_dir or source.is_dir) return status.INVALID_DEVICE_REQUEST;
            if (!target.can_write) return status.ACCESS_DENIED;
            if (!source.can_read) return status.ACCESS_DENIED;

            var total: u64 = 0;
            for (0..count) |index| {
                const at = input[copychunk_header + index * copychunk_element ..];
                const chunk = .{
                    .source = std.mem.readInt(u64, at[0..8], .little),
                    .target = std.mem.readInt(u64, at[8..16], .little),
                    .length = std.mem.readInt(u32, at[16..20], .little),
                };
                if (chunk.length > copychunk_limits.chunk_bytes) return status.INVALID_PARAMETER;
                total += chunk.length;
                if (total > copychunk_limits.total_bytes) return status.INVALID_PARAMETER;
                if (s.lockedAgainst(source, chunk.source, chunk.length, false)) return status.FILE_LOCK_CONFLICT;
                if (s.lockedAgainst(target, chunk.target, chunk.length, true)) return status.FILE_LOCK_CONFLICT;
            }

            const from = s.shares[source.share];
            const to = s.shares[target.share];
            var moved: u64 = 0;
            for (0..count) |index| {
                const at = input[copychunk_header + index * copychunk_element ..];
                const source_offset = std.mem.readInt(u64, at[0..8], .little);
                const target_offset = std.mem.readInt(u64, at[8..16], .little);
                const length = std.mem.readInt(u32, at[16..20], .little);

                var done: u64 = 0;
                while (done < length) {
                    const piece = @min(length - done, limits.copy_buffer);
                    const got = from.read(source.handle, source_offset + done, s.copy[0..piece]) catch |err|
                        return Share.statusFor(err);
                    if (got == 0) break; // the source ended sooner than the client thought
                    const put = to.write(target.handle, target_offset + done, s.copy[0..got]) catch |err|
                        return Share.statusFor(err);
                    done += put;
                    if (put < got) break;
                }
                moved += done;
            }

            s.breakGrants(target);
            s.noteOpenChange(target, notify_action.modified, notify_filter.last_write | notify_filter.size);

            ctx.w.u32_(@intCast(count)) catch return status.INSUFF_SERVER_RESOURCES; // ChunksWritten
            ctx.w.u32_(0) catch return status.INSUFF_SERVER_RESOURCES; // ChunkBytesWritten
            ctx.w.u32_(@intCast(moved)) catch return status.INSUFF_SERVER_RESOURCES; // TotalBytesWritten
            return status.SUCCESS;
        }

        // ------------------------------------------------------ change notify

        /// What a client asks to hear about.
        const notify_filter = struct {
            const file_name: u32 = 0x0000_0001;
            const dir_name: u32 = 0x0000_0002;
            const attributes: u32 = 0x0000_0004;
            const size: u32 = 0x0000_0008;
            const last_write: u32 = 0x0000_0010;
        };

        /// What happened, in the words MS-FSCC uses for it.
        const notify_action = struct {
            const added: u32 = 0x0000_0001;
            const removed: u32 = 0x0000_0002;
            const modified: u32 = 0x0000_0003;
            const renamed_old: u32 = 0x0000_0004;
            const renamed_new: u32 = 0x0000_0005;
        };

        /// Accepts a request that cannot be answered yet.
        ///
        /// The answer is a change nobody has made, so the client is told the
        /// request is alive and given a name for it. What comes back later is
        /// the same message id and the same name, carrying the change — or a
        /// reason there will never be one, if the handle closes or the client
        /// changes its mind.
        fn handleChangeNotify(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 32) return status.INVALID_PARAMETER;
            const flags = r.u16_() catch return status.INVALID_PARAMETER;
            const output_length = r.u32_() catch return status.INVALID_PARAMETER;
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;
            const filter = r.u32_() catch return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            // Watching anything but a directory is not a thing a client can ask
            // for, and a file handle here means the client is confused.
            if (!open.is_dir) return status.INVALID_PARAMETER;
            if (filter == 0) return status.INVALID_PARAMETER;
            if (s.watch_count == limits.max_watches) return status.INSUFF_SERVER_RESOURCES;

            const watch = &s.watches[s.watch_count];
            watch.* = .{
                .conn = ctx.conn.token,
                .session_id = ctx.session.?.id,
                .message_id = ctx.head.message_id,
                .async_id = s.nextId(),
                .owner = open.id,
                .share = open.share,
                .path_len = open.path_len,
                .watch_tree = flags & 0x0001 != 0,
                .filter = filter,
                .output_limit = output_length,
            };
            @memcpy(watch.path[0..open.path_len], open.path_());
            s.watch_count += 1;

            ctx.async_id = watch.async_id;
            return status.PENDING;
        }

        /// The name a change has inside a watched directory, or nothing if it
        /// did not happen there. The share root is the empty path, so
        /// everything is somewhere inside it.
        fn relativeTo(dir: []const u8, path: []const u8, watch_tree: bool) ?[]const u8 {
            var rest = path;
            if (dir.len != 0) {
                if (path.len <= dir.len + 1) return null;
                if (!std.mem.startsWith(u8, path, dir)) return null;
                if (path[dir.len] != '/') return null;
                rest = path[dir.len + 1 ..];
            }
            // Without WATCH_TREE the client asked about this directory, not
            // about the directories inside it.
            if (!watch_tree and std.mem.indexOfScalar(u8, rest, '/') != null) return null;
            return rest;
        }

        /// Records what a waiting client is about to be told. The first change
        /// wins: the answer carries one, and the client asks again immediately
        /// after reading it.
        fn arm(watch: *Watch, code: u32, action: u32, name: []const u8) void {
            if (watch.fired) return;
            watch.fired = true;
            watch.fired_status = code;
            watch.action = action;
            const length = @min(name.len, watch.name.len);
            @memcpy(watch.name[0..length], name[0..length]);
            watch.name_len = length;
        }

        /// Something happened to a path; whoever asked to hear about it does.
        ///
        /// Only changes made through this server are seen. A file changed
        /// directly on the disk underneath it is invisible, because the share
        /// adapter deliberately hands out no filesystem to watch — the price of
        /// a share being allowed to be something other than a directory.
        fn noteChange(s: *Self, share_index: usize, path: []const u8, action: u32, filter: u32) void {
            if (s.watch_count == 0) return;
            for (s.watches[0..s.watch_count]) |*watch| {
                if (watch.fired) continue;
                if (watch.share != share_index) continue;
                if (watch.filter & filter == 0) continue;
                const name = relativeTo(watch.path_(), path, watch.watch_tree) orelse continue;
                arm(watch, status.SUCCESS, action, name);
            }
        }

        /// The same, for a change described by the handle that made it.
        fn noteOpenChange(s: *Self, open: *const Open, action: u32, filter: u32) void {
            s.noteChange(open.share, open.path_(), action, filter);
        }

        /// A client taking back a request. Nothing else outstanding can be
        /// cancelled, because nothing else is ever left unanswered.
        fn cancelWatch(s: *Self, c: *Conn, head: hdr.Header) void {
            for (s.watches[0..s.watch_count]) |*watch| {
                if (watch.conn != c.token) continue;
                const named = if (head.flags & hdr.flags.ASYNC_COMMAND != 0)
                    watch.async_id == head.async_id
                else
                    watch.message_id == head.message_id;
                if (!named) continue;
                arm(watch, status.CANCELLED, 0, "");
                return;
            }
        }

        /// Closing the directory ends the wait on it — with an answer, because
        /// a client that hears nothing waits forever.
        fn endWatches(s: *Self, owner: u64) void {
            if (s.watch_count == 0) return;
            for (s.watches[0..s.watch_count]) |*watch| {
                if (watch.owner == owner) arm(watch, status.NOTIFY_CLEANUP, 0, "");
            }
        }

        fn dropWatches(s: *Self, token: poller_mod.Token) void {
            if (s.watch_count == 0) return;
            var index = s.watch_count;
            while (index > 0) {
                index -= 1;
                if (s.watches[index].conn != token) continue;
                s.watch_count -= 1;
                s.watches[index] = s.watches[s.watch_count];
            }
        }

        /// Sends the second half of every request that now has an answer, after
        /// the frame that produced it — same reason as a break.
        fn deliverNotifications(s: *Self) void {
            if (s.watch_count == 0) return;
            var index = s.watch_count;
            while (index > 0) {
                index -= 1;
                if (!s.watches[index].fired) continue;
                const watch = s.watches[index];
                s.watch_count -= 1;
                s.watches[index] = s.watches[s.watch_count];

                const c = &s.conns[watch.conn];
                if (!c.active or c.closing) continue;
                s.sendNotification(c, &watch);
                s.flush(c);
            }
        }

        fn sendNotification(s: *Self, c: *Conn, watch: *const Watch) void {
            // A change is described by a record no longer than the path that
            // changed, and the transport and header in front of it.
            var name_utf16: [limits.path_bytes * 2]u8 = undefined;
            var name: []const u8 = &.{};
            if (watch.fired_status == status.SUCCESS) {
                var windows_name: [limits.path_bytes]u8 = undefined;
                const utf8 = watch.name_();
                for (utf8, 0..) |byte, i| windows_name[i] = if (byte == '/') '\\' else byte;
                name = unicode.toUtf16le(&name_utf16, windows_name[0..utf8.len]) catch return;
            }

            const record = if (name.len == 0) 0 else 12 + name.len;
            const body = if (watch.fired_status == status.SUCCESS) 8 + record else 9;
            if (limits.out_buffer - c.out_len < hdr.transport_header_size + hdr.header_size + body) {
                log.warn("connection {d}: no room for a change notification", .{c.token});
                c.closing = true;
                return;
            }

            var w = wire.Writer.init(c.out[0..limits.out_buffer]);
            w.pos = c.out_len;
            const frame_at = w.pos;
            w.zeroes(hdr.transport_header_size) catch return;
            const start = w.pos;

            // A record the client left no room for is not an error: it is told
            // to look at the directory again instead.
            const code = if (watch.fired_status == status.SUCCESS and record > watch.output_limit)
                status.NOTIFY_ENUM_DIR
            else
                watch.fired_status;

            hdr.write(&w, .{
                .status = code,
                .command = .change_notify,
                .credits = 1,
                .flags = hdr.flags.SERVER_TO_REDIR | hdr.flags.ASYNC_COMMAND,
                .message_id = watch.message_id,
                .async_id = watch.async_id,
                .session_id = watch.session_id,
            }) catch return;

            if (code == status.SUCCESS) {
                w.u16_(9) catch return; // StructureSize
                w.u16_(hdr.header_size + 8) catch return; // OutputBufferOffset
                w.u32_(@intCast(record)) catch return; // OutputBufferLength
                w.u32_(0) catch return; // NextEntryOffset: one change per answer
                w.u32_(watch.action) catch return;
                w.u32_(@intCast(name.len)) catch return; // FileNameLength, in bytes
                w.blob(name) catch return;
            } else {
                writeErrorBody(&w) catch return;
            }

            const message = w.buf[start..w.pos];
            s.signBreak(c, watch.session_id, message);
            hdr.writeFrameLength(w.buf[frame_at..][0..4], @intCast(message.len));
            c.out_len = w.pos;
            log.debug("connection {d}: change notified (0x{x:0>8})", .{ c.token, code });
        }

        // ------------------------------------------------------ byte-range locks

        const lock_flags = struct {
            const SHARED: u32 = 0x0000_0001;
            const EXCLUSIVE: u32 = 0x0000_0002;
            const UNLOCK: u32 = 0x0000_0004;
            const FAIL_IMMEDIATELY: u32 = 0x0000_0010;

            const kind: u32 = SHARED | EXCLUSIVE | UNLOCK;
        };

        const lock_element_size = 24;

        const LockElement = struct {
            offset: u64,
            length: u64,
            flags: u32,
        };

        fn lockElement(elements: []const u8, index: usize) LockElement {
            const at = elements[index * lock_element_size ..][0..lock_element_size];
            return .{
                .offset = std.mem.readInt(u64, at[0..8], .little),
                .length = std.mem.readInt(u64, at[8..16], .little),
                .flags = std.mem.readInt(u32, at[16..20], .little),
            };
        }

        /// Whether two ranges touch. A client that means "the whole file" sends
        /// a length of 0xFFFFFFFFFFFFFFFF, so the ends saturate rather than
        /// wrap — wrapping would turn the largest possible lock into no lock.
        fn rangesOverlap(a_offset: u64, a_length: u64, b_offset: u64, b_length: u64) bool {
            return a_offset < b_offset +| b_length and b_offset < a_offset +| a_length;
        }

        fn handleLock(s: *Self, ctx: *Ctx) u32 {
            var r = wire.Reader.init(ctx.body);
            const structure_size = r.u16_() catch return status.INVALID_PARAMETER;
            if (structure_size != 48) return status.INVALID_PARAMETER;
            const count = r.u16_() catch return status.INVALID_PARAMETER;
            _ = r.u32_() catch return status.INVALID_PARAMETER; // LockSequence
            const raw_id = r.take(16) catch return status.INVALID_PARAMETER;
            if (count == 0) return status.INVALID_PARAMETER;

            const open = findOpen(ctx, raw_id) orelse return status.FILE_CLOSED;
            if (open.is_dir) return status.INVALID_DEVICE_REQUEST;

            const elements = r.take(@as(usize, count) * lock_element_size) catch
                return status.INVALID_PARAMETER;

            // One request either takes locks or drops them; MS-SMB2 does not
            // allow a mixture, and the two halves have different failure modes.
            const unlocking = lockElement(elements, 0).flags & lock_flags.UNLOCK != 0;
            const code = if (unlocking)
                s.unlockRanges(open, elements, count)
            else
                s.lockRanges(open, elements, count);
            if (code != status.SUCCESS) return code;

            ctx.w.u16_(4) catch return status.INSUFF_SERVER_RESOURCES;
            ctx.w.u16_(0) catch return status.INSUFF_SERVER_RESOURCES;
            return status.SUCCESS;
        }

        /// Takes every lock in the request or none of them. A client told its
        /// request failed will not send an unlock for the parts that happened
        /// to succeed, so a half-applied request is a lock nobody can release.
        ///
        /// Rolling back is a truncation because taking locks only ever appends.
        fn lockRanges(s: *Self, open: *const Open, elements: []const u8, count: u16) u32 {
            const before = s.lock_count;
            for (0..count) |index| {
                const element = lockElement(elements, index);
                const exclusive = switch (element.flags & lock_flags.kind) {
                    lock_flags.SHARED => false,
                    lock_flags.EXCLUSIVE => true,
                    else => {
                        s.lock_count = before;
                        return status.INVALID_PARAMETER;
                    },
                };
                if (s.lock_count == limits.max_locks) {
                    s.lock_count = before;
                    return status.INSUFF_SERVER_RESOURCES;
                }
                if (s.lockConflict(open, element.offset, element.length, exclusive)) {
                    s.lock_count = before;
                    // A client that leaves FAIL_IMMEDIATELY off is asking to
                    // wait for the holder to let go. There is nowhere to park a
                    // half-answered request here, and a client left waiting for
                    // an answer that never comes is worse off than one told no.
                    return status.LOCK_NOT_GRANTED;
                }
                s.locks[s.lock_count] = .{
                    .share = open.share,
                    .path_hash = open.path_hash,
                    .owner = open.id,
                    .offset = element.offset,
                    .length = element.length,
                    .exclusive = exclusive,
                };
                s.lock_count += 1;
            }
            return status.SUCCESS;
        }

        /// Drops every range in the request, or leaves them all alone: the same
        /// all-or-nothing rule, which is why nothing is removed until every
        /// range has been matched to a lock this handle holds.
        fn unlockRanges(s: *Self, open: *const Open, elements: []const u8, count: u16) u32 {
            var claimed = std.StaticBitSet(limits.max_locks).initEmpty();
            for (0..count) |index| {
                const element = lockElement(elements, index);
                if (element.flags & lock_flags.kind != lock_flags.UNLOCK) return status.INVALID_PARAMETER;
                const held = s.findLock(open, element.offset, element.length, claimed) orelse
                    return status.RANGE_NOT_LOCKED;
                claimed.set(held);
            }
            s.dropLocks(claimed);
            return status.SUCCESS;
        }

        /// The lock this handle holds over exactly this range, skipping the
        /// ones an earlier range in the same request already spoke for — two
        /// identical shared locks are two locks, and one unlock drops one.
        fn findLock(
            s: *const Self,
            open: *const Open,
            offset: u64,
            length: u64,
            claimed: std.StaticBitSet(limits.max_locks),
        ) ?usize {
            for (s.locks[0..s.lock_count], 0..) |lock, index| {
                if (claimed.isSet(index)) continue;
                if (lock.owner != open.id) continue;
                if (lock.offset == offset and lock.length == length) return index;
            }
            return null;
        }

        /// Removes the marked locks by swapping the last one into each hole.
        /// Backwards, so that everything above the hole has already gone and a
        /// swap can never move a lock that is still waiting to be removed.
        fn dropLocks(s: *Self, marked: std.StaticBitSet(limits.max_locks)) void {
            var index = s.lock_count;
            while (index > 0) {
                index -= 1;
                if (!marked.isSet(index)) continue;
                s.lock_count -= 1;
                s.locks[index] = s.locks[s.lock_count];
            }
        }

        /// Everything a handle held goes when the handle does. A lock that
        /// outlived its handle could never be released: the only key to it is a
        /// FileId that has stopped existing.
        fn releaseLocks(s: *Self, owner: u64) void {
            if (s.lock_count == 0) return;
            var index = s.lock_count;
            while (index > 0) {
                index -= 1;
                if (s.locks[index].owner != owner) continue;
                s.lock_count -= 1;
                s.locks[index] = s.locks[s.lock_count];
            }
        }

        /// Whether a new lock would collide with one already held. Two shared
        /// locks never collide; anything else overlapping does, including a
        /// second lock from the same handle, which is what Windows does and
        /// what a client that tracks its own locks expects.
        fn lockConflict(s: *const Self, open: *const Open, offset: u64, length: u64, exclusive: bool) bool {
            for (s.locks[0..s.lock_count]) |lock| {
                if (lock.share != open.share or lock.path_hash != open.path_hash) continue;
                if (!exclusive and !lock.exclusive) continue;
                if (rangesOverlap(offset, length, lock.offset, lock.length)) return true;
            }
            return false;
        }

        /// Whether some *other* handle's lock stands in the way of this I/O.
        /// Reads are stopped only by an exclusive lock; writes by any lock. A
        /// handle is never blocked by a lock it took itself — that is what
        /// taking the lock was for.
        ///
        /// This runs on every read and every write, so it begins by asking
        /// whether anything is locked at all: on a share nobody locks, which is
        /// most of them, the cost is one load and one branch.
        fn lockedAgainst(s: *const Self, open: *const Open, offset: u64, length: u64, writing: bool) bool {
            if (s.lock_count == 0) return false;
            for (s.locks[0..s.lock_count]) |lock| {
                if (lock.owner == open.id) continue;
                if (lock.share != open.share or lock.path_hash != open.path_hash) continue;
                if (!writing and !lock.exclusive) continue;
                if (rangesOverlap(offset, length, lock.offset, lock.length)) return true;
            }
            return false;
        }
    };
}
