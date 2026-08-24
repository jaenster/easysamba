//! Bare non-blocking TCP sockets. Zero heap, no allocator.
//!
//! Zig 0.16 moved socket/bind/listen/accept/close out of `std.posix` and behind
//! `std.Io`, which implies an event loop we do not want. So: raw syscalls on
//! Linux (no libc), libc on macOS/BSD (no stable syscall ABI there).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const c = std.c;

const use_linux_syscalls = builtin.os.tag == .linux;

pub const Handle = posix.fd_t;

pub const invalid: Handle = -1;

pub const Error = error{
    SocketFailed,
    BindFailed,
    ListenFailed,
    AddressInUse,
    NonBlockFailed,
    BadAddress,
    ConnectFailed,
};

pub const Address = union(enum) {
    ip4: struct { addr: [4]u8, port: u16 },
    ip6: struct { addr: [16]u8, port: u16 },

    /// Accepts dotted-quad IPv4, bracketed or bare IPv6, and the wildcards
    /// "" / "*" / "::" / "0.0.0.0".
    ///
    /// "" and "*" resolve to the IPv6 wildcard: a dual-stack wildcard socket
    /// accepts IPv4 too (see `listenTcp`), so the pod need not know whether the
    /// cluster hands out v4 or v6.
    pub fn parse(text: []const u8, port: u16) Error!Address {
        if (text.len == 0 or std.mem.eql(u8, text, "*")) {
            return .{ .ip6 = .{ .addr = @splat(0), .port = port } };
        }
        const body = if (text.len >= 2 and text[0] == '[' and text[text.len - 1] == ']')
            text[1 .. text.len - 1]
        else
            text;

        if (std.mem.indexOfScalar(u8, body, ':') != null) {
            return .{ .ip6 = .{ .addr = try parseIp6(body), .port = port } };
        }
        return .{ .ip4 = .{ .addr = try parseIp4(body), .port = port } };
    }

    pub fn getPort(a: Address) u16 {
        return switch (a) {
            inline else => |v| v.port,
        };
    }
};

fn parseIp4(text: []const u8) Error![4]u8 {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return error.BadAddress;
        octets[i] = std.fmt.parseInt(u8, part, 10) catch return error.BadAddress;
    }
    if (i != 4) return error.BadAddress;
    return octets;
}

/// Handles the "::" zero-run elision and a trailing "%scope" (accepted and
/// ignored; a server binds by address).
fn parseIp6(text: []const u8) Error![16]u8 {
    const body = if (std.mem.indexOfScalar(u8, text, '%')) |i| text[0..i] else text;

    var out: [16]u8 = @splat(0);

    const elide = std.mem.indexOf(u8, body, "::");
    const head = if (elide) |i| body[0..i] else body;
    const tail = if (elide) |i| body[i + 2 ..] else "";

    var n_head: usize = 0;
    if (head.len > 0) {
        var it = std.mem.splitScalar(u8, head, ':');
        while (it.next()) |part| {
            if (n_head >= 8) return error.BadAddress;
            const group = std.fmt.parseInt(u16, part, 16) catch return error.BadAddress;
            std.mem.writeInt(u16, out[n_head * 2 ..][0..2], group, .big);
            n_head += 1;
        }
    }

    var n_tail: usize = 0;
    if (tail.len > 0) {
        var groups: [8]u16 = undefined;
        var it = std.mem.splitScalar(u8, tail, ':');
        while (it.next()) |part| {
            if (n_tail >= 8) return error.BadAddress;
            groups[n_tail] = std.fmt.parseInt(u16, part, 16) catch return error.BadAddress;
            n_tail += 1;
        }
        if (n_head + n_tail > 8) return error.BadAddress;
        for (groups[0..n_tail], 0..) |group, i| {
            const slot = 8 - n_tail + i;
            std.mem.writeInt(u16, out[slot * 2 ..][0..2], group, .big);
        }
    }

    if (elide == null and n_head != 8) return error.BadAddress;
    if (elide != null and n_head + n_tail > 7) return error.BadAddress;
    return out;
}

/// Creates a listening, non-blocking TCP socket. An IPv6 wildcard bind clears
/// IPV6_V6ONLY so one socket serves both families, with IPv4 peers arriving
/// v4-mapped.
pub fn listenTcp(address: Address, backlog: u31) Error!Handle {
    const family: u32 = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };

    const fd = try createSocket(family);
    errdefer close(fd);

    setSockOpt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);
    if (address == .ip6 and std.mem.allEqual(u8, &address.ip6.addr, 0)) {
        setSockOpt(fd, IPPROTO_IPV6, IPV6_V6ONLY, 0);
    }

    switch (address) {
        .ip4 => |v| {
            var sa: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
            sa.family = posix.AF.INET;
            sa.port = std.mem.nativeToBig(u16, v.port);
            sa.addr = @bitCast(v.addr);
            if (@hasField(posix.sockaddr.in, "len")) sa.len = @sizeOf(posix.sockaddr.in);
            try bindSocket(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
        },
        .ip6 => |v| {
            var sa: posix.sockaddr.in6 = std.mem.zeroes(posix.sockaddr.in6);
            sa.family = posix.AF.INET6;
            sa.port = std.mem.nativeToBig(u16, v.port);
            sa.addr = v.addr;
            if (@hasField(posix.sockaddr.in6, "len")) sa.len = @sizeOf(posix.sockaddr.in6);
            try bindSocket(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6));
        },
    }

    try listenSocket(fd, backlog);
    if (!setNonBlock(fd)) return error.NonBlockFailed;
    return fd;
}

/// Accepts one pending connection, already non-blocking. Null means the backlog
/// is empty — the normal way to end an accept loop. A connection that died
/// before we accepted it is also null: it must not tear down the listener.
/// Starts a non-blocking outbound connection. The fd returns before the
/// handshake finishes: register it for writability and, when it fires, check
/// `connectError` — zero means connected, anything else is the failure. This is
/// how a node dials its peers.
pub fn connectTcp(address: Address) Error!Handle {
    const family: u32 = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const fd = try createSocket(family);
    errdefer close(fd);
    setNoDelay(fd);

    const rc: isize = switch (address) {
        .ip4 => |v| blk: {
            var sa: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
            sa.family = posix.AF.INET;
            sa.port = std.mem.nativeToBig(u16, v.port);
            sa.addr = @bitCast(v.addr);
            if (@hasField(posix.sockaddr.in, "len")) sa.len = @sizeOf(posix.sockaddr.in);
            break :blk doConnect(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
        },
        .ip6 => |v| blk: {
            var sa: posix.sockaddr.in6 = std.mem.zeroes(posix.sockaddr.in6);
            sa.family = posix.AF.INET6;
            sa.port = std.mem.nativeToBig(u16, v.port);
            sa.addr = v.addr;
            if (@hasField(posix.sockaddr.in6, "len")) sa.len = @sizeOf(posix.sockaddr.in6);
            break :blk doConnect(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6));
        },
    };

    // Connected immediately (loopback), or in progress — both fine. Any other
    // errno is a hard failure (no route, refused synchronously).
    if (rc < 0) {
        const e = if (use_linux_syscalls) linux.errno(@as(usize, @bitCast(rc))) else c.errno(@as(c_int, -1));
        if (e != .INPROGRESS) return error.ConnectFailed;
    }
    if (!setNonBlock(fd)) return error.NonBlockFailed;
    return fd;
}

fn doConnect(fd: Handle, sa: *const posix.sockaddr, len: u32) isize {
    if (use_linux_syscalls) return @bitCast(linux.connect(fd, sa, len));
    return c.connect(fd, sa, len);
}

/// The pending error on a socket, read after it first becomes writable. Zero
/// means the connection succeeded.
pub fn connectError(fd: Handle) c_int {
    var v: c_int = 0;
    var len: u32 = @sizeOf(c_int);
    if (use_linux_syscalls) {
        _ = linux.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&v), &len);
    } else {
        _ = c.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&v), &len);
    }
    return v;
}

pub fn accept(listen_fd: Handle) ?Handle {
    if (use_linux_syscalls) {
        // accept4 sets both flags atomically; the libc path below needs a second
        // syscall and briefly holds a blocking fd.
        const flags = linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
        const rc = linux.accept4(listen_fd, null, null, flags);
        return switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => null,
        };
    }
    const fd = c.accept(listen_fd, null, null);
    if (fd < 0) return null;
    if (!setNonBlock(fd)) {
        close(fd);
        return null;
    }
    return fd;
}

pub const Io = enum {
    eof,
    /// Nothing to do right now; wait for the poller to say otherwise.
    would_block,
    failed,
};

pub const ReadResult = union(enum) {
    read: usize,
    status: Io,
};

pub fn read(fd: Handle, buf: []u8) ReadResult {
    const rc: isize = if (use_linux_syscalls)
        @bitCast(linux.read(fd, buf.ptr, buf.len))
    else
        c.read(fd, buf.ptr, buf.len);

    if (rc > 0) return .{ .read = @intCast(rc) };
    if (rc == 0) return .{ .status = .eof };
    return .{ .status = if (wouldBlock(rc)) .would_block else .failed };
}

pub const WriteResult = union(enum) {
    /// Bytes accepted by the kernel. May be short: the rest must be parked and
    /// retried on writable.
    wrote: usize,
    status: Io,
};

pub fn write(fd: Handle, buf: []const u8) WriteResult {
    const rc: isize = if (use_linux_syscalls)
        @bitCast(linux.write(fd, buf.ptr, buf.len))
    else
        c.write(fd, buf.ptr, buf.len);

    if (rc >= 0) return .{ .wrote = @intCast(rc) };
    return .{ .status = if (wouldBlock(rc)) .would_block else .failed };
}

/// Writing to a peer that has already closed raises SIGPIPE, whose default
/// action is to kill the process — so one client disconnecting at the wrong
/// instant would take the whole server down. The broken pipe is already
/// reported through `write` returning `.failed`, so the signal is pure
/// downside: ignore it process-wide once at startup.
pub fn ignoreSigpipe() void {
    if (use_linux_syscalls) {
        var act = std.mem.zeroes(linux.Sigaction);
        act.handler.handler = linux.SIG.IGN;
        _ = linux.sigaction(linux.SIG.PIPE, &act, null);
    } else {
        var act = std.mem.zeroes(c.Sigaction);
        act.handler.handler = c.SIG.IGN;
        _ = c.sigaction(c.SIG.PIPE, &act, null);
    }
}

pub fn close(fd: Handle) void {
    if (use_linux_syscalls) {
        _ = linux.close(fd);
    } else {
        _ = c.close(fd);
    }
}

pub const ShutdownHow = enum(c_int) { recv = 0, send = 1, both = 2 };

pub fn shutdown(fd: Handle, how: ShutdownHow) void {
    if (use_linux_syscalls) {
        _ = linux.shutdown(fd, @intFromEnum(how));
    } else {
        _ = c.shutdown(fd, @intFromEnum(how));
    }
}

/// Disables Nagle: our messages are small, latency-sensitive, and already
/// batched by the write path.
pub fn setNoDelay(fd: Handle) void {
    setSockOpt(fd, IPPROTO_TCP, TCP_NODELAY, 1);
}

pub fn peerAddress(fd: Handle) ?Address {
    var storage: posix.sockaddr.in6 = std.mem.zeroes(posix.sockaddr.in6);
    var len: u32 = @sizeOf(posix.sockaddr.in6);
    if (use_linux_syscalls) {
        const rc = linux.getpeername(fd, @ptrCast(&storage), &len);
        if (linux.errno(rc) != .SUCCESS) return null;
    } else {
        if (c.getpeername(fd, @ptrCast(&storage), &len) != 0) return null;
    }

    if (storage.family == posix.AF.INET) {
        const sa: *const posix.sockaddr.in = @ptrCast(@alignCast(&storage));
        return .{ .ip4 = .{
            .addr = @bitCast(sa.addr),
            .port = std.mem.bigToNative(u16, sa.port),
        } };
    }
    if (storage.family == posix.AF.INET6) {
        // A v4 peer on a dual-stack socket arrives v4-mapped (::ffff:a.b.c.d);
        // unwrap it, or hostmasks and ban masks break.
        if (isV4Mapped(storage.addr)) {
            return .{ .ip4 = .{
                .addr = storage.addr[12..16].*,
                .port = std.mem.bigToNative(u16, storage.port),
            } };
        }
        return .{ .ip6 = .{
            .addr = storage.addr,
            .port = std.mem.bigToNative(u16, storage.port),
        } };
    }
    return null;
}

fn isV4Mapped(addr: [16]u8) bool {
    return std.mem.allEqual(u8, addr[0..10], 0) and addr[10] == 0xff and addr[11] == 0xff;
}

/// Renders an address without the port. `buf` must be >= 46 bytes.
pub fn formatAddress(a: Address, buf: []u8) []const u8 {
    return switch (a) {
        .ip4 => |v| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            v.addr[0], v.addr[1], v.addr[2], v.addr[3],
        }) catch unreachable,
        .ip6 => |v| formatIp6(v.addr, buf),
    };
}

/// RFC 5952 form: lowercase hex, leading zeroes dropped, longest run of zero
/// groups (2 or more) collapsed to "::".
fn formatIp6(addr: [16]u8, buf: []u8) []const u8 {
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*g, i| g.* = std.mem.readInt(u16, addr[i * 2 ..][0..2], .big);

    var best_start: usize = 0;
    var best_len: usize = 0;
    var i: usize = 0;
    while (i < 8) {
        if (groups[i] != 0) {
            i += 1;
            continue;
        }
        const start = i;
        while (i < 8 and groups[i] == 0) i += 1;
        if (i - start > best_len) {
            best_start = start;
            best_len = i - start;
        }
    }
    if (best_len < 2) best_len = 0;

    var n: usize = 0;
    i = 0;
    while (i < 8) {
        if (best_len > 0 and i == best_start) {
            buf[n] = ':';
            buf[n + 1] = ':';
            n += 2;
            i += best_len;
            continue;
        }
        if (i > 0 and !(best_len > 0 and i == best_start + best_len)) {
            buf[n] = ':';
            n += 1;
        }
        n += (std.fmt.bufPrint(buf[n..], "{x}", .{groups[i]}) catch unreachable).len;
        i += 1;
    }
    return buf[0..n];
}

/// Monotonic ms, for deadlines: must not jump when the wall clock is adjusted.
pub fn monotonicMs() i64 {
    var ts: c.timespec = undefined;
    if (use_linux_syscalls) {
        _ = linux.clock_gettime(.MONOTONIC, @ptrCast(&ts));
    } else {
        _ = c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

/// Unix epoch ms. Only for wire timestamps that must be comparable across
/// nodes (IRCv3 server-time, TS6 conflict resolution).
pub fn realtimeMs() i64 {
    var ts: c.timespec = undefined;
    if (use_linux_syscalls) {
        _ = linux.clock_gettime(.REALTIME, @ptrCast(&ts));
    } else {
        _ = c.clock_gettime(.REALTIME, &ts);
    }
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

// Not exposed by std.posix on every target we build for.
const IPPROTO_TCP: u32 = 6;
const IPPROTO_IPV6: u32 = 41;
const TCP_NODELAY: u32 = 1;
const IPV6_V6ONLY: u32 = if (builtin.os.tag == .linux) 26 else 27;

fn createSocket(family: u32) Error!Handle {
    if (use_linux_syscalls) {
        const kind = linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
        const rc = linux.socket(family, kind, 0);
        return switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => error.SocketFailed,
        };
    }
    const fd = c.socket(@intCast(family), c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    return fd;
}

fn bindSocket(fd: Handle, sa: *const posix.sockaddr, len: u32) Error!void {
    if (use_linux_syscalls) {
        return switch (linux.errno(linux.bind(fd, sa, len))) {
            .SUCCESS => {},
            .ADDRINUSE => error.AddressInUse,
            else => error.BindFailed,
        };
    }
    if (c.bind(fd, sa, len) != 0) {
        return switch (c.errno(@as(c_int, -1))) {
            .ADDRINUSE => error.AddressInUse,
            else => error.BindFailed,
        };
    }
}

fn listenSocket(fd: Handle, backlog: u31) Error!void {
    if (use_linux_syscalls) {
        return switch (linux.errno(linux.listen(fd, backlog))) {
            .SUCCESS => {},
            else => error.ListenFailed,
        };
    }
    if (c.listen(fd, @intCast(backlog)) != 0) return error.ListenFailed;
}

fn setSockOpt(fd: Handle, level: u32, opt: u32, value: c_int) void {
    const v = value;
    if (use_linux_syscalls) {
        _ = linux.setsockopt(fd, @intCast(level), @intCast(opt), @ptrCast(&v), @sizeOf(c_int));
    } else {
        _ = c.setsockopt(fd, @intCast(level), @intCast(opt), @ptrCast(&v), @sizeOf(c_int));
    }
}

/// fcntl is variadic in C. On arm64 a variadic argument is passed on the stack,
/// so declaring it with a fixed third parameter puts the flags in the wrong
/// place and silently leaves the socket blocking.
extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;

fn setNonBlock(fd: Handle) bool {
    if (use_linux_syscalls) return true; // SOCK_NONBLOCK was set at creation.

    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0x0004; // darwin/BSD

    const flags = fcntl(fd, F_GETFL);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

fn wouldBlock(rc: isize) bool {
    const e = if (use_linux_syscalls) linux.errno(@as(usize, @bitCast(rc))) else c.errno(@as(c_int, -1));
    return e == .AGAIN or e == .INTR;
}

const testing = std.testing;

test "Address.parse: ipv4" {
    const a = try Address.parse("127.0.0.1", 6667);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, a.ip4.addr);
    try testing.expectEqual(@as(u16, 6667), a.getPort());

    const any = try Address.parse("0.0.0.0", 1);
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, any.ip4.addr);
}

test "Address.parse: wildcard defaults to dual-stack ipv6" {
    // A pod should not care whether the cluster hands out v4 or v6.
    for ([_][]const u8{ "", "*" }) |text| {
        const a = try Address.parse(text, 6667);
        try testing.expect(a == .ip6);
        try testing.expectEqual([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, a.ip6.addr);
    }
}

test "Address.parse: ipv6 loopback and elision" {
    const loop = try Address.parse("::1", 6667);
    try testing.expectEqual([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, loop.ip6.addr);

    const any = try Address.parse("::", 6667);
    try testing.expectEqual(@as([16]u8, @splat(0)), any.ip6.addr);

    const full = try Address.parse("2001:db8:0:0:0:0:0:1", 6667);
    try testing.expectEqual(@as(u8, 0x20), full.ip6.addr[0]);
    try testing.expectEqual(@as(u8, 0x01), full.ip6.addr[15]);

    const elided = try Address.parse("2001:db8::1", 6667);
    try testing.expectEqualSlices(u8, &full.ip6.addr, &elided.ip6.addr);

    const head_only = try Address.parse("fe80::", 6667);
    try testing.expectEqual(@as(u8, 0xfe), head_only.ip6.addr[0]);
    try testing.expectEqual(@as(u8, 0x80), head_only.ip6.addr[1]);
    try testing.expectEqual(@as(u8, 0), head_only.ip6.addr[15]);
}

test "Address.parse: bracketed ipv6 and scope suffix" {
    const bracketed = try Address.parse("[::1]", 6667);
    try testing.expectEqual(@as(u8, 1), bracketed.ip6.addr[15]);

    // A scope id is accepted and ignored; a server binds by address.
    const scoped = try Address.parse("fe80::1%eth0", 6667);
    try testing.expectEqual(@as(u8, 0xfe), scoped.ip6.addr[0]);
    try testing.expectEqual(@as(u8, 1), scoped.ip6.addr[15]);
}

test "Address.parse: rejects malformed input" {
    try testing.expectError(error.BadAddress, Address.parse("1.2.3", 1));
    try testing.expectError(error.BadAddress, Address.parse("1.2.3.4.5", 1));
    try testing.expectError(error.BadAddress, Address.parse("256.0.0.1", 1));
    try testing.expectError(error.BadAddress, Address.parse("1.2.3.x", 1));
    // Without "::" all eight groups are required.
    try testing.expectError(error.BadAddress, Address.parse("2001:db8:1", 1));
    try testing.expectError(error.BadAddress, Address.parse("2001:db8::zz", 1));
}

test "listenTcp: binds, accepts, and round-trips bytes" {
    // Port 0 lets the kernel choose, so the test cannot collide with anything.
    const addr = try Address.parse("127.0.0.1", 0);
    const server = try listenTcp(addr, 16);
    defer close(server);

    // An empty backlog reports "nothing to do", not an error.
    try testing.expect(accept(server) == null);

    const port = try boundPort(server);
    try testing.expect(port != 0);

    const client = try connectLoopback(port);
    defer close(client);

    // The connection may need a moment to land in the backlog.
    const conn = for (0..100) |_| {
        if (accept(server)) |fd| break fd;
        sleepMs(5);
    } else return error.AcceptTimedOut;
    defer close(conn);

    switch (write(client, "PING :hello\r\n")) {
        .wrote => |n| try testing.expectEqual(@as(usize, 13), n),
        .status => return error.WriteFailed,
    }

    var buf: [64]u8 = undefined;
    const got = for (0..100) |_| {
        switch (read(conn, &buf)) {
            .read => |n| break buf[0..n],
            .status => |s| switch (s) {
                .would_block => sleepMs(5),
                else => return error.ReadFailed,
            },
        }
    } else return error.ReadTimedOut;

    try testing.expectEqualStrings("PING :hello\r\n", got);
}

test "read: a non-blocking socket with no data reports would_block, not an error" {
    const addr = try Address.parse("127.0.0.1", 0);
    const server = try listenTcp(addr, 16);
    defer close(server);

    const client = try connectLoopback(try boundPort(server));
    defer close(client);

    const conn = for (0..100) |_| {
        if (accept(server)) |fd| break fd;
        sleepMs(5);
    } else return error.AcceptTimedOut;
    defer close(conn);

    // This is the single most important property of the whole file: an idle
    // socket must never block the loop.
    var buf: [64]u8 = undefined;
    try testing.expectEqual(Io.would_block, read(conn, &buf).status);
}

test "formatAddress: ipv4" {
    var buf: [46]u8 = undefined;
    const a: Address = .{ .ip4 = .{ .addr = .{ 192, 168, 1, 10 }, .port = 0 } };
    try testing.expectEqualStrings("192.168.1.10", formatAddress(a, &buf));
}

test "formatAddress: ipv6 collapses the longest zero run" {
    var buf: [46]u8 = undefined;

    const loop = try Address.parse("::1", 0);
    try testing.expectEqualStrings("::1", formatAddress(loop, &buf));

    const any = try Address.parse("::", 0);
    try testing.expectEqualStrings("::", formatAddress(any, &buf));

    const doc = try Address.parse("2001:db8::1", 0);
    try testing.expectEqualStrings("2001:db8::1", formatAddress(doc, &buf));

    const full = try Address.parse("2001:db8:1:2:3:4:5:6", 0);
    try testing.expectEqualStrings("2001:db8:1:2:3:4:5:6", formatAddress(full, &buf));

    // A lone zero group stays "0"; "::" is only for runs of two or more.
    const single = try Address.parse("2001:db8:0:1:1:1:1:1", 0);
    try testing.expectEqualStrings("2001:db8:0:1:1:1:1:1", formatAddress(single, &buf));

    const tail = try Address.parse("fe80::", 0);
    try testing.expectEqualStrings("fe80::", formatAddress(tail, &buf));
}

test "monotonicMs advances and never goes backwards" {
    const first = monotonicMs();
    sleepMs(5);
    const second = monotonicMs();
    try testing.expect(second >= first);
    try testing.expect(second - first < 5000);
}

test "realtimeMs looks like a plausible epoch timestamp" {
    // Well after 2020 and well before 2100 — catches a unit mix-up (seconds vs
    // milliseconds), which would silently break server-time and TS6 ordering.
    const now = realtimeMs();
    try testing.expect(now > 1_577_836_800_000);
    try testing.expect(now < 4_102_444_800_000);
}

test "peerAddress: reports the connected peer as ipv4" {
    const addr = try Address.parse("127.0.0.1", 0);
    const server = try listenTcp(addr, 16);
    defer close(server);

    const client = try connectLoopback(try boundPort(server));
    defer close(client);

    const conn = for (0..100) |_| {
        if (accept(server)) |fd| break fd;
        sleepMs(5);
    } else return error.AcceptTimedOut;
    defer close(conn);

    const peer = peerAddress(conn) orelse return error.NoPeerAddress;
    try testing.expect(peer == .ip4);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, peer.ip4.addr);
}

test "read: reports eof when the peer closes" {
    const addr = try Address.parse("127.0.0.1", 0);
    const server = try listenTcp(addr, 16);
    defer close(server);

    const client = try connectLoopback(try boundPort(server));

    const conn = for (0..100) |_| {
        if (accept(server)) |fd| break fd;
        sleepMs(5);
    } else return error.AcceptTimedOut;
    defer close(conn);

    close(client);

    var buf: [64]u8 = undefined;
    const status = for (0..100) |_| {
        switch (read(conn, &buf)) {
            .read => return error.UnexpectedData,
            .status => |s| switch (s) {
                .would_block => sleepMs(5),
                else => break s,
            },
        }
    } else return error.EofTimedOut;

    try testing.expectEqual(Io.eof, status);
}

fn sleepMs(ms: u64) void {
    var ts: c.timespec = .{ .sec = 0, .nsec = @intCast(ms * std.time.ns_per_ms) };
    if (use_linux_syscalls) {
        _ = linux.nanosleep(&ts, null);
    } else {
        _ = c.nanosleep(&ts, null);
    }
}

/// The port the kernel actually assigned when we bound to port 0.
fn boundPort(fd: Handle) !u16 {
    var sa: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
    var len: u32 = @sizeOf(posix.sockaddr.in);
    if (use_linux_syscalls) {
        const rc = linux.getsockname(fd, @ptrCast(&sa), &len);
        if (linux.errno(rc) != .SUCCESS) return error.GetSockNameFailed;
    } else {
        if (c.getsockname(fd, @ptrCast(&sa), &len) != 0) return error.GetSockNameFailed;
    }
    return std.mem.bigToNative(u16, sa.port);
}

fn connectLoopback(port: u16) !Handle {
    const fd = try createSocket(posix.AF.INET);
    errdefer close(fd);

    var sa: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
    sa.family = posix.AF.INET;
    sa.port = std.mem.nativeToBig(u16, port);
    sa.addr = @bitCast([4]u8{ 127, 0, 0, 1 });
    if (@hasField(posix.sockaddr.in, "len")) sa.len = @sizeOf(posix.sockaddr.in);

    // Non-blocking connect returns EINPROGRESS; the test's accept loop waits.
    if (use_linux_syscalls) {
        _ = linux.connect(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
    } else {
        _ = c.connect(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
    }
    return fd;
}
