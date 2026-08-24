//! Readiness multiplexer. Zero heap, no allocator.
//!
//! Backend chosen at comptime: epoll (Linux, raw syscalls, no libc), kqueue
//! (macOS/BSD, via libc), poll (portable fallback, O(registered) per wakeup
//! rather than O(ready); force it with `-Dpoll`).
//!
//! epoll and kqueue keep registration in the kernel and hand our token back on
//! every event, so only the poll backend carries state of its own.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;

pub const Backend = enum { epoll, kqueue, poll };

pub const backend: Backend = if (build_options.force_poll) .poll else switch (builtin.os.tag) {
    .linux => .epoll,
    .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => .kqueue,
    else => .poll,
};

/// Handed back on every event; callers use it to index their own connection
/// table. The poll backend indexes its arrays by it directly, so it must be
/// less than `max_fds` on every backend.
pub const Token = u32;

/// What to be woken for. Register `write` only while output is actually
/// pending: a level-triggered backend reports an idle writable socket
/// continuously, spinning the loop at 100% CPU.
pub const Interest = packed struct {
    read: bool = false,
    write: bool = false,
};

/// `hangup` can arrive alongside `read`, leaving buffered data to drain first.
pub const Readiness = packed struct {
    read: bool = false,
    write: bool = false,
    hangup: bool = false,
};

pub const Event = struct {
    token: Token,
    readiness: Readiness,
};

pub const InitError = error{ SystemResources, ProcessFdQuotaExceeded, SystemFdQuotaExceeded, Unexpected };
pub const RegisterError = error{ TooManyFds, SystemResources, Unexpected };
pub const WaitError = error{ SystemResources, Unexpected };

/// Bounded so a busy moment cannot starve timers.
pub const max_events = 256;

/// `max_fds` bounds the poll backend's tables and the token space.
pub fn Poller(comptime max_fds: usize) type {
    return struct {
        impl: Impl,

        const Self = @This();

        const Impl = switch (backend) {
            .epoll => EpollImpl,
            .kqueue => KqueueImpl,
            .poll => PollImpl(max_fds),
        };

        /// In place, not by value: the poll backend embeds a fixed table that
        /// must not be copied.
        pub fn init(p: *Self) InitError!void {
            return p.impl.init();
        }

        pub fn deinit(p: *Self) void {
            p.impl.deinit();
        }

        pub fn add(p: *Self, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
            assert(token < max_fds);
            return p.impl.add(fd, token, interest);
        }

        pub fn modify(p: *Self, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
            assert(token < max_fds);
            return p.impl.modify(fd, token, interest);
        }

        pub fn remove(p: *Self, fd: posix.fd_t, token: Token) void {
            assert(token < max_fds);
            p.impl.remove(fd, token);
        }

        /// Fills `out` and returns the populated prefix. A negative timeout
        /// blocks indefinitely; zero events means the timeout fired.
        pub fn wait(p: *Self, out: []Event, timeout_ms: i32) WaitError![]Event {
            assert(out.len > 0);
            return p.impl.wait(out, timeout_ms);
        }
    };
}

const EpollImpl = struct {
    fd: i32,

    fn init(s: *EpollImpl) InitError!void {
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        s.fd = switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        };
    }

    fn deinit(s: *EpollImpl) void {
        _ = linux.close(s.fd);
    }

    fn ctl(s: *EpollImpl, op: u32, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
        var events: u32 = linux.EPOLL.RDHUP;
        if (interest.read) events |= linux.EPOLL.IN;
        if (interest.write) events |= linux.EPOLL.OUT;
        var ev: linux.epoll_event = .{ .events = events, .data = .{ .u64 = token } };
        return switch (linux.errno(linux.epoll_ctl(s.fd, op, fd, &ev))) {
            .SUCCESS => {},
            .NOMEM, .NOSPC => error.SystemResources,
            else => error.Unexpected,
        };
    }

    fn add(s: *EpollImpl, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
        return s.ctl(linux.EPOLL.CTL_ADD, fd, token, interest);
    }

    fn modify(s: *EpollImpl, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
        return s.ctl(linux.EPOLL.CTL_MOD, fd, token, interest);
    }

    fn remove(s: *EpollImpl, fd: posix.fd_t, token: Token) void {
        _ = token;
        // Pre-2.6.9 kernels rejected a null event; passing one is harmless.
        var ev: linux.epoll_event = .{ .events = 0, .data = .{ .u64 = 0 } };
        _ = linux.epoll_ctl(s.fd, linux.EPOLL.CTL_DEL, fd, &ev);
    }

    fn wait(s: *EpollImpl, out: []Event, timeout_ms: i32) WaitError![]Event {
        var buf: [max_events]linux.epoll_event = undefined;
        const want = @min(out.len, buf.len);
        while (true) {
            const rc = linux.epoll_wait(s.fd, &buf, @intCast(want), timeout_ms);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    for (buf[0..rc], out[0..rc]) |ev, *slot| {
                        slot.* = .{
                            .token = @truncate(ev.data.u64),
                            .readiness = .{
                                .read = ev.events & linux.EPOLL.IN != 0,
                                .write = ev.events & linux.EPOLL.OUT != 0,
                                .hangup = ev.events & (linux.EPOLL.HUP | linux.EPOLL.RDHUP | linux.EPOLL.ERR) != 0,
                            },
                        };
                    }
                    return out[0..rc];
                },
                .INTR => continue,
                else => return error.Unexpected,
            }
        }
    }
};

const KqueueImpl = struct {
    fd: i32,

    const c = std.c;

    /// kevent(2) declares its list parameters as non-optional pointers, so
    /// "no changes" and "no events wanted" are expressed with a zero-length
    /// array rather than null. Nothing is ever read from or written to it.
    var none: [0]c.Kevent = .{};

    fn init(s: *KqueueImpl) InitError!void {
        const fd = c.kqueue();
        if (fd < 0) return switch (c.errno(fd)) {
            .MFILE => error.ProcessFdQuotaExceeded,
            .NFILE => error.SystemFdQuotaExceeded,
            .NOMEM => error.SystemResources,
            else => error.Unexpected,
        };
        s.fd = fd;
    }

    fn deinit(s: *KqueueImpl) void {
        _ = c.close(s.fd);
    }

    fn kev(fd: posix.fd_t, filter: i16, flags: u16, token: Token) c.Kevent {
        return .{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = token,
        };
    }

    /// An unwanted filter is disabled rather than deleted: keeps add and modify
    /// identical, and avoids ENOENT on a filter that was never added.
    fn apply(s: *KqueueImpl, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
        const enable: u16 = c.EV.ADD | c.EV.ENABLE;
        const disable: u16 = c.EV.ADD | c.EV.DISABLE;
        var ch: [2]c.Kevent = .{
            kev(fd, c.EVFILT.READ, if (interest.read) enable else disable, token),
            kev(fd, c.EVFILT.WRITE, if (interest.write) enable else disable, token),
        };
        const rc = c.kevent(s.fd, &ch, ch.len, &none, 0, null);
        if (rc < 0) return switch (c.errno(rc)) {
            .NOMEM => error.SystemResources,
            else => error.Unexpected,
        };
    }

    fn add(s: *KqueueImpl, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
        return s.apply(fd, token, interest);
    }

    fn modify(s: *KqueueImpl, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
        return s.apply(fd, token, interest);
    }

    fn remove(s: *KqueueImpl, fd: posix.fd_t, token: Token) void {
        _ = token;
        // Callers may remove without closing; a stale filter would resurface as
        // a bogus event.
        var ch: [2]c.Kevent = .{
            kev(fd, c.EVFILT.READ, c.EV.DELETE, 0),
            kev(fd, c.EVFILT.WRITE, c.EV.DELETE, 0),
        };
        _ = c.kevent(s.fd, &ch, ch.len, &none, 0, null);
    }

    fn wait(s: *KqueueImpl, out: []Event, timeout_ms: i32) WaitError![]Event {
        var buf: [max_events]c.Kevent = undefined;
        const want = @min(out.len, buf.len);

        var ts: c.timespec = undefined;
        const ts_ptr: ?*const c.timespec = if (timeout_ms < 0) null else blk: {
            ts = .{
                .sec = @divTrunc(timeout_ms, 1000),
                .nsec = @as(@FieldType(c.timespec, "nsec"), @rem(timeout_ms, 1000)) * std.time.ns_per_ms,
            };
            break :blk &ts;
        };

        while (true) {
            const rc = c.kevent(s.fd, &none, 0, &buf, @intCast(want), ts_ptr);
            if (rc < 0) {
                if (c.errno(rc) == .INTR) continue;
                return error.Unexpected;
            }
            const n: usize = @intCast(rc);

            // kqueue emits read and write separately for one fd; the contract is
            // one merged event, as epoll gives.
            var count: usize = 0;
            for (buf[0..n]) |ev| {
                const token: Token = @truncate(ev.udata);
                const slot = for (out[0..count]) |*existing| {
                    if (existing.token == token) break existing;
                } else blk: {
                    if (count == out.len) break;
                    out[count] = .{ .token = token, .readiness = .{} };
                    count += 1;
                    break :blk &out[count - 1];
                };

                if (ev.filter == c.EVFILT.READ) slot.readiness.read = true;
                if (ev.filter == c.EVFILT.WRITE) slot.readiness.write = true;
                if (ev.flags & (c.EV.EOF | c.EV.ERROR) != 0) slot.readiness.hangup = true;
            }
            return out[0..count];
        }
    }
};

fn PollImpl(comptime max_fds: usize) type {
    return struct {
        /// Indexed by token, not compacted. poll(2) skips an entry whose fd is
        /// negative, so a free slot costs one ignored array entry and add,
        /// modify and remove all stay O(1) with no fd lookup table.
        fds: [max_fds]posix.pollfd,
        /// One past the highest token ever registered, so `wait` hands the
        /// kernel a prefix rather than the whole table.
        high_water: usize,

        const Self = @This();

        fn init(s: *Self) InitError!void {
            s.high_water = 0;
            for (&s.fds) |*p| p.* = .{ .fd = -1, .events = 0, .revents = 0 };
        }

        fn deinit(s: *Self) void {
            _ = s;
        }

        fn mask(interest: Interest) i16 {
            var m: i16 = 0;
            if (interest.read) m |= posix.POLL.IN;
            if (interest.write) m |= posix.POLL.OUT;
            return m;
        }

        fn add(s: *Self, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
            if (token >= max_fds) return error.TooManyFds;
            s.fds[token] = .{ .fd = fd, .events = mask(interest), .revents = 0 };
            if (token + 1 > s.high_water) s.high_water = token + 1;
        }

        fn modify(s: *Self, fd: posix.fd_t, token: Token, interest: Interest) RegisterError!void {
            return s.add(fd, token, interest);
        }

        fn remove(s: *Self, fd: posix.fd_t, token: Token) void {
            _ = fd;
            s.fds[token] = .{ .fd = -1, .events = 0, .revents = 0 };
            // Pull back over trailing free slots so a connection burst does not
            // permanently widen every later poll.
            while (s.high_water > 0 and s.fds[s.high_water - 1].fd < 0) s.high_water -= 1;
        }

        fn wait(s: *Self, out: []Event, timeout_ms: i32) WaitError![]Event {
            // poll(2) with zero fds and a timeout is just a sleep. Zero fds with
            // no timeout would block forever with nothing able to wake it.
            assert(s.high_water > 0 or timeout_ms >= 0);

            const n = posix.poll(s.fds[0..s.high_water], timeout_ms) catch |err| switch (err) {
                error.SystemResources => return error.SystemResources,
                else => return error.Unexpected,
            };
            if (n == 0) return out[0..0];

            var count: usize = 0;
            for (s.fds[0..s.high_water], 0..) |*pfd, token| {
                if (count == out.len) break;
                const re = pfd.revents;
                if (re == 0) continue;
                pfd.revents = 0;
                out[count] = .{
                    .token = @intCast(token),
                    .readiness = .{
                        .read = re & posix.POLL.IN != 0,
                        .write = re & posix.POLL.OUT != 0,
                        .hangup = re & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0,
                    },
                };
                count += 1;
            }
            return out[0..count];
        }
    };
}

const testing = std.testing;

const Pair = struct {
    a: posix.fd_t,
    b: posix.fd_t,

    fn create() !Pair {
        var fds: [2]posix.fd_t = undefined;
        switch (builtin.os.tag) {
            .linux => {
                const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
                if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
            },
            else => {
                const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &fds);
                if (rc != 0) return error.SocketPairFailed;
            },
        }
        return .{ .a = fds[0], .b = fds[1] };
    }

    fn close(p: Pair) void {
        switch (builtin.os.tag) {
            .linux => {
                _ = linux.close(p.a);
                _ = linux.close(p.b);
            },
            else => {
                _ = std.c.close(p.a);
                _ = std.c.close(p.b);
            },
        }
    }

    fn send(p: Pair, bytes: []const u8) !void {
        const rc = switch (builtin.os.tag) {
            .linux => @as(isize, @bitCast(linux.write(p.b, bytes.ptr, bytes.len))),
            else => std.c.write(p.b, bytes.ptr, bytes.len),
        };
        if (rc != @as(isize, @intCast(bytes.len))) return error.WriteFailed;
    }
};

const TestPoller = Poller(64);

test "wait: times out with nothing ready" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const pair = try Pair.create();
    defer pair.close();

    try p.add(pair.a, 0, .{ .read = true });

    var events: [8]Event = undefined;
    const ready = try p.wait(&events, 10);
    try testing.expectEqual(@as(usize, 0), ready.len);
}

test "wait: reports readable with the caller's token" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const pair = try Pair.create();
    defer pair.close();

    try p.add(pair.a, 7, .{ .read = true });
    try pair.send("PING\r\n");

    var events: [8]Event = undefined;
    const ready = try p.wait(&events, 1000);
    try testing.expectEqual(@as(usize, 1), ready.len);
    try testing.expectEqual(@as(Token, 7), ready[0].token);
    try testing.expect(ready[0].readiness.read);
}

test "wait: a socket with no pending output is not reported writable" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const pair = try Pair.create();
    defer pair.close();

    // An idle socket is almost always writable. Registering read-only must not
    // report it, or a level-triggered loop would spin at 100% CPU.
    try p.add(pair.a, 0, .{ .read = true });

    var events: [8]Event = undefined;
    const ready = try p.wait(&events, 10);
    try testing.expectEqual(@as(usize, 0), ready.len);
}

test "modify: enabling write reports the socket, disabling it stops" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const pair = try Pair.create();
    defer pair.close();

    try p.add(pair.a, 3, .{ .read = true });

    try p.modify(pair.a, 3, .{ .read = true, .write = true });
    var events: [8]Event = undefined;
    var ready = try p.wait(&events, 1000);
    try testing.expectEqual(@as(usize, 1), ready.len);
    try testing.expectEqual(@as(Token, 3), ready[0].token);
    try testing.expect(ready[0].readiness.write);

    try p.modify(pair.a, 3, .{ .read = true });
    ready = try p.wait(&events, 10);
    try testing.expectEqual(@as(usize, 0), ready.len);
}

test "wait: read and write for one fd merge into a single event" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const pair = try Pair.create();
    defer pair.close();

    try p.add(pair.a, 5, .{ .read = true, .write = true });
    try pair.send("x");

    var events: [8]Event = undefined;
    const ready = try p.wait(&events, 1000);
    // kqueue would naturally emit two events here; the contract is one.
    try testing.expectEqual(@as(usize, 1), ready.len);
    try testing.expectEqual(@as(Token, 5), ready[0].token);
    try testing.expect(ready[0].readiness.read);
    try testing.expect(ready[0].readiness.write);
}

test "wait: reports hangup when the peer closes" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const pair = try Pair.create();
    defer switch (builtin.os.tag) {
        .linux => _ = linux.close(pair.a),
        else => _ = std.c.close(pair.a),
    };

    try p.add(pair.a, 1, .{ .read = true });
    switch (builtin.os.tag) {
        .linux => _ = linux.close(pair.b),
        else => _ = std.c.close(pair.b),
    }

    var events: [8]Event = undefined;
    const ready = try p.wait(&events, 1000);
    try testing.expectEqual(@as(usize, 1), ready.len);
    try testing.expect(ready[0].readiness.hangup);
}

test "remove: a removed fd stops being reported" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const pair = try Pair.create();
    defer pair.close();

    try p.add(pair.a, 2, .{ .read = true });
    try pair.send("data");

    p.remove(pair.a, 2);

    var events: [8]Event = undefined;
    const ready = try p.wait(&events, 10);
    try testing.expectEqual(@as(usize, 0), ready.len);
}

test "multiple fds report independently" {
    var p: TestPoller = undefined;
    try p.init();
    defer p.deinit();

    const first = try Pair.create();
    defer first.close();
    const second = try Pair.create();
    defer second.close();

    try p.add(first.a, 10, .{ .read = true });
    try p.add(second.a, 20, .{ .read = true });

    try second.send("hi");

    var events: [8]Event = undefined;
    const ready = try p.wait(&events, 1000);
    try testing.expectEqual(@as(usize, 1), ready.len);
    try testing.expectEqual(@as(Token, 20), ready[0].token);

    try first.send("hi");
    const both = try p.wait(&events, 1000);
    try testing.expectEqual(@as(usize, 2), both.len);
}
