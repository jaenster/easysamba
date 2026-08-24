//! Windows FILETIME: 100-nanosecond ticks since 1601-01-01 UTC. Every timestamp
//! on the wire is one of these, and a zero means "leave unchanged" in SET_INFO
//! while 0xFFFF_FFFF_FFFF_FFFF means "do not touch, ever" — the two are not
//! interchangeable, so the conversions keep them distinct.

const std = @import("std");
const builtin = @import("builtin");

/// Seconds between 1601-01-01 and 1970-01-01, including the 89 leap days.
pub const epoch_delta_s: i64 = 11_644_473_600;
pub const ticks_per_s: i64 = 10_000_000;
pub const ticks_per_ns: i64 = 100;

pub const unchanged: u64 = 0;
pub const frozen: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub fn fromUnixNs(ns: i128) u64 {
    const ticks = @divFloor(ns, ticks_per_ns) + @as(i128, epoch_delta_s) * ticks_per_s;
    if (ticks <= 0) return 0;
    if (ticks > std.math.maxInt(u64)) return frozen;
    return @intCast(ticks);
}

pub fn fromUnixSec(sec: i64) u64 {
    return fromUnixNs(@as(i128, sec) * std.time.ns_per_s);
}

pub fn toUnixNs(ft: u64) i128 {
    return (@as(i128, ft) - @as(i128, epoch_delta_s) * ticks_per_s) * ticks_per_ns;
}

/// Right now, as a FILETIME. Used for the negotiate response's SystemTime and
/// for stamping writes when the adapter has no clock of its own.
///
/// Reads the clock directly rather than through `std.time`, which in 0.16 lives
/// behind `std.Io` and the event loop this server does not use.
pub fn now() u64 {
    var ts: std.c.timespec = undefined;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.REALTIME, @ptrCast(&ts));
    } else {
        _ = std.c.clock_gettime(.REALTIME, &ts);
    }
    return fromUnixNs(@as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec)));
}

const testing = std.testing;

test "the unix epoch is exactly the 1601 delta" {
    try testing.expectEqual(@as(u64, @intCast(epoch_delta_s * ticks_per_s)), fromUnixSec(0));
}

test "round-trips through unix nanoseconds" {
    const ns: i128 = 1_700_000_000 * std.time.ns_per_s + 123_456_700;
    try testing.expectEqual(ns, toUnixNs(fromUnixNs(ns)));
}

test "pre-1601 timestamps clamp to zero rather than wrapping" {
    try testing.expectEqual(@as(u64, 0), fromUnixSec(-100_000_000_000));
}
