//! Cryptographic randomness, straight from the OS.
//!
//! `std.crypto.random` is gone in Zig 0.16, and the values this feeds — the
//! NTLM server challenge above all — are exactly the ones that must never be
//! guessable: a predictable challenge turns a captured response into a reusable
//! one. So this asks the kernel and refuses to continue if the kernel will not
//! answer, rather than falling back to anything weaker.

const std = @import("std");
const builtin = @import("builtin");

pub fn fill(buf: []u8) void {
    if (builtin.os.tag == .linux) {
        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => filled += rc,
                .INTR => continue,
                else => @panic("getrandom failed; refusing to serve with predictable challenges"),
            }
        }
    } else {
        std.c.arc4random_buf(buf.ptr, buf.len);
    }
}

const testing = std.testing;

test "fill produces different bytes each time" {
    var a: [32]u8 = @splat(0);
    var b: [32]u8 = @splat(0);
    fill(&a);
    fill(&b);
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(!std.mem.allEqual(u8, &a, 0));
}

test "fill handles a partial buffer without touching its neighbours" {
    var buf: [16]u8 = @splat(0xEE);
    fill(buf[4..12]);
    try testing.expectEqualSlices(u8, &.{ 0xEE, 0xEE, 0xEE, 0xEE }, buf[0..4]);
    try testing.expectEqualSlices(u8, &.{ 0xEE, 0xEE, 0xEE, 0xEE }, buf[12..16]);
}
