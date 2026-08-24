//! Bounds-checked little-endian cursors. SMB2 is a little-endian, offset-heavy
//! protocol whose every field is attacker-controlled, so nothing here indexes
//! without a length check and nothing returns a slice the caller did not prove
//! exists.
//!
//! Offsets in SMB2 are almost always measured from the START OF THE MESSAGE,
//! not from the current field, which is why both cursors keep the whole message
//! and expose absolute `sliceAt`/`patch` accessors alongside the sequential
//! ones.

const std = @import("std");

pub const Error = error{
    /// Ran past the end of the message: a truncated or lying request.
    Truncated,
    /// The response would not fit the output buffer.
    NoSpace,
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn remaining(r: Reader) usize {
        return r.bytes.len - r.pos;
    }

    pub fn take(r: *Reader, n: usize) Error![]const u8 {
        if (r.remaining() < n) return error.Truncated;
        defer r.pos += n;
        return r.bytes[r.pos..][0..n];
    }

    pub fn takeArray(r: *Reader, comptime n: usize) Error!*const [n]u8 {
        if (r.remaining() < n) return error.Truncated;
        defer r.pos += n;
        return r.bytes[r.pos..][0..n];
    }

    pub fn skip(r: *Reader, n: usize) Error!void {
        if (r.remaining() < n) return error.Truncated;
        r.pos += n;
    }

    pub fn int(r: *Reader, comptime T: type) Error!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        return std.mem.readInt(T, try r.takeArray(n), .little);
    }

    pub fn u8_(r: *Reader) Error!u8 {
        return r.int(u8);
    }
    pub fn u16_(r: *Reader) Error!u16 {
        return r.int(u16);
    }
    pub fn u32_(r: *Reader) Error!u32 {
        return r.int(u32);
    }
    pub fn u64_(r: *Reader) Error!u64 {
        return r.int(u64);
    }

    /// An (offset, length) pair as SMB2 states them: absolute from the start of
    /// whatever `bytes` is. A zero length is legal and yields an empty slice
    /// even when the offset is nonsense, because clients do exactly that.
    pub fn sliceAt(r: Reader, offset: usize, len: usize) Error![]const u8 {
        if (len == 0) return r.bytes[0..0];
        if (offset > r.bytes.len or r.bytes.len - offset < len) return error.Truncated;
        return r.bytes[offset..][0..len];
    }
};

pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn written(w: Writer) []u8 {
        return w.buf[0..w.pos];
    }

    pub fn space(w: Writer) usize {
        return w.buf.len - w.pos;
    }

    /// Reserves `n` bytes and hands back the slice, for fields whose value is
    /// only known once later bytes have been laid down (lengths, offsets).
    pub fn reserve(w: *Writer, n: usize) Error![]u8 {
        if (w.space() < n) return error.NoSpace;
        defer w.pos += n;
        return w.buf[w.pos..][0..n];
    }

    pub fn reserveArray(w: *Writer, comptime n: usize) Error!*[n]u8 {
        if (w.space() < n) return error.NoSpace;
        defer w.pos += n;
        return w.buf[w.pos..][0..n];
    }

    pub fn int(w: *Writer, comptime T: type, value: T) Error!void {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        std.mem.writeInt(T, try w.reserveArray(n), value, .little);
    }

    pub fn u8_(w: *Writer, v: u8) Error!void {
        return w.int(u8, v);
    }
    pub fn u16_(w: *Writer, v: u16) Error!void {
        return w.int(u16, v);
    }
    pub fn u32_(w: *Writer, v: u32) Error!void {
        return w.int(u32, v);
    }
    pub fn u64_(w: *Writer, v: u64) Error!void {
        return w.int(u64, v);
    }

    pub fn blob(w: *Writer, bytes: []const u8) Error!void {
        @memcpy(try w.reserve(bytes.len), bytes);
    }

    pub fn zeroes(w: *Writer, n: usize) Error!void {
        @memset(try w.reserve(n), 0);
    }

    /// Pads to an 8-byte boundary relative to the start of the buffer, which is
    /// how SMB2 aligns compounded messages and info-class records.
    pub fn alignTo(w: *Writer, comptime n: usize) Error!void {
        const pad = (n - (w.pos % n)) % n;
        try w.zeroes(pad);
    }

    /// Overwrites bytes already emitted (a reserved length field, a signature).
    pub fn patch(w: *Writer, offset: usize, bytes: []const u8) Error!void {
        if (offset > w.pos or w.pos - offset < bytes.len) return error.NoSpace;
        @memcpy(w.buf[offset..][0..bytes.len], bytes);
    }

    pub fn patchInt(w: *Writer, comptime T: type, offset: usize, value: T) Error!void {
        var tmp: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
        std.mem.writeInt(T, &tmp, value, .little);
        return w.patch(offset, &tmp);
    }
};

const testing = std.testing;

test "Reader: sequential ints are little-endian and bounded" {
    var r = Reader.init(&.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });
    try testing.expectEqual(@as(u8, 0x01), try r.u8_());
    try testing.expectEqual(@as(u16, 0x0302), try r.u16_());
    try testing.expectEqual(@as(usize, 3), r.remaining());
    try testing.expectError(error.Truncated, r.u32_());
}

test "Reader: sliceAt honours absolute offsets and rejects overruns" {
    const r = Reader.init(&.{ 0, 1, 2, 3, 4, 5, 6, 7 });
    try testing.expectEqualSlices(u8, &.{ 4, 5 }, try r.sliceAt(4, 2));
    try testing.expectError(error.Truncated, r.sliceAt(6, 4));
    // A zero length is legal whatever the offset claims — clients send
    // (offset=0, length=0) for "no buffer" all the time.
    try testing.expectEqual(@as(usize, 0), (try r.sliceAt(9999, 0)).len);
}

test "Writer: patch rewrites a reserved field in place" {
    var buf: [16]u8 = undefined;
    var w = Writer.init(&buf);
    const len_at = w.pos;
    try w.u32_(0); // placeholder
    try w.blob("abc");
    try w.patchInt(u32, len_at, 3);
    try testing.expectEqualSlices(u8, &.{ 3, 0, 0, 0, 'a', 'b', 'c' }, w.written());
}

test "Writer: alignTo pads relative to the buffer start" {
    var buf: [16]u8 = undefined;
    var w = Writer.init(&buf);
    try w.blob("abc");
    try w.alignTo(8);
    try testing.expectEqual(@as(usize, 8), w.pos);
    try w.alignTo(8); // already aligned: no padding
    try testing.expectEqual(@as(usize, 8), w.pos);
}

test "Writer: runs out of space instead of overflowing" {
    var buf: [4]u8 = undefined;
    var w = Writer.init(&buf);
    try w.u32_(0);
    try testing.expectError(error.NoSpace, w.u8_(1));
}
