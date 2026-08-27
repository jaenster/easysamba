//! The SMB2 packet header, the transport framing around it, and the constants
//! the rest of the protocol code shares.
//!
//! Transport is "direct TCP" on port 445: every message is preceded by four
//! bytes — one zero, then a 24-bit big-endian length. It is the NetBIOS session
//! service header with the type byte pinned to zero, and it is the only
//! big-endian thing in SMB2.

const std = @import("std");
const wire = @import("wire.zig");

pub const protocol_id = [4]u8{ 0xFE, 'S', 'M', 'B' };
pub const smb1_protocol_id = [4]u8{ 0xFF, 'S', 'M', 'B' };
pub const header_size: usize = 64;
pub const transport_header_size: usize = 4;
/// The 24-bit length field caps a message; we cap far below it anyway.
pub const max_message = 0xFF_FFFF;

pub const Command = enum(u16) {
    negotiate = 0x00,
    session_setup = 0x01,
    logoff = 0x02,
    tree_connect = 0x03,
    tree_disconnect = 0x04,
    create = 0x05,
    close = 0x06,
    flush = 0x07,
    read = 0x08,
    write = 0x09,
    lock = 0x0A,
    ioctl = 0x0B,
    cancel = 0x0C,
    echo = 0x0D,
    query_directory = 0x0E,
    change_notify = 0x0F,
    query_info = 0x10,
    set_info = 0x11,
    oplock_break = 0x12,
    _,
};

/// The name of a command, for logs. A client may send a command number that
/// does not exist, and asking a non-exhaustive enum for the name of a value it
/// does not have is a panic — one wrong byte would be enough to stop the
/// server for everyone.
pub fn commandName(command: Command) []const u8 {
    return std.enums.tagName(Command, command) orelse "unknown";
}

pub const flags = struct {
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    pub const SIGNED: u32 = 0x0000_0008;
    pub const PRIORITY_MASK: u32 = 0x0000_0070;
    pub const DFS_OPERATIONS: u32 = 0x1000_0000;
    pub const REPLAY_OPERATION: u32 = 0x2000_0000;
};

pub const Dialect = enum(u16) {
    smb_2_0_2 = 0x0202,
    smb_2_1 = 0x0210,
    smb_3_0 = 0x0300,
    smb_3_0_2 = 0x0302,
    smb_3_1_1 = 0x0311,
    /// The reply to a multi-protocol (SMB1) negotiate: "ask me again in SMB2".
    wildcard = 0x02FF,
    _,
};

pub const security_mode = struct {
    pub const SIGNING_ENABLED: u16 = 0x0001;
    pub const SIGNING_REQUIRED: u16 = 0x0002;
};

pub const capabilities = struct {
    pub const DFS: u32 = 0x0000_0001;
    pub const LEASING: u32 = 0x0000_0002;
    pub const LARGE_MTU: u32 = 0x0000_0004;
    pub const MULTI_CHANNEL: u32 = 0x0000_0008;
    pub const PERSISTENT_HANDLES: u32 = 0x0000_0010;
    pub const DIRECTORY_LEASING: u32 = 0x0000_0020;
    pub const ENCRYPTION: u32 = 0x0000_0040;
};

pub const Header = struct {
    credit_charge: u16 = 0,
    status: u32 = 0,
    command: Command = .negotiate,
    credits: u16 = 0,
    flags: u32 = 0,
    next_command: u32 = 0,
    message_id: u64 = 0,
    tree_id: u32 = 0,
    /// Carried in the same eight bytes as the tree id, and read and written
    /// instead of it when the message is asynchronous: a server that cannot
    /// answer at once names its half-answer, and the client cancels by that
    /// name.
    async_id: u64 = 0,
    session_id: u64 = 0,
    signature: [16]u8 = @splat(0),

    pub fn isRelated(h: Header) bool {
        return h.flags & flags.RELATED_OPERATIONS != 0;
    }

    pub fn isSigned(h: Header) bool {
        return h.flags & flags.SIGNED != 0;
    }
};

pub const Error = error{ NotSmb2, Malformed } || wire.Error;

pub fn parse(bytes: []const u8) Error!Header {
    if (bytes.len < header_size) return error.Malformed;
    if (!std.mem.eql(u8, bytes[0..4], &protocol_id)) return error.NotSmb2;

    var r = wire.Reader.init(bytes);
    try r.skip(4);
    const structure_size = try r.u16_();
    if (structure_size != header_size) return error.Malformed;

    var h: Header = .{};
    h.credit_charge = try r.u16_();
    h.status = try r.u32_();
    h.command = @enumFromInt(try r.u16_());
    h.credits = try r.u16_();
    h.flags = try r.u32_();
    h.next_command = try r.u32_();
    h.message_id = try r.u64_();
    // Bytes 32..40 are Reserved+TreeId in a sync header and AsyncId in an
    // async one. A request is asynchronous only when it cancels one.
    if (h.flags & flags.ASYNC_COMMAND != 0) {
        h.async_id = try r.u64_();
    } else {
        try r.skip(4);
        h.tree_id = try r.u32_();
    }
    h.session_id = try r.u64_();
    h.signature = (try r.takeArray(16)).*;
    return h;
}

pub fn write(w: *wire.Writer, h: Header) wire.Error!void {
    try w.blob(&protocol_id);
    try w.u16_(@intCast(header_size));
    try w.u16_(h.credit_charge);
    try w.u32_(h.status);
    try w.u16_(@intFromEnum(h.command));
    try w.u16_(h.credits);
    try w.u32_(h.flags);
    try w.u32_(h.next_command);
    try w.u64_(h.message_id);
    if (h.flags & flags.ASYNC_COMMAND != 0) {
        try w.u64_(h.async_id);
    } else {
        try w.u32_(0); // Reserved
        try w.u32_(h.tree_id);
    }
    try w.u64_(h.session_id);
    try w.blob(&h.signature);
}

/// Reads the 4-byte transport prefix. Returns null when fewer than four bytes
/// have arrived; a non-zero type byte is a protocol violation on port 445.
pub fn frameLength(bytes: []const u8) Error!?u32 {
    if (bytes.len < transport_header_size) return null;
    if (bytes[0] != 0) return error.Malformed;
    return (@as(u32, bytes[1]) << 16) | (@as(u32, bytes[2]) << 8) | bytes[3];
}

pub fn writeFrameLength(out: *[4]u8, len: u32) void {
    out[0] = 0;
    out[1] = @intCast((len >> 16) & 0xFF);
    out[2] = @truncate(len >> 8);
    out[3] = @truncate(len);
}

/// True when a buffer starts with an SMB1 header. Clients that still open with
/// a multi-protocol negotiate get one SMB2 answer and never speak SMB1 again;
/// nothing else in this server understands the old dialect.
pub fn isSmb1(bytes: []const u8) bool {
    return bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], &smb1_protocol_id);
}

const testing = std.testing;

test "header round-trips" {
    var buf: [header_size]u8 = undefined;
    var w = wire.Writer.init(&buf);
    const original: Header = .{
        .credit_charge = 1,
        .status = 0,
        .command = .create,
        .credits = 32,
        .flags = flags.SERVER_TO_REDIR | flags.SIGNED,
        .next_command = 128,
        .message_id = 0x1122334455667788,
        .tree_id = 5,
        .session_id = 0xDEADBEEFCAFEBABE,
        .signature = @splat(0xAB),
    };
    try write(&w, original);
    try testing.expectEqual(header_size, w.pos);

    const parsed = try parse(&buf);
    try testing.expectEqual(original.command, parsed.command);
    try testing.expectEqual(original.message_id, parsed.message_id);
    try testing.expectEqual(original.session_id, parsed.session_id);
    try testing.expectEqual(original.tree_id, parsed.tree_id);
    try testing.expectEqual(original.next_command, parsed.next_command);
    try testing.expectEqualSlices(u8, &original.signature, &parsed.signature);
    try testing.expect(parsed.isSigned());
}

test "parse rejects anything that is not a 64-byte SMB2 header" {
    var buf: [header_size]u8 = @splat(0);
    try testing.expectError(error.Malformed, parse(buf[0..32]));

    @memcpy(buf[0..4], &smb1_protocol_id);
    try testing.expectError(error.NotSmb2, parse(&buf));
    try testing.expect(isSmb1(&buf));

    @memcpy(buf[0..4], &protocol_id);
    std.mem.writeInt(u16, buf[4..6], 32, .little); // wrong StructureSize
    try testing.expectError(error.Malformed, parse(&buf));
}

test "transport framing is big-endian with a zero type byte" {
    var frame: [4]u8 = undefined;
    writeFrameLength(&frame, 0x012345);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x23, 0x45 }, &frame);
    try testing.expectEqual(@as(u32, 0x012345), (try frameLength(&frame)).?);
    try testing.expectEqual(@as(?u32, null), try frameLength(&.{ 0, 1 }));
    try testing.expectError(error.Malformed, frameLength(&.{ 0x81, 0, 0, 0 })); // NetBIOS session request
}
