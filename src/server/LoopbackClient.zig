//! A client that speaks the SMB2 wire format straight into a `Server`, with no
//! socket in between.
//!
//! It builds every request byte by byte, the way a redirector does, so what it
//! exercises is the real layout rather than a helper's idea of one. The
//! protocol tests use it to check behaviour and the benchmark uses it to
//! measure the dispatch path without a kernel in the middle.

const std = @import("std");

const wire = @import("../smb/wire.zig");
const hdr = @import("../smb/header.zig");
const status = @import("../smb/status.zig");
const info = @import("../smb/info.zig");
const signing = @import("../smb/sign.zig");
const unicode = @import("../smb/unicode.zig");
const ntlm = @import("../auth/ntlm.zig");
const spnego = @import("../auth/spnego.zig");

pub const Wrapping = enum { raw, spnego };

pub fn LoopbackClient(comptime ServerType: type) type {
    return struct {
        server: *ServerType,
        conn: *ServerType.Conn,
        /// Room to build one request. Must be at least as large as the biggest
        /// write the caller intends to send.
        scratch: []u8,

        message_id: u64 = 0,
        session_id: u64 = 0,
        tree_id: u32 = 0,
        file_id: [16]u8 = @splat(0),
        /// Set once a session key is known and the client is signing.
        sign_key: ?[16]u8 = null,

        const Self = @This();

        pub fn init(server: *ServerType, slot: usize, scratch: []u8) Self {
            return .{ .server = server, .conn = server.adopt(slot), .scratch = scratch };
        }

        /// Sends one request and returns the response message, without the
        /// transport header.
        pub fn send(c: *Self, command: hdr.Command, body: []const u8) []const u8 {
            return c.sendWithFlags(command, body, 0);
        }

        pub fn sendWithFlags(c: *Self, command: hdr.Command, body: []const u8, flags: u32) []const u8 {
            var w = wire.Writer.init(c.scratch);
            c.message_id += 1;
            hdr.write(&w, .{
                .command = command,
                .credits = 64,
                .flags = flags,
                .message_id = c.message_id,
                .session_id = c.session_id,
                .tree_id = c.tree_id,
            }) catch unreachable;
            w.blob(body) catch unreachable;
            const message = w.written();
            if (c.sign_key) |key| signing.sign(.hmac_sha256, key, message);

            c.conn.out_len = 0;
            c.server.handleFrame(c.conn, message);
            return firstFrame(c.conn.out[0..c.conn.out_len]);
        }

        /// Writes one complete transport-framed request into `out` and returns
        /// how many bytes it took. This is what `send` does minus the handing
        /// over, so a caller can build a pipeline of several and give them to
        /// `Server.feed` in one go — which is the path a real socket takes and
        /// `handleFrame` does not.
        pub fn buildFrame(c: *Self, command: hdr.Command, body: []const u8, out: []u8) usize {
            var w = wire.Writer.init(out);
            w.zeroes(hdr.transport_header_size) catch unreachable;
            c.message_id += 1;
            hdr.write(&w, .{
                .command = command,
                .credits = 64,
                .message_id = c.message_id,
                .session_id = c.session_id,
                .tree_id = c.tree_id,
            }) catch unreachable;
            w.blob(body) catch unreachable;
            const message = out[hdr.transport_header_size..w.pos];
            if (c.sign_key) |key| signing.sign(.hmac_sha256, key, message);
            hdr.writeFrameLength(out[0..hdr.transport_header_size], @intCast(message.len));
            return w.pos;
        }

        /// Sends a pre-built frame (for compound chains the helpers do not
        /// cover) and returns every response in it.
        pub fn sendFrame(c: *Self, frame: []const u8) []const u8 {
            c.conn.out_len = 0;
            c.server.handleFrame(c.conn, frame);
            return firstFrame(c.conn.out[0..c.conn.out_len]);
        }

        /// The break the server sent of its own accord while answering the last
        /// request, if it sent one. It arrives behind the response, in its own
        /// transport frame, answering a request that was never made.
        pub fn breakNotification(c: *Self) ?[]const u8 {
            const buffer = c.conn.out[0..c.conn.out_len];
            var at: usize = 0;
            while (at + hdr.transport_header_size <= buffer.len) {
                const length = (hdr.frameLength(buffer[at..]) catch return null) orelse return null;
                const message = buffer[at + hdr.transport_header_size ..][0..length];
                const head = hdr.parse(message) catch return null;
                if (head.command == .oplock_break and head.message_id == std.math.maxInt(u64)) return message;
                at += hdr.transport_header_size + length;
            }
            return null;
        }

        pub fn negotiate(c: *Self) []const u8 {
            var body: [128]u8 = undefined;
            var w = wire.Writer.init(&body);
            w.u16_(36) catch unreachable;
            w.u16_(2) catch unreachable; // DialectCount
            w.u16_(hdr.security_mode.SIGNING_ENABLED) catch unreachable;
            w.u16_(0) catch unreachable;
            w.u32_(0) catch unreachable; // Capabilities
            w.zeroes(16) catch unreachable; // ClientGuid
            w.u64_(0) catch unreachable; // ClientStartTime
            w.u16_(0x0202) catch unreachable;
            w.u16_(0x0210) catch unreachable;
            return c.send(.negotiate, w.written());
        }

        pub fn sessionSetupBody(blob: []const u8, out: []u8, sign_required: bool) []u8 {
            var w = wire.Writer.init(out);
            w.u16_(25) catch unreachable;
            w.u8_(0) catch unreachable; // Flags
            w.u8_(if (sign_required) hdr.security_mode.SIGNING_REQUIRED else 0) catch unreachable;
            w.u32_(0) catch unreachable; // Capabilities
            w.u32_(0) catch unreachable; // Channel
            w.u16_(64 + 24) catch unreachable; // SecurityBufferOffset
            w.u16_(@intCast(blob.len)) catch unreachable;
            w.u64_(0) catch unreachable; // PreviousSessionId
            w.blob(blob) catch unreachable;
            return w.written();
        }

        /// The two-round NTLMv2 exchange, in whichever wrapping the caller
        /// wants to exercise.
        pub fn login(c: *Self, user: []const u8, pass: []const u8, wrap: Wrapping, sign: bool) u32 {
            var negotiate_msg: [40]u8 = @splat(0);
            @memcpy(negotiate_msg[0..8], ntlm.signature);
            std.mem.writeInt(u32, negotiate_msg[8..12], 1, .little);
            std.mem.writeInt(u32, negotiate_msg[12..16], ntlm.flags.UNICODE | ntlm.flags.NTLM, .little);

            var wrapped: [512]u8 = undefined;
            const first_blob: []const u8 = switch (wrap) {
                .raw => &negotiate_msg,
                .spnego => spnego.buildNegTokenResp(&wrapped, .accept_incomplete, true, &negotiate_msg) catch unreachable,
            };

            var body: [1024]u8 = undefined;
            const first = c.send(.session_setup, sessionSetupBody(first_blob, &body, sign));
            if (statusOf(first) != status.MORE_PROCESSING_REQUIRED) return statusOf(first);
            c.session_id = std.mem.readInt(u64, first[40..48], .little);

            const challenge_msg = spnego.findNtlmToken(securityBuffer(first)).?;
            const challenge: [8]u8 = challenge_msg[24..32].*;

            const nt_hash = ntlm.ntHash(pass) catch unreachable;
            const client_blob = [_]u8{ 0x01, 0x01, 0, 0, 0, 0, 0, 0 } ++ [_]u8{0x5A} ** 24;
            var auth_buf: [512]u8 = undefined;
            const auth_msg = ntlm.buildAuthenticateForTest(&auth_buf, nt_hash, user, "", challenge, &client_blob) catch unreachable;
            const second_blob: []const u8 = switch (wrap) {
                .raw => auth_msg,
                .spnego => spnego.buildNegTokenResp(&wrapped, .accept_incomplete, false, auth_msg) catch unreachable,
            };

            const second = c.send(.session_setup, sessionSetupBody(second_blob, &body, sign));
            const code = statusOf(second);
            if (code == status.SUCCESS and sign) {
                c.sign_key = sessionKey(nt_hash, user, challenge, &client_blob);
            }
            return code;
        }

        pub fn treeConnect(c: *Self, share: []const u8) u32 {
            var path: [128]u8 = undefined;
            const text = std.fmt.bufPrint(&path, "\\\\server\\{s}", .{share}) catch unreachable;
            var utf16_buf: [256]u8 = undefined;
            const utf16 = unicode.toUtf16le(&utf16_buf, text) catch unreachable;

            var body: [512]u8 = undefined;
            var w = wire.Writer.init(&body);
            w.u16_(9) catch unreachable;
            w.u16_(0) catch unreachable;
            w.u16_(64 + 8) catch unreachable;
            w.u16_(@intCast(utf16.len)) catch unreachable;
            w.blob(utf16) catch unreachable;

            const response = c.send(.tree_connect, w.written());
            if (statusOf(response) == status.SUCCESS) c.tree_id = std.mem.readInt(u32, response[36..40], .little);
            return statusOf(response);
        }

        pub const CreateArgs = struct {
            path: []const u8,
            /// FILE_GENERIC_READ by default.
            access_mask: u32 = 0x0012_0089,
            /// FILE_OPEN.
            disposition: u32 = 1,
            options: u32 = 0,
            attributes: u32 = 0,
            /// Ask for a lease under this key, the way a 2.1 client does.
            lease_key: ?[16]u8 = null,
            /// Ask for a plain oplock instead, the way a 2.0.2 client does.
            oplock: u8 = 0,
        };

        pub fn createBody(args: CreateArgs, out: []u8) []u8 {
            var name_buf: [1024]u8 = undefined;
            const name = unicode.toUtf16le(&name_buf, args.path) catch unreachable;
            var w = wire.Writer.init(out);
            w.u16_(57) catch unreachable;
            w.u8_(0) catch unreachable; // SecurityFlags
            w.u8_(if (args.lease_key != null) 0xFF else args.oplock) catch unreachable;
            w.u32_(2) catch unreachable; // ImpersonationLevel
            w.u64_(0) catch unreachable; // SmbCreateFlags
            w.u64_(0) catch unreachable; // Reserved
            w.u32_(args.access_mask) catch unreachable;
            w.u32_(args.attributes) catch unreachable;
            w.u32_(7) catch unreachable; // ShareAccess: read/write/delete
            w.u32_(args.disposition) catch unreachable;
            w.u32_(args.options) catch unreachable;
            w.u16_(64 + 56) catch unreachable; // NameOffset
            w.u16_(@intCast(name.len)) catch unreachable;
            const contexts_at = w.pos;
            w.u32_(0) catch unreachable; // CreateContextsOffset
            w.u32_(0) catch unreachable; // CreateContextsLength
            w.blob(name) catch unreachable;

            if (args.lease_key) |key| {
                // Contexts start 8-aligned, measured from the SMB2 header.
                while ((64 + w.pos) % 8 != 0) w.u8_(0) catch unreachable;
                const at = w.pos;
                w.u32_(0) catch unreachable; // Next
                w.u16_(16) catch unreachable; // NameOffset
                w.u16_(4) catch unreachable; // NameLength
                w.u16_(0) catch unreachable; // Reserved
                w.u16_(24) catch unreachable; // DataOffset
                w.u32_(32) catch unreachable; // DataLength
                w.blob("RqLs") catch unreachable;
                w.zeroes(4) catch unreachable;
                w.blob(&key) catch unreachable;
                w.u32_(0x0000_0007) catch unreachable; // LeaseState: read, handle and write
                w.u32_(0) catch unreachable; // LeaseFlags
                w.u64_(0) catch unreachable; // LeaseDuration
                w.patchInt(u32, contexts_at, @intCast(64 + at)) catch unreachable;
                w.patchInt(u32, contexts_at + 4, @intCast(w.pos - at)) catch unreachable;
            }
            return w.written();
        }

        pub fn open(c: *Self, args: CreateArgs) u32 {
            var body: [2048]u8 = undefined;
            const response = c.send(.create, createBody(args, &body));
            if (statusOf(response) == status.SUCCESS) @memcpy(&c.file_id, response[64 + 64 ..][0..16]);
            return statusOf(response);
        }

        pub fn writeFile(c: *Self, offset: u64, data: []const u8) []const u8 {
            // Built at the far end of the scratch buffer, since `send` builds
            // the message at the near end.
            var w = wire.Writer.init(c.scratch[c.scratch.len / 2 ..]);
            w.u16_(49) catch unreachable;
            w.u16_(64 + 48) catch unreachable; // DataOffset
            w.u32_(@intCast(data.len)) catch unreachable;
            w.u64_(offset) catch unreachable;
            w.blob(&c.file_id) catch unreachable;
            w.u32_(0) catch unreachable; // Channel
            w.u32_(0) catch unreachable; // RemainingBytes
            w.u16_(0) catch unreachable;
            w.u16_(0) catch unreachable;
            w.u32_(0) catch unreachable; // Flags
            w.blob(data) catch unreachable;
            return c.send(.write, w.written());
        }

        pub fn readFile(c: *Self, offset: u64, length: u32) []const u8 {
            var body: [64]u8 = undefined;
            return c.send(.read, c.readBody(offset, length, &body));
        }

        pub fn readBody(c: *Self, offset: u64, length: u32, out: []u8) []const u8 {
            var w = wire.Writer.init(out);
            w.u16_(49) catch unreachable;
            w.u8_(0) catch unreachable; // Padding
            w.u8_(0) catch unreachable; // Flags
            w.u32_(length) catch unreachable;
            w.u64_(offset) catch unreachable;
            w.blob(&c.file_id) catch unreachable;
            w.u32_(0) catch unreachable; // MinimumCount
            w.u32_(0) catch unreachable; // Channel
            w.u32_(0) catch unreachable; // RemainingBytes
            w.u16_(0) catch unreachable;
            w.u16_(0) catch unreachable;
            w.u8_(0) catch unreachable;
            return w.written();
        }

        pub fn queryDirectory(c: *Self, class: info.FileClass, pattern: []const u8, flags: u8) []const u8 {
            var pattern_buf: [256]u8 = undefined;
            const utf16 = unicode.toUtf16le(&pattern_buf, pattern) catch unreachable;
            var body: [512]u8 = undefined;
            var w = wire.Writer.init(&body);
            w.u16_(33) catch unreachable;
            w.u8_(@intFromEnum(class)) catch unreachable;
            w.u8_(flags) catch unreachable;
            w.u32_(0) catch unreachable; // FileIndex
            w.blob(&c.file_id) catch unreachable;
            w.u16_(64 + 32) catch unreachable;
            w.u16_(@intCast(utf16.len)) catch unreachable;
            w.u32_(64 * 1024) catch unreachable; // OutputBufferLength
            w.blob(utf16) catch unreachable;
            return c.send(.query_directory, w.written());
        }

        pub fn queryInfo(c: *Self, info_type: info.InfoType, class: u8) []const u8 {
            var body: [64]u8 = undefined;
            var w = wire.Writer.init(&body);
            w.u16_(41) catch unreachable;
            w.u8_(@intFromEnum(info_type)) catch unreachable;
            w.u8_(class) catch unreachable;
            w.u32_(4096) catch unreachable; // OutputBufferLength
            w.u16_(0) catch unreachable; // InputBufferOffset
            w.u16_(0) catch unreachable;
            w.u32_(0) catch unreachable; // InputBufferLength
            w.u32_(0x7) catch unreachable; // AdditionalInformation
            w.u32_(0) catch unreachable; // Flags
            w.blob(&c.file_id) catch unreachable;
            return c.send(.query_info, w.written());
        }

        pub fn setInfo(c: *Self, class: info.FileClass, payload: []const u8) []const u8 {
            var body: [1024]u8 = undefined;
            var w = wire.Writer.init(&body);
            w.u16_(33) catch unreachable;
            w.u8_(@intFromEnum(info.InfoType.file)) catch unreachable;
            w.u8_(@intFromEnum(class)) catch unreachable;
            w.u32_(@intCast(payload.len)) catch unreachable;
            w.u16_(64 + 32) catch unreachable; // BufferOffset
            w.u16_(0) catch unreachable; // Reserved
            w.u32_(0) catch unreachable; // AdditionalInformation
            w.blob(&c.file_id) catch unreachable;
            w.blob(payload) catch unreachable;
            return c.send(.set_info, w.written());
        }

        pub fn closeFile(c: *Self) []const u8 {
            var body: [32]u8 = undefined;
            var w = wire.Writer.init(&body);
            w.u16_(24) catch unreachable;
            w.u16_(0) catch unreachable; // Flags
            w.u32_(0) catch unreachable; // Reserved
            w.blob(&c.file_id) catch unreachable;
            return c.send(.close, w.written());
        }

        pub fn echo(c: *Self) []const u8 {
            return c.send(.echo, &.{ 4, 0, 0, 0 });
        }

        /// One LOCK request covering every range given, which is how a client
        /// takes or drops several at once — and the only way to see whether the
        /// server applies them all or none.
        pub fn lock(c: *Self, ranges: []const LockRange) u32 {
            var body: [512]u8 = undefined;
            var w = wire.Writer.init(&body);
            w.u16_(48) catch unreachable;
            w.u16_(@intCast(ranges.len)) catch unreachable; // LockCount
            w.u32_(0) catch unreachable; // LockSequence
            w.blob(&c.file_id) catch unreachable;
            for (ranges) |range| {
                w.u64_(range.offset) catch unreachable;
                w.u64_(range.length) catch unreachable;
                w.u32_(range.flags) catch unreachable;
                w.u32_(0) catch unreachable; // Reserved
            }
            return statusOf(c.send(.lock, w.written()));
        }
    };
}

pub const LockRange = struct {
    offset: u64,
    length: u64,
    flags: u32 = lock_flags.exclusive,
};

/// LockFlags from MS-SMB2.
pub const lock_flags = struct {
    pub const shared: u32 = 0x0000_0001;
    pub const exclusive: u32 = 0x0000_0002;
    pub const unlock: u32 = 0x0000_0004;
    pub const fail_immediately: u32 = 0x0000_0010;
};

/// Strips the transport header the server puts in front of every frame, and
/// checks it against what follows.
pub fn frameBody(frame: []const u8) []const u8 {
    if (frame.len == 0) return frame;
    const length = (hdr.frameLength(frame) catch unreachable).?;
    std.debug.assert(length == frame.len - hdr.transport_header_size);
    return frame[hdr.transport_header_size..];
}

/// The first frame in a buffer, without its transport header. The server may
/// have written more than one: a break notification follows the response whose
/// handling decided on it.
pub fn firstFrame(buffer: []const u8) []const u8 {
    if (buffer.len == 0) return buffer;
    const length = (hdr.frameLength(buffer) catch unreachable).?;
    return buffer[hdr.transport_header_size..][0..length];
}

pub fn statusOf(response: []const u8) u32 {
    return std.mem.readInt(u32, response[8..12], .little);
}

pub fn bodyOf(response: []const u8) []const u8 {
    return response[hdr.header_size..];
}

/// The security buffer out of a NEGOTIATE or SESSION_SETUP response.
pub fn securityBuffer(response: []const u8) []const u8 {
    const command: hdr.Command = @enumFromInt(std.mem.readInt(u16, response[12..14], .little));
    const fixed: usize = switch (command) {
        .negotiate => 56,
        .session_setup => 4,
        else => unreachable,
    };
    const body = bodyOf(response);
    const offset = std.mem.readInt(u16, body[fixed..][0..2], .little);
    const length = std.mem.readInt(u16, body[fixed + 2 ..][0..2], .little);
    return response[offset..][0..length];
}

/// Recomputes the SMB session key the way the client side of NTLMv2 does, so
/// the caller can sign what it sends.
pub fn sessionKey(nt_hash: [16]u8, user: []const u8, challenge: [8]u8, blob: []const u8) [16]u8 {
    const HmacMd5 = std.crypto.auth.hmac.HmacMd5;
    const key = ntlm.responseKey(nt_hash, user, "") catch unreachable;
    var proof: [16]u8 = undefined;
    var mac = HmacMd5.init(&key);
    mac.update(&challenge);
    mac.update(blob);
    mac.final(&proof);
    var out: [16]u8 = undefined;
    HmacMd5.create(&out, &proof, &key);
    return out;
}
