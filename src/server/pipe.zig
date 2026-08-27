//! The one named pipe this server answers: `\srvsvc`, enough of it to tell a
//! client what shares exist.
//!
//! Listing shares is not a file operation. A client opens a pipe on `IPC$`,
//! binds to the Server Service interface over DCE/RPC, and calls
//! NetShareEnumAll; the answer comes back marshalled in NDR. That is three
//! layers of encoding to say "here are four names", which is why so many small
//! servers skip it — and why a share on them can be mounted but never found.
//!
//! What is here is deliberately the narrow path: one interface, one call, one
//! information level. Anything else is answered with a fault, which is what a
//! client expects when it asks a server for something the server does not do.

const std = @import("std");
const wire = @import("../smb/wire.zig");
const unicode = @import("../smb/unicode.zig");

/// DCE/RPC packet types, of which this speaks four.
const ptype = struct {
    const request: u8 = 0;
    const response: u8 = 2;
    const fault: u8 = 3;
    const bind: u8 = 11;
    const bind_ack: u8 = 12;
};

const pfc_first_last: u8 = 0x03;
/// Little-endian, ASCII, IEEE floats: the only representation anyone sends.
const data_representation = [4]u8{ 0x10, 0x00, 0x00, 0x00 };
const header_size = 16;

pub const Error = wire.Error || unicode.Error;

/// 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0, the way NDR is named on the
/// wire. A client that cannot do this one gets its context rejected.
const ndr_syntax = [16]u8{
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
};
const ndr_version: u32 = 2;

/// NetShareEnumAll.
const opnum_share_enum: u16 = 15;

/// WERR_UNKNOWN_LEVEL: the client asked for a description of a share in a
/// shape this does not produce.
const werr_unknown_level: u32 = 0x0000_007C;
/// nca_s_op_rng_error: no such operation on this interface.
const fault_op_rng_error: u32 = 0x1C01_0002;

/// The share types a client understands. A disk share is offered for use; the
/// interprocess one is hidden, because it is not something anyone mounts.
const share_type = struct {
    const disktree: u32 = 0x0000_0000;
    const ipc_hidden: u32 = 0x8000_0003;
};

pub const max_contexts = 4;

/// What a client asked for, kept between the request arriving and the answer
/// being written. Small on purpose: it lives in every open handle.
pub const State = struct {
    reply: Reply = .none,
    call_id: u32 = 0,
    context_id: u16 = 0,
    level: u32 = 0,
    fault_code: u32 = 0,
    /// BIND: how many contexts were offered, and which of them can be
    /// accepted. Results are positional, so the count has to come back with
    /// the answer even for the ones being turned down.
    context_count: u8 = 0,
    accepted: u8 = 0,

    pub const Reply = enum { none, bind_ack, share_enum, fault };
};

/// Reads one PDU from a client and works out what the answer will be. Nothing
/// is written here: the answer may be asked for in a separate READ, and the
/// buffer it goes into belongs to that request.
pub fn receive(state: *State, pdu: []const u8) void {
    state.* = .{};
    if (pdu.len < header_size) return;

    var r = wire.Reader.init(pdu);
    const version = r.u8_() catch return;
    _ = r.u8_() catch return; // minor version
    const kind = r.u8_() catch return;
    _ = r.u8_() catch return; // flags
    _ = r.take(4) catch return; // data representation
    _ = r.u16_() catch return; // fragment length
    _ = r.u16_() catch return; // authentication length
    const call_id = r.u32_() catch return;
    if (version != 5) return;

    state.call_id = call_id;
    switch (kind) {
        ptype.bind => receiveBind(state, &r),
        ptype.request => receiveRequest(state, &r),
        else => {
            state.reply = .fault;
            state.fault_code = fault_op_rng_error;
        },
    }
}

fn receiveBind(state: *State, r: *wire.Reader) void {
    _ = r.u16_() catch return; // max transmit fragment
    _ = r.u16_() catch return; // max receive fragment
    _ = r.u32_() catch return; // association group
    const count = r.u8_() catch return;
    _ = r.u8_() catch return; // reserved
    _ = r.u16_() catch return; // reserved

    state.reply = .bind_ack;
    state.context_count = @intCast(@min(count, max_contexts));

    var index: usize = 0;
    while (index < state.context_count) : (index += 1) {
        _ = r.u16_() catch return; // context id
        const syntaxes = r.u8_() catch return;
        _ = r.u8_() catch return; // reserved
        _ = r.take(20) catch return; // abstract syntax: which interface

        // A context is accepted if NDR is among the ways it offers to encode.
        var offered: usize = 0;
        while (offered < syntaxes) : (offered += 1) {
            const uuid = r.take(16) catch return;
            const version = r.u32_() catch return;
            if (std.mem.eql(u8, uuid, &ndr_syntax) and version == ndr_version) {
                state.accepted |= @as(u8, 1) << @intCast(index);
            }
        }
    }
}

fn receiveRequest(state: *State, r: *wire.Reader) void {
    _ = r.u32_() catch return; // allocation hint
    state.context_id = r.u16_() catch return;
    const opnum = r.u16_() catch return;

    if (opnum != opnum_share_enum) {
        state.reply = .fault;
        state.fault_code = fault_op_rng_error;
        return;
    }
    state.reply = .share_enum;
    state.level = shareEnumLevel(r) orelse 1;
}

/// The information level a NetShareEnumAll asked for, out of the marshalled
/// arguments in front of it: a server name nobody needs, then the level.
fn shareEnumLevel(r: *wire.Reader) ?u32 {
    const name_pointer = r.u32_() catch return null;
    if (name_pointer != 0) {
        _ = r.u32_() catch return null; // maximum count
        _ = r.u32_() catch return null; // offset
        const actual = r.u32_() catch return null;
        if (actual > std.math.maxInt(u32) / 2) return null;
        const bytes = actual * 2;
        r.skip(bytes + (bytes % 4)) catch return null; // characters, padded to four
    }
    return r.u32_() catch null;
}

/// One share as a client is told about it.
pub const Entry = struct {
    name: []const u8,
    ipc: bool = false,
};

/// Writes the answer decided on by the last `receive`.
pub fn respond(state: *const State, w: *wire.Writer, shares: []const Entry) Error!void {
    const start = w.pos;
    switch (state.reply) {
        .none => return,
        .bind_ack => {
            try writeHeader(w, ptype.bind_ack, state.call_id);
            try writeBindAck(w, state, start);
        },
        .share_enum => {
            try writeHeader(w, ptype.response, state.call_id);
            try w.u32_(0); // allocation hint, patched below
            try w.u16_(state.context_id);
            try w.u8_(0); // cancel count
            try w.u8_(0); // reserved
            const stub_at = w.pos;
            try writeShareEnum(w, state.level, shares);
            try w.patchInt(u32, stub_at - 8, @intCast(w.pos - stub_at));
        },
        .fault => {
            try writeHeader(w, ptype.fault, state.call_id);
            try w.u32_(0); // allocation hint
            try w.u16_(state.context_id);
            try w.u8_(0); // cancel count
            try w.u8_(0); // reserved
            try w.u32_(state.fault_code);
            try w.u32_(0); // reserved
        },
    }
    // The fragment length is only known once the fragment is written.
    try w.patchInt(u16, start + 8, @intCast(w.pos - start));
}

fn writeHeader(w: *wire.Writer, kind: u8, call_id: u32) wire.Error!void {
    try w.u8_(5); // version
    try w.u8_(0); // minor version
    try w.u8_(kind);
    try w.u8_(pfc_first_last);
    try w.blob(&data_representation);
    try w.u16_(0); // fragment length, patched by the caller
    try w.u16_(0); // authentication length
    try w.u32_(call_id);
}

fn writeBindAck(w: *wire.Writer, state: *const State, start: usize) wire.Error!void {
    try w.u16_(4280); // maximum transmit fragment
    try w.u16_(4280); // maximum receive fragment
    try w.u32_(0x0000_1063); // association group, any non-zero number will do

    // The address a client would use to reach this pipe a second time.
    const address = "\\PIPE\\srvsvc";
    try w.u16_(address.len + 1);
    try w.blob(address);
    try w.u8_(0);
    while ((w.pos - start) % 4 != 0) try w.u8_(0);

    try w.u8_(state.context_count);
    try w.u8_(0); // reserved
    try w.u16_(0); // reserved

    var index: usize = 0;
    while (index < state.context_count) : (index += 1) {
        const accepted = state.accepted & (@as(u8, 1) << @intCast(index)) != 0;
        if (accepted) {
            try w.u16_(0); // acceptance
            try w.u16_(0); // reason
            try w.blob(&ndr_syntax);
            try w.u32_(ndr_version);
        } else {
            // Provider rejection, "proposed transfer syntaxes not supported".
            try w.u16_(2);
            try w.u16_(2);
            try w.zeroes(16);
            try w.u32_(0);
        }
    }
}

/// NetShareEnumAll's answer, marshalled the way NDR wants it: the fixed part
/// of every entry first, then the strings they point at, in the same order.
fn writeShareEnum(w: *wire.Writer, level: u32, shares: []const Entry) Error!void {
    try w.u32_(level);
    if (level != 1) {
        // The level is echoed, the union is empty, and the error says why.
        try w.u32_(level);
        try w.u32_(0); // no container
        try w.u32_(0); // total entries
        try w.u32_(0); // no resume handle
        try w.u32_(werr_unknown_level);
        return;
    }

    const count: u32 = @intCast(shares.len);
    try w.u32_(1); // union arm: SHARE_INFO_1
    try w.u32_(reference_pointer); // the container is always there
    try w.u32_(count); // EntriesRead
    try w.u32_(reference_pointer + 4); // and so is its array
    try w.u32_(count); // the array's maximum count

    var pointer: u32 = reference_pointer + 8;
    for (shares) |share| {
        try w.u32_(pointer); // the name, deferred
        pointer += 4;
        try w.u32_(if (share.ipc) share_type.ipc_hidden else share_type.disktree);
        try w.u32_(pointer); // the remark, deferred
        pointer += 4;
    }
    for (shares) |share| {
        try writeString(w, share.name);
        try writeString(w, "");
    }

    try w.u32_(count); // TotalEntries
    try w.u32_(0); // no resume handle
    try w.u32_(0); // WERR_OK
}

/// The first pointer identity handed out. Any non-zero number does; what
/// matters is that a pointer that is meant to be there is not zero.
const reference_pointer: u32 = 0x0002_0000;

/// A string as NDR carries one: how much room it takes, where it starts, how
/// much of it there is, and then the characters, including the terminator.
fn writeString(w: *wire.Writer, text: []const u8) Error!void {
    const chars = try unicode.utf16leLen(text) / 2 + 1;
    try w.u32_(@intCast(chars)); // maximum count
    try w.u32_(0); // offset
    try w.u32_(@intCast(chars)); // actual count
    _ = try unicode.toUtf16le(try w.reserve((chars - 1) * 2), text);
    try w.u16_(0); // the terminator, which NDR counts as a character
    if ((chars * 2) % 4 != 0) try w.u16_(0); // padded to four
}

const testing = std.testing;

test "a bind is accepted for a client that offers NDR" {
    var request: [72]u8 = undefined;
    var w = wire.Writer.init(&request);
    try writeHeader(&w, ptype.bind, 7);
    try w.u16_(4280);
    try w.u16_(4280);
    try w.u32_(0);
    try w.u8_(1); // one context
    try w.u8_(0);
    try w.u16_(0);
    try w.u16_(0); // context id
    try w.u8_(1); // one transfer syntax
    try w.u8_(0);
    try w.zeroes(20); // abstract syntax
    try w.blob(&ndr_syntax);
    try w.u32_(ndr_version);

    var state = State{};
    receive(&state, w.written());
    try testing.expectEqual(State.Reply.bind_ack, state.reply);
    try testing.expectEqual(@as(u32, 7), state.call_id);
    try testing.expectEqual(@as(u8, 1), state.context_count);
    try testing.expectEqual(@as(u8, 1), state.accepted);

    var out: [128]u8 = undefined;
    var answer = wire.Writer.init(&out);
    try respond(&state, &answer, &.{});
    const pdu = answer.written();
    try testing.expectEqual(ptype.bind_ack, pdu[2]);
    try testing.expectEqual(@as(u16, @intCast(pdu.len)), std.mem.readInt(u16, pdu[8..10], .little));
    // Acceptance, and the syntax it was accepted for.
    const result_at = pdu.len - 24;
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, pdu[result_at..][0..2], .little));
    try testing.expectEqualSlices(u8, &ndr_syntax, pdu[result_at + 4 ..][0..16]);
}

test "a context that cannot do NDR is turned down, not ignored" {
    var request: [72]u8 = undefined;
    var w = wire.Writer.init(&request);
    try writeHeader(&w, ptype.bind, 1);
    try w.u16_(4280);
    try w.u16_(4280);
    try w.u32_(0);
    try w.u8_(1);
    try w.u8_(0);
    try w.u16_(0);
    try w.u16_(0);
    try w.u8_(1);
    try w.u8_(0);
    try w.zeroes(20);
    try w.zeroes(16); // some other syntax
    try w.u32_(1);

    var state = State{};
    receive(&state, w.written());
    try testing.expectEqual(@as(u8, 1), state.context_count);
    try testing.expectEqual(@as(u8, 0), state.accepted);
}

test "a share list comes back as one entry per share" {
    var request: [48]u8 = undefined;
    var w = wire.Writer.init(&request);
    try writeHeader(&w, ptype.request, 9);
    try w.u32_(0); // allocation hint
    try w.u16_(0); // context id
    try w.u16_(opnum_share_enum);
    try w.u32_(0); // no server name
    try w.u32_(1); // level 1

    var state = State{};
    receive(&state, w.written());
    try testing.expectEqual(State.Reply.share_enum, state.reply);
    try testing.expectEqual(@as(u32, 1), state.level);

    var out: [512]u8 = undefined;
    var answer = wire.Writer.init(&out);
    try respond(&state, &answer, &.{
        .{ .name = "files" },
        .{ .name = "IPC$", .ipc = true },
    });
    const pdu = answer.written();
    try testing.expectEqual(ptype.response, pdu[2]);

    const stub = pdu[24..];
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, stub[0..4], .little)); // level
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, stub[12..16], .little)); // entries
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, stub[20..24], .little)); // array count
    // The second entry is the hidden interprocess one.
    try testing.expectEqual(share_type.ipc_hidden, std.mem.readInt(u32, stub[40..44], .little));
    // And the total at the end agrees with the count at the front.
    const tail = stub[stub.len - 12 ..];
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, tail[0..4], .little));
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, tail[8..12], .little)); // WERR_OK
}

test "an operation this interface does not have is faulted, not ignored" {
    var request: [32]u8 = undefined;
    var w = wire.Writer.init(&request);
    try writeHeader(&w, ptype.request, 2);
    try w.u32_(0);
    try w.u16_(0);
    try w.u16_(21); // NetSrvGetInfo, which is not here

    var state = State{};
    receive(&state, w.written());
    try testing.expectEqual(State.Reply.fault, state.reply);

    var out: [64]u8 = undefined;
    var answer = wire.Writer.init(&out);
    try respond(&state, &answer, &.{});
    try testing.expectEqual(ptype.fault, answer.written()[2]);
    try testing.expectEqual(fault_op_rng_error, std.mem.readInt(u32, answer.written()[24..28], .little));
}

test "a level nobody implements is refused in the shape the client expects" {
    var out: [128]u8 = undefined;
    var w = wire.Writer.init(&out);
    const state = State{ .reply = .share_enum, .level = 502 };
    try respond(&state, &w, &.{});
    const stub = w.written()[24..];
    try testing.expectEqual(@as(u32, 502), std.mem.readInt(u32, stub[0..4], .little));
    try testing.expectEqual(werr_unknown_level, std.mem.readInt(u32, stub[20..24], .little));
}
