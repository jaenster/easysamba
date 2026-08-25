//! End-to-end protocol tests: a real `Server`, a real `MemFs` share, a real
//! account table, and a hand-built client that speaks the wire format.
//!
//! These drive `handleFrame` directly rather than a socket, so they cover
//! everything above the transport — negotiation, NTLMv2, signing, compounding,
//! and every handler — without needing a network or a filesystem.

const std = @import("std");
const testing = std.testing;

const wire = @import("../smb/wire.zig");
const hdr = @import("../smb/header.zig");
const status = @import("../smb/status.zig");
const info = @import("../smb/info.zig");
const signing = @import("../smb/sign.zig");
const unicode = @import("../smb/unicode.zig");
const ntlm = @import("../auth/ntlm.zig");
const spnego = @import("../auth/spnego.zig");
const Authenticator = @import("../auth/Authenticator.zig");
const Share = @import("../vfs/Share.zig");
const MemFs = @import("../vfs/MemFs.zig").MemFs;
const server_mod = @import("Server.zig");
const Server = server_mod.Server;
const loopback = @import("LoopbackClient.zig");

const statusOf = loopback.statusOf;
const bodyOf = loopback.bodyOf;
const securityBuffer = loopback.securityBuffer;
const frameBody = loopback.frameBody;

const TestServer = Server(.{
    .max_connections = 1,
    .sessions_per_connection = 2,
    .trees_per_session = 4,
    .opens_per_session = 8,
    .max_shares = 2,
    .in_buffer = 64 * 1024,
    .out_buffer = 64 * 1024,
    .max_read = 16 * 1024,
    .max_write = 16 * 1024,
    .max_transact = 16 * 1024,
    .path_bytes = 256,
    .search_pattern_bytes = 64,
});
const TestFs = MemFs(.{ .max_nodes = 16, .max_file_bytes = 4096, .max_path = 128 });
const Accounts = Authenticator.UserTable(4, 32);
const Client = loopback.LoopbackClient(TestServer);

const password = "hunter2";

/// A server, a share, an account table and a client wired straight into it.
const Harness = struct {
    server: *TestServer,
    conn: *TestServer.Conn,
    fs: *TestFs,
    accounts: *Accounts,
    scratch: []u8,
    client: Client,

    fn create(allocator: std.mem.Allocator, config: server_mod.Config, accounts_config: []const u8) !*Harness {
        const h = try allocator.create(Harness);
        h.* = .{
            .server = try allocator.create(TestServer),
            .conn = undefined,
            .fs = try allocator.create(TestFs),
            .accounts = try allocator.create(Accounts),
            .scratch = try allocator.alloc(u8, 64 * 1024),
            .client = undefined,
        };
        try h.accounts.parse(accounts_config);
        h.fs.init();
        h.server.init(config, h.accounts.authenticator());
        try h.server.addShare(h.fs.share("data"));
        h.client = Client.init(h.server, 0, h.scratch);
        h.conn = h.client.conn;
        return h;
    }

    fn destroy(h: *Harness, allocator: std.mem.Allocator) void {
        allocator.free(h.scratch);
        allocator.destroy(h.accounts);
        allocator.destroy(h.fs);
        allocator.destroy(h.server);
        allocator.destroy(h);
    }
};

fn setup(config: server_mod.Config, accounts: []const u8) !*Harness {
    const c = try Harness.create(testing.allocator, config, accounts);
    try c.fs.put("notes.txt", "hello smb");
    try c.fs.mkdir("docs");
    try c.fs.put("docs/report.pdf", "%PDF-1.4");
    return c;
}

fn loggedIn(user: []const u8) !*Harness {
    const c = try setup(.{}, "alice:" ++ password ++ "\nbob:" ++ password ++ ":ro");
    _ = c.client.negotiate();
    try testing.expectEqual(status.SUCCESS, c.client.login(user, password, .raw, false));
    try testing.expectEqual(status.SUCCESS, c.client.treeConnect("data"));
    return c;
}

test "negotiate settles on 2.1 and offers NTLMSSP" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);

    const response = c.client.negotiate();
    try testing.expectEqual(status.SUCCESS, statusOf(response));

    const body = bodyOf(response);
    try testing.expectEqual(@as(u16, 65), std.mem.readInt(u16, body[0..2], .little));
    try testing.expectEqual(@as(u16, 0x0210), std.mem.readInt(u16, body[4..6], .little));
    try testing.expect(std.mem.readInt(u16, body[2..4], .little) & hdr.security_mode.SIGNING_ENABLED != 0);
    try testing.expectEqual(@as(u32, 16 * 1024), std.mem.readInt(u32, body[28..32], .little)); // MaxRead

    const blob = securityBuffer(response);
    try testing.expect(std.mem.indexOf(u8, blob, &spnego.ntlmssp_oid) != null);
}

test "an SMB1 multi-protocol negotiate gets one SMB2 answer" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);

    var message: [64]u8 = @splat(0);
    @memcpy(message[0..4], &hdr.smb1_protocol_id);
    const response = c.client.sendFrame(&message);
    try testing.expect(std.mem.eql(u8, response[0..4], &hdr.protocol_id));
    try testing.expectEqual(@as(u16, 0x02FF), std.mem.readInt(u16, bodyOf(response)[4..6], .little));
}

test "requests before a negotiate are refused" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    var body: [64]u8 = undefined;
    try testing.expectEqual(status.INVALID_PARAMETER, statusOf(c.client.send(.session_setup, Client.sessionSetupBody(&.{}, &body, false))));
}

test "NTLMv2 login with a raw NTLMSSP token" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    try testing.expectEqual(status.SUCCESS, c.client.login("alice", password, .raw, false));
    try testing.expect(c.client.session_id != 0);
}

test "NTLMv2 login with the token wrapped in SPNEGO, as real clients send it" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    try testing.expectEqual(status.SUCCESS, c.client.login("alice", password, .spnego, false));
    try testing.expect(c.client.session_id != 0);
}

test "a wrong password and an unknown user are both refused, with no session left behind" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();

    try testing.expectEqual(status.LOGON_FAILURE, c.client.login("alice", "wrong", .raw, false));
    try testing.expect(!c.server.conns[0].sessions[0].established);

    c.client.session_id = 0;
    try testing.expectEqual(status.LOGON_FAILURE, c.client.login("mallory", password, .raw, false));
}

test "a null session is refused outright" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();

    // An AUTHENTICATE with no user and no response: the anonymous logon every
    // SMB server used to accept.
    var negotiate_msg: [40]u8 = @splat(0);
    @memcpy(negotiate_msg[0..8], ntlm.signature);
    std.mem.writeInt(u32, negotiate_msg[8..12], 1, .little);
    var body: [512]u8 = undefined;
    const first = c.client.send(.session_setup, Client.sessionSetupBody(&negotiate_msg, &body, false));
    c.client.session_id = std.mem.readInt(u64, first[40..48], .little);

    var anonymous: [72]u8 = @splat(0);
    @memcpy(anonymous[0..8], ntlm.signature);
    std.mem.writeInt(u32, anonymous[8..12], 3, .little);
    const second = c.client.send(.session_setup, Client.sessionSetupBody(&anonymous, &body, false));
    try testing.expectEqual(status.LOGON_FAILURE, statusOf(second));
}

test "commands before authentication are refused" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    try testing.expectEqual(status.USER_SESSION_DELETED, c.client.treeConnect("data"));
}

test "tree connect finds the share and refuses anything else" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    _ = c.client.login("alice", password, .raw, false);

    try testing.expectEqual(status.SUCCESS, c.client.treeConnect("data"));
    try testing.expect(c.client.tree_id != 0);
    try testing.expectEqual(status.SUCCESS, c.client.treeConnect("DATA")); // case-insensitive
    try testing.expectEqual(status.BAD_NETWORK_NAME, c.client.treeConnect("secret"));
}

test "IPC$ connects as an empty pipe share and refuses every open" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    _ = c.client.login("alice", password, .raw, false);

    // Clients connect IPC$ as part of establishing a session; failing that
    // outright makes them give up before they ever ask for a real share.
    try testing.expectEqual(status.SUCCESS, c.client.treeConnect("ipc$"));
    var body: [64]u8 = undefined;
    const response = c.client.send(.tree_connect, blk: {
        var path_buf: [64]u8 = undefined;
        const utf16 = unicode.toUtf16le(&path_buf, "\\\\server\\IPC$") catch unreachable;
        var w = wire.Writer.init(&body);
        w.u16_(9) catch unreachable;
        w.u16_(0) catch unreachable;
        w.u16_(64 + 8) catch unreachable;
        w.u16_(@intCast(utf16.len)) catch unreachable;
        w.blob(utf16) catch unreachable;
        break :blk w.written();
    });
    try testing.expectEqual(@as(u8, 2), bodyOf(response)[2]); // SHARE_TYPE_PIPE

    try testing.expectEqual(status.ACCESS_DENIED, c.client.open(.{ .path = "srvsvc" }));
}

test "open, read and close an existing file" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);

    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt" }));
    const response = c.client.readFile(0, 64);
    try testing.expectEqual(status.SUCCESS, statusOf(response));

    const body = bodyOf(response);
    const data_offset = body[2];
    const data_length = std.mem.readInt(u32, body[4..8], .little);
    try testing.expectEqual(@as(u8, 80), data_offset); // header + fixed part
    try testing.expectEqualStrings("hello smb", response[data_offset..][0..data_length]);
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.closeFile()));
}

test "creating a file under a directory that does not exist fails cleanly" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.OBJECT_PATH_NOT_FOUND, c.client.open(.{
        .path = "nowhere\\file.txt",
        .access_mask = 0x0012_0116,
        .disposition = 3, // FILE_OPEN_IF
    }));
}

test "writing a new file and reading it back" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);

    try testing.expectEqual(status.SUCCESS, c.client.open(.{
        .path = "fresh.txt",
        .access_mask = 0x0012_019F, // read and write, as a client that means to do both asks
        .disposition = 3,
    }));
    const write_response = c.client.writeFile(0, "written by a test");
    try testing.expectEqual(status.SUCCESS, statusOf(write_response));
    try testing.expectEqual(@as(u32, 17), std.mem.readInt(u32, bodyOf(write_response)[4..8], .little));

    const read_response = c.client.readFile(0, 64);
    const body = bodyOf(read_response);
    const length = std.mem.readInt(u32, body[4..8], .little);
    try testing.expectEqualStrings("written by a test", read_response[body[2]..][0..length]);
}

test "a read-only account may read but not write" {
    const c = try setup(.{}, "alice:" ++ password ++ "\nbob:" ++ password ++ ":ro");
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    try testing.expectEqual(status.SUCCESS, c.client.login("bob", password, .raw, false));
    try testing.expectEqual(status.SUCCESS, c.client.treeConnect("data"));

    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt" }));
    try testing.expectEqual(status.ACCESS_DENIED, c.client.open(.{
        .path = "notes.txt",
        .access_mask = 0x0012_0116,
    }));
    try testing.expectEqual(status.ACCESS_DENIED, c.client.open(.{
        .path = "brand-new.txt",
        .access_mask = 0x0012_0116,
        .disposition = 2,
    }));
}

test "paths that try to escape the share are refused" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.OBJECT_NAME_INVALID, c.client.open(.{ .path = "..\\..\\etc\\passwd" }));
    try testing.expectEqual(status.OBJECT_NAME_INVALID, c.client.open(.{ .path = "docs\\..\\..\\x" }));
    try testing.expectEqual(status.OBJECT_NAME_INVALID, c.client.open(.{ .path = "notes.txt:$DATA" }));
    try testing.expectEqual(status.OBJECT_NAME_NOT_FOUND, c.client.open(.{ .path = "nothing-here" }));
}

test "the root reports its name as a single backslash" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "", .options = 1 }));

    const all = c.client.queryInfo(.file, @intFromEnum(info.FileClass.all));
    const at = std.mem.readInt(u16, bodyOf(all)[2..4], .little);
    const name_len = std.mem.readInt(u32, all[at + 96 ..][0..4], .little);
    var name_utf8: [8]u8 = undefined;
    try testing.expectEqualStrings("\\", try unicode.toUtf8(&name_utf8, all[at + 100 ..][0..name_len]));
    try testing.expect(std.mem.readInt(u32, bodyOf(all)[4..8], .little) >= 101);
}

test "directory listing starts with . and .. and honours the pattern" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "", .options = 1 })); // FILE_DIRECTORY_FILE

    const response = c.client.queryDirectory(.id_both_directory, "*", 0);
    try testing.expectEqual(status.SUCCESS, statusOf(response));

    var names: [8][]const u8 = undefined;
    var name_storage: [8][64]u8 = undefined;
    const count = collectNames(response, 104, &names, &name_storage); // FileIdBothDirectoryInformation
    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqualStrings(".", names[0]);
    try testing.expectEqualStrings("..", names[1]);
    try testing.expectEqualStrings("notes.txt", names[2]);
    try testing.expectEqualStrings("docs", names[3]);

    // A second pass over an exhausted directory says so rather than repeating.
    try testing.expectEqual(status.NO_MORE_FILES, statusOf(c.client.queryDirectory(.id_both_directory, "", 0)));

    // Restarting with a pattern narrows the result.
    const filtered = c.client.queryDirectory(.both_directory, "*.txt", 0x01); // RESTART_SCANS
    try testing.expectEqual(status.SUCCESS, statusOf(filtered));
    const filtered_count = collectNames(filtered, 94, &names, &name_storage); // FileBothDirectoryInformation
    try testing.expectEqual(@as(usize, 1), filtered_count);
    try testing.expectEqualStrings("notes.txt", names[0]);

    try testing.expectEqual(status.NO_SUCH_FILE, statusOf(c.client.queryDirectory(.both_directory, "nothing*", 0x01)));
}

/// Walks a QUERY_DIRECTORY response, copying each entry's name out. `fixed` is
/// the class's fixed record size, which is where its name begins.
fn collectNames(response: []const u8, fixed: usize, names: [][]const u8, storage: [][64]u8) usize {
    const body = bodyOf(response);
    const offset = std.mem.readInt(u16, body[2..4], .little);
    const length = std.mem.readInt(u32, body[4..8], .little);
    const buffer = response[offset..][0..length];

    var count: usize = 0;
    var pos: usize = 0;
    while (pos < buffer.len and count < names.len) {
        const entry = buffer[pos..];
        const next = std.mem.readInt(u32, entry[0..4], .little);
        const name_length = std.mem.readInt(u32, entry[60..64], .little);
        var utf8: [64]u8 = undefined;
        const decoded = unicode.toUtf8(&utf8, entry[fixed..][0..name_length]) catch unreachable;
        @memcpy(storage[count][0..decoded.len], decoded);
        names[count] = storage[count][0..decoded.len];
        count += 1;
        if (next == 0) break;
        pos += next;
    }
    return count;
}

test "query info: basic, standard, all and the filesystem classes" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt" }));

    const basic = c.client.queryInfo(.file, @intFromEnum(info.FileClass.basic));
    try testing.expectEqual(status.SUCCESS, statusOf(basic));
    try testing.expectEqual(@as(u32, 40), std.mem.readInt(u32, bodyOf(basic)[4..8], .little));

    const standard = c.client.queryInfo(.file, @intFromEnum(info.FileClass.standard));
    const standard_body = bodyOf(standard);
    const at = std.mem.readInt(u16, standard_body[2..4], .little);
    try testing.expectEqual(@as(u64, 9), std.mem.readInt(u64, standard[at + 8 ..][0..8], .little)); // EndOfFile

    const all = c.client.queryInfo(.file, @intFromEnum(info.FileClass.all));
    try testing.expectEqual(status.SUCCESS, statusOf(all));
    const all_len = std.mem.readInt(u32, bodyOf(all)[4..8], .little);
    // 100 bytes of fixed fields plus the name. A client that expects the whole
    // structure rejects anything under 101, so the name is never empty.
    try testing.expect(all_len >= 101);
    const all_at = std.mem.readInt(u16, bodyOf(all)[2..4], .little);
    const name_len = std.mem.readInt(u32, all[all_at + 96 ..][0..4], .little);
    var name_utf8: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "\\notes.txt",
        try unicode.toUtf8(&name_utf8, all[all_at + 100 ..][0..name_len]),
    );

    const fs_size = c.client.queryInfo(.filesystem, @intFromEnum(info.FsClass.full_size));
    try testing.expectEqual(status.SUCCESS, statusOf(fs_size));
    try testing.expectEqual(@as(u32, 32), std.mem.readInt(u32, bodyOf(fs_size)[4..8], .little));

    const security = c.client.queryInfo(.security, 0);
    try testing.expectEqual(status.SUCCESS, statusOf(security));

    try testing.expectEqual(status.INVALID_INFO_CLASS, statusOf(c.client.queryInfo(.file, 99)));
}

test "set info: truncate, rename, and delete on close" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{
        .path = "notes.txt",
        .access_mask = 0x0012_0116,
    }));

    var eof: [8]u8 = undefined;
    std.mem.writeInt(u64, &eof, 4, .little);
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.setInfo(.end_of_file, &eof)));

    var rename_buf: [64]u8 = undefined;
    var w = wire.Writer.init(&rename_buf);
    w.u8_(0) catch unreachable; // ReplaceIfExists
    w.zeroes(7) catch unreachable;
    w.u64_(0) catch unreachable; // RootDirectory
    var name_buf: [32]u8 = undefined;
    const name = unicode.toUtf16le(&name_buf, "renamed.txt") catch unreachable;
    w.u32_(@intCast(name.len)) catch unreachable;
    w.blob(name) catch unreachable;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.setInfo(.rename, w.written())));

    _ = c.client.closeFile();
    try testing.expectEqual(status.OBJECT_NAME_NOT_FOUND, c.client.open(.{ .path = "notes.txt" }));
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "renamed.txt" }));

    // Now delete it: mark the disposition and close.
    try testing.expectEqual(status.SUCCESS, c.client.open(.{
        .path = "renamed.txt",
        .access_mask = 0x0001_0000, // DELETE
    }));
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.setInfo(.disposition, &.{1})));
    _ = c.client.closeFile();
    try testing.expectEqual(status.OBJECT_NAME_NOT_FOUND, c.client.open(.{ .path = "renamed.txt" }));
}

test "a compound create + query_info + close in one frame" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);

    var frame: [1024]u8 = undefined;
    var w = wire.Writer.init(&frame);

    var create_body: [512]u8 = undefined;
    const create = Client.createBody(.{ .path = "notes.txt" }, &create_body);

    // Request 1: CREATE, with NextCommand pointing at request 2.
    const first_at = w.pos;
    c.client.message_id += 1;
    hdr.write(&w, .{
        .command = .create,
        .credits = 64,
        .message_id = c.client.message_id,
        .session_id = c.client.session_id,
        .tree_id = c.client.tree_id,
    }) catch unreachable;
    w.blob(create) catch unreachable;
    w.alignTo(8) catch unreachable;
    w.patchInt(u32, first_at + 20, @intCast(w.pos - first_at)) catch unreachable;

    // Request 2: QUERY_INFO on the file the CREATE just opened, named by the
    // all-ones FileId that only means anything inside a related chain.
    const second_at = w.pos;
    c.client.message_id += 1;
    hdr.write(&w, .{
        .command = .query_info,
        .credits = 64,
        .flags = hdr.flags.RELATED_OPERATIONS,
        .message_id = c.client.message_id,
    }) catch unreachable;
    w.u16_(41) catch unreachable;
    w.u8_(@intFromEnum(info.InfoType.file)) catch unreachable;
    w.u8_(@intFromEnum(info.FileClass.standard)) catch unreachable;
    w.u32_(4096) catch unreachable;
    w.u16_(0) catch unreachable;
    w.u16_(0) catch unreachable;
    w.u32_(0) catch unreachable;
    w.u32_(0) catch unreachable;
    w.u32_(0) catch unreachable;
    w.blob(&([_]u8{0xFF} ** 16)) catch unreachable;
    w.alignTo(8) catch unreachable;
    w.patchInt(u32, second_at + 20, @intCast(w.pos - second_at)) catch unreachable;

    // Request 3: CLOSE, same trick.
    c.client.message_id += 1;
    hdr.write(&w, .{
        .command = .close,
        .credits = 64,
        .flags = hdr.flags.RELATED_OPERATIONS,
        .message_id = c.client.message_id,
    }) catch unreachable;
    w.u16_(24) catch unreachable;
    w.u16_(0) catch unreachable;
    w.u32_(0) catch unreachable;
    w.blob(&([_]u8{0xFF} ** 16)) catch unreachable;

    const responses = c.client.sendFrame(w.written());

    // Three chained responses, each pointing at the next.
    const first_next = std.mem.readInt(u32, responses[20..24], .little);
    try testing.expect(first_next > 0);
    try testing.expectEqual(status.SUCCESS, statusOf(responses));

    const second = responses[first_next..];
    const second_next = std.mem.readInt(u32, second[20..24], .little);
    try testing.expect(second_next > 0);
    try testing.expectEqual(status.SUCCESS, statusOf(second));
    // The QUERY_INFO answered about the file the CREATE opened.
    const at = std.mem.readInt(u16, bodyOf(second)[2..4], .little);
    try testing.expectEqual(@as(u64, 9), std.mem.readInt(u64, second[at + 8 ..][0..8], .little));

    const third = second[second_next..];
    try testing.expectEqual(status.SUCCESS, statusOf(third));
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, third[20..24], .little)); // last in the chain
}

test "a failed request in a chain fails the requests related to it" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);

    var frame: [1024]u8 = undefined;
    var w = wire.Writer.init(&frame);

    var create_body: [512]u8 = undefined;
    const create = Client.createBody(.{ .path = "does-not-exist.txt" }, &create_body);
    const first_at = w.pos;
    hdr.write(&w, .{ .command = .create, .credits = 64, .message_id = 100, .session_id = c.client.session_id, .tree_id = c.client.tree_id }) catch unreachable;
    w.blob(create) catch unreachable;
    w.alignTo(8) catch unreachable;
    w.patchInt(u32, first_at + 20, @intCast(w.pos - first_at)) catch unreachable;

    hdr.write(&w, .{ .command = .close, .credits = 64, .flags = hdr.flags.RELATED_OPERATIONS, .message_id = 101 }) catch unreachable;
    w.u16_(24) catch unreachable;
    w.u16_(0) catch unreachable;
    w.u32_(0) catch unreachable;
    w.blob(&([_]u8{0xFF} ** 16)) catch unreachable;

    const responses = c.client.sendFrame(w.written());
    try testing.expectEqual(status.OBJECT_NAME_NOT_FOUND, statusOf(responses));

    const next = std.mem.readInt(u32, responses[20..24], .little);
    try testing.expectEqual(status.OBJECT_NAME_NOT_FOUND, statusOf(responses[next..]));
}

test "signing: responses are signed and a tampered request is rejected" {
    const c = try setup(.{ .require_signing = true }, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    try testing.expectEqual(status.SUCCESS, c.client.login("alice", password, .raw, true));
    try testing.expect(c.client.sign_key != null);

    // Every response on a signed session carries a signature the client's key
    // reproduces.
    const response = c.client.send(.echo, &.{ 4, 0, 0, 0 });
    try testing.expectEqual(status.SUCCESS, statusOf(response));
    try testing.expect(std.mem.readInt(u32, response[16..20], .little) & hdr.flags.SIGNED != 0);
    var copy: [128]u8 = undefined;
    @memcpy(copy[0..response.len], response);
    try testing.expect(signing.verify(.hmac_sha256, c.client.sign_key.?, copy[0..response.len]));

    // A request signed with the wrong key is refused.
    const good = c.client.sign_key.?;
    c.client.sign_key = @splat(0xAA);
    try testing.expectEqual(status.ACCESS_DENIED, statusOf(c.client.send(.echo, &.{ 4, 0, 0, 0 })));

    // ...and so is an unsigned one, on a session that requires signing.
    c.client.sign_key = null;
    try testing.expectEqual(status.ACCESS_DENIED, statusOf(c.client.send(.echo, &.{ 4, 0, 0, 0 })));
    c.client.sign_key = good;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.send(.echo, &.{ 4, 0, 0, 0 })));
}

test "logoff ends the session and everything after it fails" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.send(.logoff, &.{ 4, 0, 0, 0 })));
    try testing.expectEqual(status.USER_SESSION_DELETED, c.client.treeConnect("data"));
}

test "unsupported commands are answered, not ignored" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    var body: [64]u8 = @splat(0);
    std.mem.writeInt(u16, body[0..2], 32, .little);
    try testing.expectEqual(status.NOT_SUPPORTED, statusOf(c.client.send(.ioctl, body[0..56])));
    try testing.expectEqual(status.NOT_SUPPORTED, statusOf(c.client.send(.change_notify, body[0..32])));
}

test "a connection that never authenticates is dropped, an authenticated one is not" {
    const c = try setup(.{ .handshake_timeout_ms = 1000 }, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();

    // Not yet due.
    c.conn.opened_at = 0;
    c.server.reapUnauthenticated(500);
    try testing.expect(c.conn.active);

    // Overdue: a client that connects and says nothing must not hold a slot.
    c.server.reapUnauthenticated(1500);
    try testing.expect(!c.conn.active);

    const live = try loggedIn("alice");
    defer live.destroy(testing.allocator);
    live.conn.opened_at = 0;
    live.server.reapUnauthenticated(1_000_000);
    try testing.expect(live.conn.active);
}

test "the connection table's bookkeeping survives clients coming and going" {
    // Four slots, so the accounting that decides which ones are free and how
    // many have yet to authenticate has something to get wrong. Getting it
    // wrong is not a subtle failure: an undercount stops the handshake reaper
    // from ever running again, and an overcount takes the count below zero.
    const Multi = Server(.{
        .max_connections = 4,
        .sessions_per_connection = 2,
        .trees_per_session = 2,
        .opens_per_session = 4,
        .max_shares = 1,
        .in_buffer = 16 * 1024,
        .out_buffer = 16 * 1024,
        .max_read = 4096,
        .max_write = 4096,
        .max_transact = 4096,
        .path_bytes = 128,
        .search_pattern_bytes = 32,
    });
    const MultiClient = loopback.LoopbackClient(Multi);

    const server = try testing.allocator.create(Multi);
    defer testing.allocator.destroy(server);
    const fs = try testing.allocator.create(TestFs);
    defer testing.allocator.destroy(fs);
    const accounts = try testing.allocator.create(Accounts);
    defer testing.allocator.destroy(accounts);
    const scratch = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(scratch);

    try accounts.parse("alice:" ++ password);
    fs.init();
    server.init(.{ .handshake_timeout_ms = 1000 }, accounts.authenticator());
    try server.addShare(fs.share("data"));
    defer server.deinit();

    var clients: [4]MultiClient = undefined;
    for (&clients, 0..) |*client, i| {
        client.* = MultiClient.init(server, i, scratch);
        client.conn.opened_at = 0; // as if they all arrived at time zero
        _ = client.negotiate();
    }
    // One of them gets as far as a session; the other three never will.
    try testing.expectEqual(status.SUCCESS, clients[1].login("alice", password, .raw, false));

    server.reapUnauthenticated(2000);
    try testing.expect(!clients[0].conn.active);
    try testing.expect(clients[1].conn.active);
    try testing.expect(!clients[2].conn.active);
    try testing.expect(!clients[3].conn.active);

    // Reaping again must be a no-op rather than an underflow, and the freed
    // slots must be usable by the next client to arrive.
    server.reapUnauthenticated(9999);
    clients[2] = MultiClient.init(server, 2, scratch);
    clients[2].conn.opened_at = 9999;
    _ = clients[2].negotiate();
    try testing.expect(clients[2].conn.active);
    try testing.expectEqual(status.SUCCESS, clients[2].login("alice", password, .raw, false));

    // And the one that authenticated long ago is still not a candidate.
    server.reapUnauthenticated(1_000_000);
    try testing.expect(clients[1].conn.active);
    try testing.expect(clients[2].conn.active);
}

test "restarting authentication reuses the session slot instead of burning another" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();

    var negotiate_msg: [40]u8 = @splat(0);
    @memcpy(negotiate_msg[0..8], ntlm.signature);
    std.mem.writeInt(u32, negotiate_msg[8..12], 1, .little);
    std.mem.writeInt(u32, negotiate_msg[12..16], ntlm.flags.UNICODE | ntlm.flags.NTLM, .little);

    var body: [512]u8 = undefined;
    // First attempt: allocates a session.
    const first = c.client.send(.session_setup, Client.sessionSetupBody(&negotiate_msg, &body, false));
    try testing.expectEqual(status.MORE_PROCESSING_REQUIRED, statusOf(first));
    c.client.session_id = std.mem.readInt(u64, first[40..48], .little);
    try testing.expect(c.conn.sessions[0].active);

    // Restarting the exchange four times over must not exhaust a table of two.
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const again = c.client.send(.session_setup, Client.sessionSetupBody(&negotiate_msg, &body, false));
        try testing.expectEqual(status.MORE_PROCESSING_REQUIRED, statusOf(again));
        c.client.session_id = std.mem.readInt(u64, again[40..48], .little);
    }
    try testing.expect(!c.conn.sessions[1].active);

    // And the reused slot still completes a real logon.
    c.client.session_id = 0;
    try testing.expectEqual(status.SUCCESS, c.client.login("alice", password, .raw, false));
}

test "a request is granted at least the credits it charged" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);

    // A 1 MiB read charges 16 credits. Granting fewer than a request spent
    // shrinks the client's window until it stops sending altogether.
    var message: [128]u8 = undefined;
    var w = wire.Writer.init(&message);
    try hdr.write(&w, .{
        .command = .echo,
        .credit_charge = 16,
        .credits = 1,
        .message_id = 500,
        .session_id = c.client.session_id,
        .tree_id = c.client.tree_id,
    });
    try w.blob(&.{ 4, 0, 0, 0 });

    const response = c.client.sendFrame(w.written());
    try testing.expectEqual(status.SUCCESS, statusOf(response));
    try testing.expect(std.mem.readInt(u16, response[14..16], .little) >= 16);
}

test "a write-only handle cannot read" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    // FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, no read bits at all.
    try testing.expectEqual(status.SUCCESS, c.client.open(.{
        .path = "notes.txt",
        .access_mask = 0x0000_0102,
    }));
    try testing.expectEqual(status.ACCESS_DENIED, statusOf(c.client.readFile(0, 16)));
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "ok")));
}

test "a zero-length read succeeds instead of reporting the end of the file" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt" }));

    const response = c.client.readFile(0, 0);
    try testing.expectEqual(status.SUCCESS, statusOf(response));
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, bodyOf(response)[4..8], .little));

    // Reading past the end is still the end of the file.
    try testing.expectEqual(status.END_OF_FILE, statusOf(c.client.readFile(9999, 16)));
}

test "a handle cannot be used through another tree connect" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt" }));
    const handle = c.client.file_id;

    // A second tree connect to the same share is a different tree id.
    const first_tree = c.client.tree_id;
    try testing.expectEqual(status.SUCCESS, c.client.treeConnect("data"));
    try testing.expect(c.client.tree_id != first_tree);

    c.client.file_id = handle;
    try testing.expectEqual(status.FILE_CLOSED, statusOf(c.client.readFile(0, 16)));

    c.client.tree_id = first_tree;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.readFile(0, 16)));
}

test "two shares cannot answer to the same name" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    try testing.expectError(error.DuplicateShareName, c.server.addShare(c.fs.share("DATA")));
    try testing.expectError(error.InvalidShareName, c.server.addShare(c.fs.share("")));
}

test "a FileId from a closed handle is refused even once its slot is reused" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);

    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt" }));
    const stale = c.client.file_id;
    _ = c.client.closeFile();

    // The next open lands in the same slot; the generation in the id is what
    // stops the stale handle from reaching the new file.
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "docs" }));
    try testing.expect(!std.mem.eql(u8, &stale, &c.client.file_id));

    const fresh = c.client.file_id;
    c.client.file_id = stale;
    try testing.expectEqual(status.FILE_CLOSED, statusOf(c.client.readFile(0, 16)));
    try testing.expectEqual(status.FILE_CLOSED, statusOf(c.client.closeFile()));
    c.client.file_id = fresh;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.closeFile()));
}

test "backpressure: a full output buffer pauses requests and draining resumes them" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try c.fs.put("read.bin", &[_]u8{0xAB} ** 4096);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "read.bin" }));

    // Twenty pipelined 4 KiB reads. Each answer is ~4.2 KiB and the output
    // buffer is 64 KiB, so they cannot all be answered in one go — which is the
    // situation a client with plenty of credits creates as a matter of course.
    var frame: [8192]u8 = undefined;
    var w = wire.Writer.init(&frame);
    var i: u64 = 0;
    while (i < 20) : (i += 1) {
        var body: [64]u8 = undefined;
        var b = wire.Writer.init(&body);
        try b.u16_(49);
        try b.u8_(0);
        try b.u8_(0);
        try b.u32_(4096); // Length
        try b.u64_(0); // Offset
        try b.blob(&c.client.file_id);
        try b.u32_(0);
        try b.u32_(0);
        try b.u32_(0);
        try b.u16_(0);
        try b.u16_(0);
        try b.u8_(0);

        var message: [128]u8 = undefined;
        var m = wire.Writer.init(&message);
        try hdr.write(&m, .{
            .command = .read,
            .credits = 64,
            .message_id = 1000 + i,
            .session_id = c.client.session_id,
            .tree_id = c.client.tree_id,
        });
        try m.blob(b.written());

        var length: [4]u8 = undefined;
        hdr.writeFrameLength(&length, @intCast(m.pos));
        try w.blob(&length);
        try w.blob(m.written());
    }

    c.conn.out_len = 0;
    const accepted = c.server.feed(c.conn, w.written());
    try testing.expectEqual(w.pos, accepted);

    // Some answers, and requests left over: the connection is paused, not lost.
    const first_round = countResponses(c.conn.out[0..c.conn.out_len]);
    try testing.expect(first_round > 0);
    try testing.expect(first_round < 20);
    try testing.expect(c.conn.in_len > 0);

    // Drain the output the way a writable socket would, then resume. Without
    // that resume the leftover requests are never answered and the client waits
    // for responses that are not coming.
    var answered = first_round;
    var rounds: usize = 0;
    while (c.conn.in_len > 0 and rounds < 10) : (rounds += 1) {
        c.conn.out_len = 0;
        c.conn.out_sent = 0;
        _ = c.server.feed(c.conn, &.{});
        answered += countResponses(c.conn.out[0..c.conn.out_len]);
    }
    try testing.expectEqual(@as(usize, 20), answered);
    try testing.expectEqual(@as(usize, 0), c.conn.in_len);
}

/// Counts the messages in however many transport frames `out` holds.
fn countResponses(out: []const u8) usize {
    var count: usize = 0;
    var pos: usize = 0;
    while (pos + hdr.transport_header_size <= out.len) {
        const length = (hdr.frameLength(out[pos..]) catch break) orelse break;
        const frame = out[pos + hdr.transport_header_size ..][0..length];
        var at: usize = 0;
        while (at + hdr.header_size <= frame.len) {
            count += 1;
            const next = std.mem.readInt(u32, frame[at + 20 ..][0..4], .little);
            if (next == 0) break;
            at += next;
        }
        pos += hdr.transport_header_size + length;
    }
    return count;
}

test "cancel is the one request with no reply" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const response = c.client.send(.cancel, &.{ 4, 0, 0, 0 });
    try testing.expectEqual(@as(usize, 0), response.len);
}

/// FILE_GENERIC_READ plus the write bits: what a client that intends to lock
/// and then change a range asks for.
const read_write: u32 = 0x0012_0089 | 0x0000_0116;

const unlock = loopback.lock_flags.unlock;
const shared = loopback.lock_flags.shared;

/// Opens the same file twice and hands back both handles, which is the only
/// interesting case for locking: a lock exists to be seen by someone else.
fn twoHandles(c: *Harness) ![2][16]u8 {
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));
    const first = c.client.file_id;
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));
    return .{ first, c.client.file_id };
}

test "an exclusive lock keeps every other handle out of the range" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const handles = try twoHandles(c);
    const holder, const other = handles;

    c.client.file_id = holder;
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{.{ .offset = 0, .length = 4 }}));

    // Whoever holds the lock is not blocked by it; that is what it was for.
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.readFile(0, 4)));
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "held")));

    c.client.file_id = other;
    try testing.expectEqual(status.FILE_LOCK_CONFLICT, statusOf(c.client.readFile(0, 4)));
    try testing.expectEqual(status.FILE_LOCK_CONFLICT, statusOf(c.client.writeFile(2, "xx")));
    // The rest of the file is nobody's business but its own.
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(4, "yy")));

    c.client.file_id = holder;
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{.{ .offset = 0, .length = 4, .flags = unlock }}));
    c.client.file_id = other;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.readFile(0, 4)));
}

test "a shared lock lets other readers through and keeps writers out" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const handles = try twoHandles(c);
    const holder, const other = handles;

    c.client.file_id = holder;
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{.{ .offset = 0, .length = 4, .flags = shared }}));

    c.client.file_id = other;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.readFile(0, 4)));
    try testing.expectEqual(status.FILE_LOCK_CONFLICT, statusOf(c.client.writeFile(0, "no")));
    // A second reader may share it; an exclusive claim may not.
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{.{ .offset = 0, .length = 4, .flags = shared }}));
    try testing.expectEqual(status.LOCK_NOT_GRANTED, c.client.lock(&.{.{ .offset = 2, .length = 4 }}));
}

test "a lock request that cannot be granted in full takes none of it" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const handles = try twoHandles(c);
    const holder, const other = handles;

    c.client.file_id = holder;
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{.{ .offset = 0, .length = 4 }}));

    // The second range collides; the first must not survive the refusal.
    c.client.file_id = other;
    try testing.expectEqual(status.LOCK_NOT_GRANTED, c.client.lock(&.{
        .{ .offset = 8, .length = 4 },
        .{ .offset = 0, .length = 4 },
    }));

    c.client.file_id = holder;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(8, "z")));
    try testing.expectEqual(@as(usize, 1), c.server.lock_count);
}

test "unlocking a range nobody holds is refused" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));

    try testing.expectEqual(status.RANGE_NOT_LOCKED, c.client.lock(&.{.{ .offset = 0, .length = 4, .flags = unlock }}));
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{.{ .offset = 0, .length = 4 }}));
    // The range has to match the one that was taken, not merely overlap it.
    try testing.expectEqual(status.RANGE_NOT_LOCKED, c.client.lock(&.{.{ .offset = 0, .length = 2, .flags = unlock }}));
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{.{ .offset = 0, .length = 4, .flags = unlock }}));
    try testing.expectEqual(@as(usize, 0), c.server.lock_count);
}

test "locks go when the handle that took them goes" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const handles = try twoHandles(c);
    const holder, const other = handles;

    c.client.file_id = holder;
    try testing.expectEqual(status.SUCCESS, c.client.lock(&.{
        .{ .offset = 0, .length = 4 },
        .{ .offset = 16, .length = 4 },
    }));
    try testing.expectEqual(@as(usize, 2), c.server.lock_count);

    _ = c.client.closeFile();
    try testing.expectEqual(@as(usize, 0), c.server.lock_count);

    c.client.file_id = other;
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "free")));
}

test "a lock on a directory, or on nothing at all, is refused" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "docs", .options = 0x0000_0001 }));
    try testing.expectEqual(status.INVALID_DEVICE_REQUEST, c.client.lock(&.{.{ .offset = 0, .length = 4 }}));

    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));
    try testing.expectEqual(status.INVALID_PARAMETER, c.client.lock(&.{}));
    // Neither shared nor exclusive nor unlock: nothing to do and no way to say so.
    try testing.expectEqual(status.INVALID_PARAMETER, c.client.lock(&.{.{ .offset = 0, .length = 4, .flags = 0 }}));
}

/// Offsets into a CREATE response body: OplockLevel, then the two fields that
/// say where the answered create contexts are.
const create_oplock_at = 2;
const create_contexts_offset_at = 80;
const create_contexts_length_at = 84;

fn createWithLease(c: *Harness, path: []const u8, key: [16]u8, mask: u32) []const u8 {
    var buf: [512]u8 = undefined;
    const response = c.client.send(.create, Client.createBody(.{
        .path = path,
        .access_mask = mask,
        .lease_key = key,
    }, &buf));
    if (statusOf(response) == status.SUCCESS) @memcpy(&c.client.file_id, response[64 + 64 ..][0..16]);
    return response;
}

test "a lease request is answered with read caching under the client's own key" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const key: [16]u8 = @splat(0xA5);

    const response = createWithLease(c, "notes.txt", key, 0x0012_0089);
    try testing.expectEqual(status.SUCCESS, statusOf(response));

    const body = bodyOf(response);
    try testing.expectEqual(@as(u8, 0xFF), body[create_oplock_at]); // SMB2_OPLOCK_LEVEL_LEASE
    const contexts_at = std.mem.readInt(u32, body[create_contexts_offset_at..][0..4], .little);
    const contexts_len = std.mem.readInt(u32, body[create_contexts_length_at..][0..4], .little);
    try testing.expectEqual(@as(u32, 56), contexts_len);

    // Offsets in a response are measured from the start of the message.
    const context = response[contexts_at..][0..contexts_len];
    try testing.expectEqualStrings("RqLs", context[16..20]);
    try testing.expectEqualSlices(u8, &key, context[24..40]);
    // Read caching, and nothing else, whatever the client asked for.
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, context[40..44], .little));
    try testing.expectEqual(@as(usize, 1), c.server.grant_count);
}

test "a write from somebody else breaks the lease" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const key: [16]u8 = @splat(0x11);

    try testing.expectEqual(status.SUCCESS, statusOf(createWithLease(c, "notes.txt", key, 0x0012_0089)));
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));

    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "changed")));
    const notification = c.client.breakNotification() orelse return error.NoBreakSent;
    const body = bodyOf(notification);
    try testing.expectEqual(@as(u16, 44), std.mem.readInt(u16, body[0..2], .little));
    try testing.expectEqualSlices(u8, &key, body[8..24]);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, body[24..28], .little)); // was read caching
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, body[28..32], .little)); // and now nothing

    // The grant is gone with it, so a second write has nothing left to break.
    try testing.expectEqual(@as(usize, 0), c.server.grant_count);
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "again")));
    try testing.expect(c.client.breakNotification() == null);
}

test "a client writing through its own lease key is not broken by itself" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const key: [16]u8 = @splat(0x22);

    try testing.expectEqual(status.SUCCESS, statusOf(createWithLease(c, "notes.txt", key, 0x0012_0089)));
    // The same client, the same lease, a second handle: one client, not two.
    try testing.expectEqual(status.SUCCESS, statusOf(createWithLease(c, "notes.txt", key, read_write)));

    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "mine")));
    try testing.expect(c.client.breakNotification() == null);
    try testing.expectEqual(@as(usize, 2), c.server.grant_count);
}

test "a client that asks for an oplock rather than a lease gets level II" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);

    var buf: [512]u8 = undefined;
    // FILE_OPEN_BATCH_OPLOCK: more than this server will ever hand out.
    const response = c.client.send(.create, Client.createBody(.{
        .path = "notes.txt",
        .oplock = 0x09,
    }, &buf));
    try testing.expectEqual(status.SUCCESS, statusOf(response));
    try testing.expectEqual(@as(u8, 0x01), bodyOf(response)[create_oplock_at]);
    @memcpy(&c.client.file_id, response[64 + 64 ..][0..16]);
    const holder = c.client.file_id;

    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "changed")));

    const notification = c.client.breakNotification() orelse return error.NoBreakSent;
    const body = bodyOf(notification);
    try testing.expectEqual(@as(u16, 24), std.mem.readInt(u16, body[0..2], .little));
    try testing.expectEqual(@as(u8, 0), body[2]); // nothing left
    try testing.expectEqualSlices(u8, holder[0..8], body[8..16]);
}

test "truncating and renaming break a lease the same way writing does" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const key: [16]u8 = @splat(0x33);

    try testing.expectEqual(status.SUCCESS, statusOf(createWithLease(c, "notes.txt", key, 0x0012_0089)));
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));

    var payload: [8]u8 = @splat(0);
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.setInfo(.end_of_file, &payload)));
    try testing.expect(c.client.breakNotification() != null);

    // And again for a rename, which changes the name two clients disagree about.
    try testing.expectEqual(status.SUCCESS, statusOf(createWithLease(c, "notes.txt", key, 0x0012_0089)));
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write | 0x0001_0000 }));
    var rename_buf: [64]u8 = undefined;
    var w = wire.Writer.init(&rename_buf);
    try w.u8_(1); // ReplaceIfExists
    try w.zeroes(7);
    try w.u64_(0); // RootDirectory
    var name_buf: [32]u8 = undefined;
    const name = try unicode.toUtf16le(&name_buf, "moved.txt");
    try w.u32_(@intCast(name.len));
    try w.blob(name);
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.setInfo(.rename, w.written())));
    try testing.expect(c.client.breakNotification() != null);
}

test "a lease goes when the handle that held it closes" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const key: [16]u8 = @splat(0x44);

    try testing.expectEqual(status.SUCCESS, statusOf(createWithLease(c, "notes.txt", key, 0x0012_0089)));
    try testing.expectEqual(@as(usize, 1), c.server.grant_count);
    _ = c.client.closeFile();
    try testing.expectEqual(@as(usize, 0), c.server.grant_count);

    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "nobody is caching this")));
    try testing.expect(c.client.breakNotification() == null);
}

test "a directory is never leased" {
    const c = try loggedIn("alice");
    defer c.destroy(testing.allocator);
    const key: [16]u8 = @splat(0x55);

    var buf: [512]u8 = undefined;
    const response = c.client.send(.create, Client.createBody(.{
        .path = "docs",
        .options = 0x0000_0001, // FILE_DIRECTORY_FILE
        .lease_key = key,
    }, &buf));
    try testing.expectEqual(status.SUCCESS, statusOf(response));
    try testing.expectEqual(@as(u8, 0), bodyOf(response)[create_oplock_at]);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, bodyOf(response)[create_contexts_length_at..][0..4], .little));
    try testing.expectEqual(@as(usize, 0), c.server.grant_count);
}

test "a break on a signed session is signed" {
    const c = try setup(.{}, "alice:" ++ password);
    defer c.destroy(testing.allocator);
    _ = c.client.negotiate();
    try testing.expectEqual(status.SUCCESS, c.client.login("alice", password, .raw, true));
    try testing.expectEqual(status.SUCCESS, c.client.treeConnect("data"));
    const key: [16]u8 = @splat(0x66);

    try testing.expectEqual(status.SUCCESS, statusOf(createWithLease(c, "notes.txt", key, 0x0012_0089)));
    try testing.expectEqual(status.SUCCESS, c.client.open(.{ .path = "notes.txt", .access_mask = read_write }));
    try testing.expectEqual(status.SUCCESS, statusOf(c.client.writeFile(0, "changed")));

    const notification = c.client.breakNotification() orelse return error.NoBreakSent;
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..notification.len], notification);
    try testing.expect(signing.verify(.hmac_sha256, c.client.sign_key.?, copy[0..notification.len]));
}
