//! Every frame in this file is wrong on purpose.
//!
//! A file server answers whatever arrives on port 445, from clients that
//! disagree with it about the protocol and from people who are not clients at
//! all. The rule the tests below hold it to is narrow and absolute: no input
//! makes the daemon stop. A malformed request is answered with an error, or
//! costs the sender its connection, and either way the next client is served.
//!
//! Zig checks bounds, overflow and every other undefined behaviour in the
//! builds this ships as, so a slip is a panic, and a panic in a single-threaded
//! server is every client's problem. These run the real handlers against real
//! state, so a panic here is a crash there.

const std = @import("std");
const testing = std.testing;

const hdr = @import("../smb/header.zig");
const log = @import("../log.zig");
const status = @import("../smb/status.zig");
const info = @import("../smb/info.zig");
const Authenticator = @import("../auth/Authenticator.zig");
const MemFs = @import("../vfs/MemFs.zig").MemFs;
const server_mod = @import("Server.zig");
const Server = server_mod.Server;
const loopback = @import("LoopbackClient.zig");
const statusOf = loopback.statusOf;

const FuzzServer = Server(.{
    .max_connections = 2,
    .sessions_per_connection = 2,
    .trees_per_session = 4,
    .opens_per_session = 8,
    .max_shares = 2,
    .in_buffer = 16 * 1024,
    .out_buffer = 16 * 1024,
    .max_read = 8 * 1024,
    .max_write = 8 * 1024,
    .max_transact = 8 * 1024,
    .path_bytes = 128,
    .search_pattern_bytes = 32,
});
const FuzzFs = MemFs(.{ .max_nodes = 8, .max_file_bytes = 2048, .max_path = 64 });
const Accounts = Authenticator.UserTable(2, 32);
const Client = loopback.LoopbackClient(FuzzServer);

const password = "hunter2";

/// How many rounds each mutation test runs, scaled by `-Dfuzz-rounds`. The
/// default keeps a plain `zig build test` under a second; CI turns it up.
fn rounds(comptime share: f32) usize {
    const configured: f32 = @floatFromInt(@import("build_options").fuzz_rounds);
    return @intFromFloat(@max(1, configured * share));
}

const Harness = struct {
    server: *FuzzServer,
    fs: *FuzzFs,
    accounts: *Accounts,
    scratch: []u8,
    client: Client,
    log_level: log.Level,

    fn create(allocator: std.mem.Allocator) !*Harness {
        const h = try allocator.create(Harness);
        h.* = .{
            .server = try allocator.create(FuzzServer),
            .fs = try allocator.create(FuzzFs),
            .accounts = try allocator.create(Accounts),
            .scratch = try allocator.alloc(u8, 16 * 1024),
            .client = undefined,
            .log_level = log.level,
        };
        // Hundreds of thousands of refusals, one line each, would bury every
        // other test's output. The lines themselves are still built: the
        // arguments to a log call are evaluated before the level is checked,
        // which is exactly how the first crash these tests found got in.
        log.level = .err;
        try h.accounts.parse("alice:" ++ password);
        h.fs.init();
        h.server.init(.{}, h.accounts.authenticator());
        try h.server.addShare(h.fs.share("data"));
        try h.fs.put("notes.txt", "hello smb");
        try h.fs.mkdir("docs");
        h.client = Client.init(h.server, 0, h.scratch);
        return h;
    }

    fn destroy(h: *Harness, allocator: std.mem.Allocator) void {
        log.level = h.log_level;
        allocator.free(h.scratch);
        allocator.destroy(h.accounts);
        allocator.destroy(h.fs);
        allocator.destroy(h.server);
        allocator.destroy(h);
    }

    /// A fresh connection in the second slot, logged in and holding a handle,
    /// used to prove the server still works after being fed nonsense.
    fn stillServes(h: *Harness) !void {
        var scratch: [8 * 1024]u8 = undefined;
        var client = Client.init(h.server, 1, &scratch);
        _ = client.negotiate();
        try testing.expectEqual(status.SUCCESS, client.login("alice", password, .raw, false));
        try testing.expectEqual(status.SUCCESS, client.treeConnect("data"));
        try testing.expectEqual(status.SUCCESS, client.open(.{ .path = "notes.txt" }));
        const read = client.readFile(0, 9);
        try testing.expectEqual(status.SUCCESS, statusOf(read));
        _ = client.closeFile();
        h.server.closeConn(client.conn);
    }

    /// Hands one message straight to the frame handler, the way a socket read
    /// that produced a complete frame does. Whatever it answers is thrown
    /// away: what is being tested is that it comes back at all.
    fn poke(h: *Harness, message: []const u8) void {
        h.client.conn.out_len = 0;
        h.server.handleFrame(h.client.conn, message);
    }
};

/// Builds the frames a working session produces, so the mutation tests have
/// something real to break. Each entry is a complete message without its
/// transport header.
const Corpus = struct {
    storage: [32][512]u8 = undefined,
    lengths: [32]usize = @splat(0),
    count: usize = 0,

    /// Keeps whatever the client last sent.
    fn take(corpus: *Corpus, client: *const Client) void {
        const message = client.lastRequest();
        if (corpus.count == corpus.storage.len or message.len > corpus.storage[0].len) return;
        @memcpy(corpus.storage[corpus.count][0..message.len], message);
        corpus.lengths[corpus.count] = message.len;
        corpus.count += 1;
    }

    fn at(corpus: *const Corpus, index: usize) []const u8 {
        return corpus.storage[index][0..corpus.lengths[index]];
    }
};

fn record(h: *Harness) !Corpus {
    var corpus = Corpus{};
    const client = &h.client;

    // Every request below is one a working client sends, recorded as it goes
    // out. Mutating a real request reaches further into a handler than a
    // hand-built one does: the offsets and lengths it contains are consistent
    // until the mutation makes one of them a lie.
    _ = client.negotiate();
    corpus.take(client);
    try testing.expectEqual(status.SUCCESS, client.login("alice", password, .raw, false));
    corpus.take(client);
    try testing.expectEqual(status.SUCCESS, client.treeConnect("data"));
    corpus.take(client);

    try testing.expectEqual(status.SUCCESS, client.open(.{ .path = "notes.txt", .access_mask = 0x0012_019F }));
    corpus.take(client);
    _ = client.readFile(0, 9);
    corpus.take(client);
    _ = client.writeFile(0, "changed!!");
    corpus.take(client);
    _ = client.queryInfo(.file, @intFromEnum(info.FileClass.all));
    corpus.take(client);
    _ = client.queryInfo(.filesystem, @intFromEnum(info.FsClass.size));
    corpus.take(client);
    var basic: [40]u8 = @splat(0);
    _ = client.setInfo(.basic, &basic);
    corpus.take(client);
    _ = client.lock(&.{.{ .offset = 0, .length = 4, .flags = loopback.lock_flags.exclusive | loopback.lock_flags.fail_immediately }});
    corpus.take(client);
    _ = client.ioctl(0x0014_0078, &.{}); // FSCTL_SRV_REQUEST_RESUME_KEY
    corpus.take(client);
    _ = client.echo();
    corpus.take(client);
    _ = client.closeFile();
    corpus.take(client);

    try testing.expectEqual(status.SUCCESS, client.open(.{ .path = "docs", .options = 0x0000_0001 }));
    corpus.take(client);
    _ = client.queryDirectory(.both_directory, "*", 0);
    corpus.take(client);
    _ = client.changeNotify(0x0000_0001, 1024, false);
    corpus.take(client);
    client.cancel(0);
    corpus.take(client);
    _ = client.closeFile();
    corpus.take(client);

    // A corpus that quietly came up short would make every test below pass
    // without testing anything.
    try testing.expectEqual(@as(usize, 18), corpus.count);
    return corpus;
}

test "random bytes are answered, not fatal" {
    const h = try Harness.create(testing.allocator);
    defer h.destroy(testing.allocator);
    _ = try record(h);

    var prng = std.Random.DefaultPrng.init(0x5EED);
    const random = prng.random();
    var noise: [1024]u8 = undefined;

    var round: usize = 0;
    while (round < rounds(1.0)) : (round += 1) {
        const length = random.uintLessThan(usize, noise.len);
        random.bytes(noise[0..length]);
        // Half the rounds carry a valid protocol id, so the dispatcher gets
        // past the first check and the handlers see the garbage too.
        if (round % 2 == 0 and length >= 4) @memcpy(noise[0..4], &hdr.protocol_id);
        h.poke(noise[0..length]);
    }

    try h.stillServes();
}

test "one flipped byte in a real request is never fatal" {
    const h = try Harness.create(testing.allocator);
    defer h.destroy(testing.allocator);
    const corpus = try record(h);

    var prng = std.Random.DefaultPrng.init(0xB17F11);
    const random = prng.random();
    var frame: [512]u8 = undefined;

    var round: usize = 0;
    while (round < rounds(2.0)) : (round += 1) {
        const original = corpus.at(random.uintLessThan(usize, corpus.count));
        @memcpy(frame[0..original.len], original);

        const flips = 1 + random.uintLessThan(usize, 4);
        var i: usize = 0;
        while (i < flips) : (i += 1) {
            const at = random.uintLessThan(usize, original.len);
            frame[at] = switch (random.uintLessThan(u8, 4)) {
                // Values that are wrong in the ways that matter: an offset or
                // length past the end of the message, a count of zero, a bit
                // in a field that only has two legal values.
                0 => 0xFF,
                1 => 0x00,
                2 => random.int(u8),
                else => frame[at] ^ (@as(u8, 1) << random.int(u3)),
            };
        }
        h.poke(frame[0..original.len]);
    }

    try h.stillServes();
}

test "a request that stops in the middle is never fatal" {
    const h = try Harness.create(testing.allocator);
    defer h.destroy(testing.allocator);
    const corpus = try record(h);

    var index: usize = 0;
    while (index < corpus.count) : (index += 1) {
        const original = corpus.at(index);
        var cut: usize = 0;
        while (cut <= original.len) : (cut += 1) h.poke(original[0..cut]);
    }

    try h.stillServes();
}

test "compound chains of nonsense are never fatal" {
    const h = try Harness.create(testing.allocator);
    defer h.destroy(testing.allocator);
    const corpus = try record(h);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const random = prng.random();
    var chain: [4096]u8 = undefined;

    var round: usize = 0;
    while (round < rounds(0.5)) : (round += 1) {
        var at: usize = 0;
        const links = 1 + random.uintLessThan(usize, 6);
        var i: usize = 0;
        while (i < links) : (i += 1) {
            const original = corpus.at(random.uintLessThan(usize, corpus.count));
            if (at + original.len > chain.len) break;
            @memcpy(chain[at..][0..original.len], original);
            // NextCommand: where the next request in the chain starts. A
            // client that lies about it is the whole point of this test.
            const next: u32 = switch (random.uintLessThan(u8, 4)) {
                0 => @intCast(original.len), // truthful
                1 => 0, // end of chain, with more bytes behind it
                2 => random.int(u16), // past the end, or into the middle
                else => 0xFFFF_FFFF,
            };
            std.mem.writeInt(u32, chain[at..][20..24], next, .little);
            at += original.len;
        }
        h.poke(chain[0..at]);
    }

    try h.stillServes();
}

test "the transport framer survives lengths that lie" {
    const h = try Harness.create(testing.allocator);
    defer h.destroy(testing.allocator);
    const corpus = try record(h);

    var prng = std.Random.DefaultPrng.init(0xFEED);
    const random = prng.random();
    var stream: [8192]u8 = undefined;

    var round: usize = 0;
    while (round < rounds(0.25)) : (round += 1) {
        const conn = h.server.adopt(1);
        var at: usize = 0;
        const chunks = 1 + random.uintLessThan(usize, 4);
        var i: usize = 0;
        while (i < chunks) : (i += 1) {
            const original = corpus.at(random.uintLessThan(usize, corpus.count));
            if (at + hdr.transport_header_size + original.len > stream.len) break;
            const claimed: u32 = switch (random.uintLessThan(u8, 5)) {
                0 => @intCast(original.len),
                1 => 0,
                2 => random.int(u24),
                3 => 0x00FF_FFFF,
                else => @intCast(original.len + random.uintLessThan(usize, 64)),
            };
            hdr.writeFrameLength(stream[at..][0..hdr.transport_header_size], claimed);
            at += hdr.transport_header_size;
            @memcpy(stream[at..][0..original.len], original);
            at += original.len;
        }
        // Fed in ragged pieces, because a socket does not deliver whole frames.
        var offset: usize = 0;
        while (offset < at) {
            const piece = @min(at - offset, 1 + random.uintLessThan(usize, 200));
            const accepted = h.server.feed(conn, stream[offset..][0..piece]);
            conn.out_len = 0;
            if (accepted == 0 or conn.closing) break;
            offset += accepted;
        }
        h.server.closeConn(conn);
    }

    try h.stillServes();
}

test "nonsense leaves no state behind" {
    const h = try Harness.create(testing.allocator);
    defer h.destroy(testing.allocator);
    const corpus = try record(h);

    var prng = std.Random.DefaultPrng.init(0xDEC0DE);
    const random = prng.random();
    var frame: [512]u8 = undefined;

    var round: usize = 0;
    while (round < rounds(1.0)) : (round += 1) {
        const original = corpus.at(random.uintLessThan(usize, corpus.count));
        @memcpy(frame[0..original.len], original);
        const at = random.uintLessThan(usize, original.len);
        frame[at] = random.int(u8);
        h.poke(frame[0..original.len]);
    }

    // Everything the server tracks across connections is per-handle, and the
    // handles go with the connection. A leak here would mean a client can fill
    // a table and never give it back, which is the cheapest denial of service
    // there is.
    h.server.closeConn(h.client.conn);
    try testing.expectEqual(@as(usize, 0), h.server.lock_count);
    try testing.expectEqual(@as(usize, 0), h.server.grant_count);
    try testing.expectEqual(@as(usize, 0), h.server.watch_count);
    try testing.expectEqual(@as(usize, 0), h.server.break_count);
    try testing.expectEqual(@as(usize, 0), h.server.unauthenticated);
}
