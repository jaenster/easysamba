//! An in-memory share adapter.
//!
//! It exists for two reasons: it is the fixture the protocol tests run against
//! without touching a disk, and it is the proof that `Share` is a real
//! interface — nothing in the SMB layer can tell it apart from a directory on
//! a filesystem, because there is nothing filesystem-shaped in the interface.
//!
//! Fixed capacity, no allocator: every node carries its own path and content
//! buffer, so a MemFs value is `max_nodes × (max_path + max_file_bytes)` and
//! belongs in a long-lived frame rather than in a stack temporary.

const std = @import("std");
const Share = @import("Share.zig");
const filetime = @import("../smb/time.zig");
const unicode = @import("../smb/unicode.zig");

pub const Options = struct {
    max_nodes: usize = 64,
    max_file_bytes: usize = 64 * 1024,
    max_path: usize = 256,
};

pub fn MemFs(comptime opts: Options) type {
    return struct {
        nodes: [opts.max_nodes]Node = @splat(.{}),
        /// Handed out as file_id so a client's cache keys stay unique even
        /// after a node index is recycled.
        next_id: u64 = 1,
        /// How many times a flush has been asked for. Nothing here needs one;
        /// it is how a test sees that one happened.
        flushes: usize = 0,

        const Self = @This();

        const Node = struct {
            used: bool = false,
            path: [opts.max_path]u8 = undefined,
            path_len: usize = 0,
            is_dir: bool = false,
            data: [opts.max_file_bytes]u8 = undefined,
            size: usize = 0,
            attributes: Share.Attributes = .{},
            created: u64 = 0,
            accessed: u64 = 0,
            modified: u64 = 0,
            id: u64 = 0,

            fn path_(n: *const Node) []const u8 {
                return n.path[0..n.path_len];
            }
        };

        pub fn init(s: *Self) void {
            for (&s.nodes) |*n| n.used = false;
            s.next_id = 1;
            s.flushes = 0;
        }

        pub fn share(s: *Self, name: []const u8) Share {
            return .{ .ctx = s, .vtable = &vtable, .name = name };
        }

        /// Test/seed helper: creates a file with `contents`, and every parent
        /// directory it needs.
        pub fn put(s: *Self, path: []const u8, contents: []const u8) !void {
            if (contents.len > opts.max_file_bytes) return error.NoSpace;
            try s.mkParents(path);
            const node = try s.ensure(path, false);
            @memcpy(node.data[0..contents.len], contents);
            node.size = contents.len;
            node.modified = filetime.now();
        }

        pub fn mkdir(s: *Self, path: []const u8) !void {
            try s.mkParents(path);
            _ = try s.ensure(path, true);
        }

        fn mkParents(s: *Self, path: []const u8) !void {
            var i: usize = 0;
            while (std.mem.indexOfScalarPos(u8, path, i, '/')) |slash| {
                _ = try s.ensure(path[0..slash], true);
                i = slash + 1;
            }
        }

        fn ensure(s: *Self, path: []const u8, is_dir: bool) !*Node {
            if (s.find(path)) |n| return n;
            if (path.len > opts.max_path) return error.NameTooLong;
            const node = s.freeNode() orelse return error.NoSpace;
            node.* = .{ .used = true, .is_dir = is_dir };
            @memcpy(node.path[0..path.len], path);
            node.path_len = path.len;
            node.attributes = .{ .directory = is_dir, .archive = !is_dir };
            node.created = filetime.now();
            node.modified = node.created;
            node.accessed = node.created;
            node.id = s.next_id;
            s.next_id += 1;
            return node;
        }

        fn freeNode(s: *Self) ?*Node {
            for (&s.nodes) |*n| {
                if (!n.used) return n;
            }
            return null;
        }

        fn find(s: *Self, path: []const u8) ?*Node {
            for (&s.nodes) |*n| {
                if (n.used and unicode.eqlIgnoreCase(n.path_(), path)) return n;
            }
            return null;
        }

        /// The root is not a stored node: it always exists and cannot be
        /// removed, which spares every caller a special case at creation time.
        const root_handle: Share.Handle = std.math.maxInt(u64);

        fn resolve(s: *Self, handle: Share.Handle) Share.Error!*Node {
            if (handle == root_handle) return error.IsDirectory;
            const index = handle - 1;
            if (index >= s.nodes.len) return error.NotFound;
            const node = &s.nodes[index];
            if (!node.used) return error.NotFound;
            return node;
        }

        fn handleOf(s: *Self, node: *Node) Share.Handle {
            return (@intFromPtr(node) - @intFromPtr(&s.nodes)) / @sizeOf(Node) + 1;
        }

        fn metaOf(node: *const Node) Share.Meta {
            return .{
                .size = node.size,
                .alloc_size = node.size,
                .attributes = node.attributes,
                .created = node.created,
                .accessed = node.accessed,
                .modified = node.modified,
                .changed = node.modified,
                .file_id = node.id,
            };
        }

        fn rootMeta() Share.Meta {
            return .{ .attributes = .{ .directory = true }, .file_id = 1 };
        }

        fn parentExists(s: *Self, path: []const u8) bool {
            const parent = unicode.dirName(path);
            if (parent.len == 0) return true;
            const node = s.find(parent) orelse return false;
            return node.is_dir;
        }

        const vtable: Share.VTable = .{
            .open = vOpen,
            .close = vClose,
            .stat = vStat,
            .read = vRead,
            .write = vWrite,
            .truncate = vTruncate,
            .flush = vFlush,
            .readDir = vReadDir,
            .setMeta = vSetMeta,
            .rename = vRename,
            .remove = vRemove,
            .statFs = vStatFs,
        };

        fn self(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }

        fn vOpen(ctx: *anyopaque, path: []const u8, o: Share.OpenOptions) Share.Error!Share.Opened {
            const s = self(ctx);
            if (path.len == 0) {
                if (o.directory == false) return error.IsDirectory;
                return .{ .handle = root_handle, .action = .opened, .meta = rootMeta() };
            }
            if (path.len > opts.max_path) return error.NameTooLong;

            if (s.find(path)) |node| {
                switch (o.disposition) {
                    .create => return error.Exists,
                    .open, .open_if, .overwrite, .overwrite_if, .supersede => {},
                }
                if (o.directory) |want_dir| {
                    if (want_dir and !node.is_dir) return error.NotDirectory;
                    if (!want_dir and node.is_dir) return error.IsDirectory;
                }
                var action: Share.Action = .opened;
                switch (o.disposition) {
                    .overwrite, .overwrite_if => {
                        if (node.is_dir) return error.IsDirectory;
                        node.size = 0;
                        action = .overwritten;
                    },
                    .supersede => {
                        if (node.is_dir) return error.IsDirectory;
                        node.size = 0;
                        action = .superseded;
                    },
                    else => {},
                }
                return .{ .handle = s.handleOf(node), .action = action, .meta = metaOf(node) };
            }

            switch (o.disposition) {
                .open, .overwrite => return error.NotFound,
                .create, .open_if, .overwrite_if, .supersede => {},
            }
            if (!s.parentExists(path)) return error.PathNotFound;
            const is_dir = o.directory orelse false;
            const node = s.ensure(path, is_dir) catch |err| return switch (err) {
                error.NameTooLong => error.NameTooLong,
                else => error.NoSpace,
            };
            node.attributes.read_only = o.attributes.read_only;
            node.attributes.hidden = o.attributes.hidden;
            return .{ .handle = s.handleOf(node), .action = .created, .meta = metaOf(node) };
        }

        fn vClose(ctx: *anyopaque, handle: Share.Handle) void {
            _ = ctx;
            _ = handle; // nothing to release: a handle is just a node index
        }

        fn vStat(ctx: *anyopaque, handle: Share.Handle) Share.Error!Share.Meta {
            if (handle == root_handle) return rootMeta();
            return metaOf(try self(ctx).resolve(handle));
        }

        fn vRead(ctx: *anyopaque, handle: Share.Handle, offset: u64, buf: []u8) Share.Error!usize {
            const node = try self(ctx).resolve(handle);
            if (node.is_dir) return error.IsDirectory;
            if (offset >= node.size) return 0;
            const n = @min(buf.len, node.size - offset);
            @memcpy(buf[0..n], node.data[@intCast(offset)..][0..n]);
            return n;
        }

        fn vWrite(ctx: *anyopaque, handle: Share.Handle, offset: u64, data: []const u8) Share.Error!usize {
            const node = try self(ctx).resolve(handle);
            if (node.is_dir) return error.IsDirectory;
            if (offset + data.len > opts.max_file_bytes) return error.NoSpace;
            const end: usize = @intCast(offset + data.len);
            // A write past the end leaves a hole; zero it rather than exposing
            // whatever the buffer happened to hold.
            if (offset > node.size) @memset(node.data[node.size..@intCast(offset)], 0);
            @memcpy(node.data[@intCast(offset)..][0..data.len], data);
            if (end > node.size) node.size = end;
            node.modified = filetime.now();
            return data.len;
        }

        fn vTruncate(ctx: *anyopaque, handle: Share.Handle, size: u64) Share.Error!void {
            const node = try self(ctx).resolve(handle);
            if (node.is_dir) return error.IsDirectory;
            if (size > opts.max_file_bytes) return error.NoSpace;
            const want: usize = @intCast(size);
            if (want > node.size) @memset(node.data[node.size..want], 0);
            node.size = want;
            node.modified = filetime.now();
        }

        fn vFlush(ctx: *anyopaque, handle: Share.Handle) Share.Error!void {
            _ = handle;
            // Nothing here outlives the process, so there is nothing to push
            // anywhere. The count is for tests that need to know a flush
            // happened at all.
            self(ctx).flushes += 1;
        }

        fn vReadDir(ctx: *anyopaque, handle: Share.Handle, cursor: *Share.Cursor, name_buf: []u8, out: *Share.DirEntry) Share.Error!bool {
            const s = self(ctx);
            const dir: []const u8 = if (handle == root_handle) "" else blk: {
                const node = try s.resolve(handle);
                if (!node.is_dir) return error.NotDirectory;
                break :blk node.path_();
            };

            while (cursor.index < s.nodes.len) {
                const node = &s.nodes[@intCast(cursor.index)];
                cursor.index += 1;
                if (!node.used) continue;
                if (!std.mem.eql(u8, unicode.dirName(node.path_()), dir)) continue;
                const name = unicode.baseName(node.path_());
                if (name.len > name_buf.len) return error.NameTooLong;
                @memcpy(name_buf[0..name.len], name);
                out.* = .{ .name = name_buf[0..name.len], .meta = metaOf(node) };
                return true;
            }
            return false;
        }

        fn vSetMeta(ctx: *anyopaque, handle: Share.Handle, changes: Share.MetaChanges) Share.Error!void {
            const node = try self(ctx).resolve(handle);
            if (changes.created) |v| node.created = v;
            if (changes.accessed) |v| node.accessed = v;
            if (changes.modified) |v| node.modified = v;
            if (changes.attributes) |a| {
                node.attributes.read_only = a.read_only;
                node.attributes.hidden = a.hidden;
                node.attributes.system = a.system;
                node.attributes.archive = a.archive;
            }
        }

        fn vRename(ctx: *anyopaque, handle: Share.Handle, new_path: []const u8, replace: bool) Share.Error!void {
            const s = self(ctx);
            const node = try s.resolve(handle);
            if (new_path.len == 0 or new_path.len > opts.max_path) return error.NameTooLong;
            if (s.find(new_path)) |existing| {
                if (!replace or existing == node) {
                    if (existing != node) return error.Exists;
                } else {
                    existing.used = false;
                }
            }
            if (!s.parentExists(new_path)) return error.PathNotFound;

            // Renaming a directory moves everything under it; without this a
            // subtree would silently detach from its parent.
            if (node.is_dir) {
                const old = node.path_();
                for (&s.nodes) |*other| {
                    if (!other.used or other == node) continue;
                    const p = other.path_();
                    if (p.len <= old.len or !std.mem.startsWith(u8, p, old) or p[old.len] != '/') continue;
                    const tail = p[old.len..];
                    if (new_path.len + tail.len > opts.max_path) return error.NameTooLong;
                    var moved: [opts.max_path]u8 = undefined;
                    @memcpy(moved[0..new_path.len], new_path);
                    @memcpy(moved[new_path.len..][0..tail.len], tail);
                    @memcpy(other.path[0 .. new_path.len + tail.len], moved[0 .. new_path.len + tail.len]);
                    other.path_len = new_path.len + tail.len;
                }
            }
            @memcpy(node.path[0..new_path.len], new_path);
            node.path_len = new_path.len;
        }

        fn vRemove(ctx: *anyopaque, handle: Share.Handle) Share.Error!void {
            const s = self(ctx);
            const node = try s.resolve(handle);
            if (node.is_dir) {
                const prefix = node.path_();
                for (&s.nodes) |*other| {
                    if (!other.used or other == node) continue;
                    const p = other.path_();
                    if (p.len > prefix.len and std.mem.startsWith(u8, p, prefix) and p[prefix.len] == '/') {
                        return error.NotEmpty;
                    }
                }
            }
            node.used = false;
        }

        fn vStatFs(ctx: *anyopaque) Share.Error!Share.FsInfo {
            const s = self(ctx);
            var used: u64 = 0;
            var free_nodes: u64 = 0;
            for (&s.nodes) |*n| {
                if (n.used) used += n.size else free_nodes += 1;
            }
            return .{
                .total_bytes = @as(u64, opts.max_nodes) * opts.max_file_bytes,
                .free_bytes = free_nodes * opts.max_file_bytes,
                .block_size = 4096,
                .label = "memfs",
                .serial = 0x4d454d46,
            };
        }
    };
}

const testing = std.testing;
const TestFs = MemFs(.{ .max_nodes = 16, .max_file_bytes = 4096, .max_path = 128 });

fn fixture(fs: *TestFs) !Share {
    fs.init();
    try fs.put("notes.txt", "hello");
    try fs.mkdir("sub");
    try fs.put("sub/deep.bin", "\x00\x01\x02");
    return fs.share("test");
}

test "open honours disposition" {
    var fs: TestFs = undefined;
    const share = try fixture(&fs);

    try testing.expectEqual(Share.Action.opened, (try share.open("notes.txt", .{})).action);
    try testing.expectError(error.Exists, share.open("notes.txt", .{ .disposition = .create }));
    try testing.expectError(error.NotFound, share.open("nope.txt", .{}));
    try testing.expectEqual(Share.Action.created, (try share.open("new.txt", .{ .disposition = .open_if, .write = true })).action);
    try testing.expectError(error.PathNotFound, share.open("missing/child.txt", .{ .disposition = .create }));
}

test "open enforces the directory/file distinction the client asked for" {
    var fs: TestFs = undefined;
    const share = try fixture(&fs);
    try testing.expectError(error.NotDirectory, share.open("notes.txt", .{ .directory = true }));
    try testing.expectError(error.IsDirectory, share.open("sub", .{ .directory = false }));
    try testing.expect((try share.open("sub", .{ .directory = true })).meta.isDir());
    try testing.expect((try share.open("", .{})).meta.isDir()); // the share root
}

test "read and write at an offset, including past the end" {
    var fs: TestFs = undefined;
    const share = try fixture(&fs);
    const h = (try share.open("notes.txt", .{ .write = true })).handle;

    var buf: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), try share.read(h, 0, &buf));
    try testing.expectEqualStrings("hello", buf[0..5]);
    try testing.expectEqual(@as(usize, 3), try share.read(h, 2, &buf));
    try testing.expectEqual(@as(usize, 0), try share.read(h, 99, &buf));

    _ = try share.write(h, 8, "X");
    const meta = try share.stat(h);
    try testing.expectEqual(@as(u64, 9), meta.size);
    _ = try share.read(h, 0, &buf);
    try testing.expectEqualSlices(u8, "hello\x00\x00\x00X", buf[0..9]); // the hole is zeroed
}

test "readDir lists one level and nothing else" {
    var fs: TestFs = undefined;
    const share = try fixture(&fs);
    const root = (try share.open("", .{})).handle;

    var cursor: Share.Cursor = .{};
    var name_buf: [128]u8 = undefined;
    var entry: Share.DirEntry = undefined;
    var seen: [4][]const u8 = undefined;
    var n: usize = 0;
    while (try share.readDir(root, &cursor, &name_buf, &entry)) : (n += 1) {
        seen[n] = try testing.allocator.dupe(u8, entry.name);
    }
    defer for (seen[0..n]) |s| testing.allocator.free(s);

    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("notes.txt", seen[0]);
    try testing.expectEqualStrings("sub", seen[1]);
}

test "rename moves a directory's whole subtree" {
    var fs: TestFs = undefined;
    const share = try fixture(&fs);
    const dir = (try share.open("sub", .{ .directory = true })).handle;
    try share.rename(dir, "moved", false);

    try testing.expectError(error.NotFound, share.open("sub/deep.bin", .{}));
    const moved = try share.open("moved/deep.bin", .{});
    try testing.expectEqual(@as(u64, 3), moved.meta.size);
}

test "remove refuses a directory that still has children" {
    var fs: TestFs = undefined;
    const share = try fixture(&fs);
    const dir = (try share.open("sub", .{ .directory = true })).handle;
    try testing.expectError(error.NotEmpty, share.remove(dir));

    const child = (try share.open("sub/deep.bin", .{})).handle;
    try share.remove(child);
    try share.remove(dir);
    try testing.expectError(error.NotFound, share.open("sub", .{}));
}

test "a read-only export refuses writes the adapter itself would allow" {
    var fs: TestFs = undefined;
    var share = try fixture(&fs);
    share.read_only = true;

    const h = (try share.open("notes.txt", .{})).handle;
    try testing.expectError(error.AccessDenied, share.write(h, 0, "nope"));
    try testing.expectError(error.AccessDenied, share.truncate(h, 0));
    try testing.expectError(error.AccessDenied, share.remove(h));
    try testing.expectError(error.AccessDenied, share.open("x.txt", .{ .disposition = .create }));
    try testing.expect((try share.statFs()).read_only);
}
