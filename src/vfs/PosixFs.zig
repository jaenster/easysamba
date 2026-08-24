//! A share backed by a directory on the local filesystem.
//!
//! Containment is the whole job here. Paths arrive already normalized (no `..`,
//! no absolute prefix — see `smb/unicode.zig`), and this adapter opens them one
//! component at a time relative to the share root with `O_NOFOLLOW` on every
//! step. So a symlink cannot be used to walk out of the share, and neither can
//! a directory that becomes a symlink between two requests: there is no path
//! string handed to the kernel that starts anywhere but the root descriptor.
//!
//! The cost is that symlinks inside a share are not usable at all. They are
//! skipped in listings too, rather than shown as files that cannot be opened.
//!
//! Fixed capacity, no allocator: `max_nodes` open handles, each with its own
//! path buffer.

const std = @import("std");
const sys = @import("sys.zig");
const Share = @import("Share.zig");
const filetime = @import("../smb/time.zig");
const unicode = @import("../smb/unicode.zig");

pub const Options = struct {
    max_nodes: usize = 256,
    max_path: usize = 512,
};

pub const OpenRootError = error{ NotFound, NotDirectory, AccessDenied, Io };

pub fn PosixFs(comptime opts: Options) type {
    return struct {
        root: sys.Fd = sys.invalid_fd,
        nodes: [opts.max_nodes]Node = undefined,
        /// Files created for a client are owned by whoever runs the daemon;
        /// these are the modes they get.
        file_mode: u32 = 0o644,
        dir_mode: u32 = 0o755,

        const Self = @This();

        const Node = struct {
            used: bool = false,
            fd: sys.Fd = sys.invalid_fd,
            is_dir: bool = false,
            path: [opts.max_path]u8 = undefined,
            path_len: usize = 0,
            dir: ?sys.DirStream = null,

            fn path_(n: *const Node) []const u8 {
                return n.path[0..n.path_len];
            }
        };

        /// Opens the directory to export. The descriptor is held for the
        /// lifetime of the share: every path is resolved against it, so the
        /// export survives the directory being renamed underneath it.
        ///
        /// Fully initializes `s`, so the value may be `undefined` going in —
        /// which is how a caller keeping one in a long-lived frame gets it.
        pub fn init(s: *Self, root_path: []const u8) OpenRootError!void {
            s.file_mode = 0o644;
            s.dir_mode = 0o755;
            for (&s.nodes) |*n| n.* = .{};
            // The root is the one path that may be a symlink: it comes from
            // whoever started the daemon, not from a client.
            s.root = sys.openat(sys.at_fdcwd, root_path, .{ .directory = true, .follow = true }, 0) catch |err| return switch (err) {
                error.NotFound => error.NotFound,
                error.NotDirectory => error.NotDirectory,
                error.AccessDenied => error.AccessDenied,
                else => error.Io,
            };
        }

        pub fn deinit(s: *Self) void {
            for (&s.nodes) |*n| {
                if (n.used) closeNode(n);
            }
            if (s.root != sys.invalid_fd) sys.close(s.root);
            s.root = sys.invalid_fd;
        }

        pub fn share(s: *Self, name: []const u8) Share {
            return .{ .ctx = s, .vtable = &vtable, .name = name };
        }

        fn closeNode(n: *Node) void {
            if (n.dir) |*dir| dir.deinit();
            n.dir = null;
            if (n.fd != sys.invalid_fd) sys.close(n.fd);
            n.fd = sys.invalid_fd;
            n.used = false;
        }

        fn self(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }

        fn resolve(s: *Self, handle: Share.Handle) Share.Error!*Node {
            if (handle == 0 or handle > opts.max_nodes) return error.NotFound;
            const node = &s.nodes[handle - 1];
            if (!node.used) return error.NotFound;
            return node;
        }

        fn mapError(err: sys.Error) Share.Error {
            return switch (err) {
                error.NotFound => error.NotFound,
                error.Exists => error.Exists,
                error.AccessDenied => error.AccessDenied,
                error.IsDirectory => error.IsDirectory,
                error.NotDirectory => error.NotDirectory,
                error.NotEmpty => error.NotEmpty,
                error.NoSpace => error.NoSpace,
                error.TooManyOpen => error.TooManyOpen,
                error.NameTooLong => error.NameTooLong,
                // A symlink where a real path component was expected: refused,
                // not followed.
                error.Loop => error.AccessDenied,
                error.Io => error.Io,
            };
        }

        /// The parent directory of `path`, opened one component at a time.
        /// The returned descriptor is the share root itself when the path has
        /// no parent, which is why `close` is a separate decision.
        const Parent = struct {
            fd: sys.Fd,
            owned: bool,
            name: []const u8,

            fn release(p: Parent) void {
                if (p.owned) sys.close(p.fd);
            }
        };

        fn openParent(s: *Self, path: []const u8) Share.Error!Parent {
            var dir = s.root;
            var owned = false;
            var rest = path;
            while (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
                const next = sys.openat(dir, rest[0..slash], .{ .directory = true }, 0) catch |err| {
                    if (owned) sys.close(dir);
                    return switch (mapError(err)) {
                        // A missing or unusable intermediate component is a bad
                        // path, not a missing file: clients react differently.
                        error.NotFound, error.NotDirectory => error.PathNotFound,
                        else => |e| e,
                    };
                };
                if (owned) sys.close(dir);
                dir = next;
                owned = true;
                rest = rest[slash + 1 ..];
            }
            return .{ .fd = dir, .owned = owned, .name = rest };
        }

        fn allocNode(s: *Self) ?*Node {
            for (&s.nodes, 0..) |*n, i| {
                if (!n.used) {
                    n.* = .{ .used = true };
                    return &s.nodes[i];
                }
            }
            return null;
        }

        fn handleOf(s: *Self, node: *Node) Share.Handle {
            return (@intFromPtr(node) - @intFromPtr(&s.nodes)) / @sizeOf(Node) + 1;
        }

        fn metaOf(stat: sys.Stat, name: []const u8) Share.Meta {
            var attributes: Share.Attributes = .{};
            attributes.directory = stat.isDir();
            if (!stat.isDir()) attributes.archive = true;
            // No unix mode maps onto "read-only" exactly; owner-write is the
            // closest thing, and it is what every SMB server on unix uses.
            if (stat.mode & 0o200 == 0) attributes.read_only = true;
            // A leading dot is what "hidden" means on this side of the wire.
            if (name.len > 1 and name[0] == '.') attributes.hidden = true;

            return .{
                .size = stat.size,
                .alloc_size = stat.allocated,
                .attributes = attributes,
                .created = filetime.fromUnixNs(stat.btime_ns orelse stat.ctime_ns),
                .accessed = filetime.fromUnixNs(stat.atime_ns),
                .modified = filetime.fromUnixNs(stat.mtime_ns),
                .changed = filetime.fromUnixNs(stat.ctime_ns),
                .file_id = stat.ino,
                .links = stat.nlink,
            };
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

        fn vOpen(ctx: *anyopaque, path: []const u8, o: Share.OpenOptions) Share.Error!Share.Opened {
            const s = self(ctx);
            if (path.len > opts.max_path) return error.NameTooLong;

            const parent = try s.openParent(path);
            defer parent.release();
            // "" is the share root; opening "." of the root gives a descriptor
            // that can be closed without taking the root with it.
            const name = if (parent.name.len == 0) "." else parent.name;
            const at_root = parent.name.len == 0;

            const want_dir = o.directory orelse false;
            var action: Share.Action = .opened;
            var fd: sys.Fd = sys.invalid_fd;

            if (at_root) {
                fd = sys.openat(parent.fd, ".", .{ .directory = true }, 0) catch |err| return mapError(err);
            } else if (want_dir and o.disposition != .open and o.disposition != .overwrite) {
                // Directories are made, not opened into existence.
                const made = blk: {
                    sys.mkdirat(parent.fd, name, s.dir_mode) catch |err| switch (err) {
                        error.Exists => break :blk false,
                        else => return mapError(err),
                    };
                    break :blk true;
                };
                if (!made and o.disposition == .create) return error.Exists;
                action = if (made) .created else .opened;
                fd = sys.openat(parent.fd, name, .{ .directory = true }, 0) catch |err| return mapError(err);
            } else {
                fd = try s.openFile(parent.fd, name, o, &action);
            }
            errdefer sys.close(fd);

            const stat = sys.fstatFd(fd) catch |err| return mapError(err);
            if (o.directory) |must_be_dir| {
                if (must_be_dir and !stat.isDir()) return error.NotDirectory;
                if (!must_be_dir and stat.isDir()) return error.IsDirectory;
            }
            // Anything that is not a file or a directory (a device, a socket,
            // a fifo) is not something a share can meaningfully export.
            if (!stat.isDir() and !stat.isRegular()) return error.AccessDenied;

            const node = s.allocNode() orelse return error.TooManyOpen;
            node.fd = fd;
            node.is_dir = stat.isDir();
            @memcpy(node.path[0..path.len], path);
            node.path_len = path.len;

            return .{
                .handle = s.handleOf(node),
                .action = action,
                .meta = metaOf(stat, unicode.baseName(path)),
            };
        }

        /// The disposition dance: the only way to learn whether a file already
        /// existed is to try to create it exclusively and see.
        fn openFile(s: *Self, dir: sys.Fd, name: []const u8, o: Share.OpenOptions, action: *Share.Action) Share.Error!sys.Fd {
            const mode: u32 = if (o.attributes.read_only) s.file_mode & 0o444 else s.file_mode;
            const write = o.write or o.disposition != .open;

            switch (o.disposition) {
                .open => return sys.openat(dir, name, .{ .write = o.write }, 0) catch |err| mapError(err),
                .overwrite => {
                    action.* = .overwritten;
                    return sys.openat(dir, name, .{ .write = true, .truncate = true }, 0) catch |err| mapError(err);
                },
                .create => {
                    action.* = .created;
                    return sys.openat(dir, name, .{ .write = write, .create = true, .exclusive = true }, mode) catch |err| mapError(err);
                },
                .open_if, .overwrite_if, .supersede => {
                    if (sys.openat(dir, name, .{ .write = write, .create = true, .exclusive = true }, mode)) |fd| {
                        action.* = .created;
                        return fd;
                    } else |err| switch (err) {
                        error.Exists => {},
                        else => return mapError(err),
                    }
                    const truncate = o.disposition != .open_if;
                    action.* = switch (o.disposition) {
                        .open_if => .opened,
                        .supersede => .superseded,
                        else => .overwritten,
                    };
                    return sys.openat(dir, name, .{ .write = write, .truncate = truncate }, 0) catch |err| mapError(err);
                },
            }
        }

        fn vClose(ctx: *anyopaque, handle: Share.Handle) void {
            const node = self(ctx).resolve(handle) catch return;
            closeNode(node);
        }

        fn vStat(ctx: *anyopaque, handle: Share.Handle) Share.Error!Share.Meta {
            const node = try self(ctx).resolve(handle);
            const stat = sys.fstatFd(node.fd) catch |err| return mapError(err);
            return metaOf(stat, unicode.baseName(node.path_()));
        }

        fn vRead(ctx: *anyopaque, handle: Share.Handle, offset: u64, buf: []u8) Share.Error!usize {
            const node = try self(ctx).resolve(handle);
            if (node.is_dir) return error.IsDirectory;
            return sys.pread(node.fd, buf, offset) catch |err| mapError(err);
        }

        fn vWrite(ctx: *anyopaque, handle: Share.Handle, offset: u64, data: []const u8) Share.Error!usize {
            const node = try self(ctx).resolve(handle);
            if (node.is_dir) return error.IsDirectory;
            var written: usize = 0;
            while (written < data.len) {
                const n = sys.pwrite(node.fd, data[written..], offset + written) catch |err| return mapError(err);
                if (n == 0) return error.NoSpace;
                written += n;
            }
            return written;
        }

        fn vTruncate(ctx: *anyopaque, handle: Share.Handle, size: u64) Share.Error!void {
            const node = try self(ctx).resolve(handle);
            if (node.is_dir) return error.IsDirectory;
            sys.ftruncate(node.fd, size) catch |err| return mapError(err);
        }

        fn vFlush(ctx: *anyopaque, handle: Share.Handle) Share.Error!void {
            const node = try self(ctx).resolve(handle);
            sys.fsync(node.fd) catch |err| return mapError(err);
        }

        fn vReadDir(ctx: *anyopaque, handle: Share.Handle, cursor: *Share.Cursor, name_buf: []u8, out: *Share.DirEntry) Share.Error!bool {
            const node = try self(ctx).resolve(handle);
            if (!node.is_dir) return error.NotDirectory;

            if (node.dir == null) {
                node.dir = sys.DirStream.open(node.fd) catch |err| return mapError(err);
                cursor.index = 0;
            }
            var stream = &node.dir.?;
            // A cursor rewound to the start means the client asked to restart.
            if (cursor.index == 0) stream.rewind();

            while (true) {
                const name = (stream.next(name_buf) catch |err| return mapError(err)) orelse return false;
                cursor.index += 1;
                // The server emits `.` and `..` itself.
                if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

                const stat = sys.fstatAt(node.fd, name) catch continue; // vanished mid-scan
                // Symlinks and device nodes are skipped rather than listed:
                // this adapter would refuse to open them anyway.
                if (!stat.isDir() and !stat.isRegular()) continue;

                out.* = .{ .name = name, .meta = metaOf(stat, name) };
                return true;
            }
        }

        fn vSetMeta(ctx: *anyopaque, handle: Share.Handle, changes: Share.MetaChanges) Share.Error!void {
            const s = self(ctx);
            const node = try s.resolve(handle);

            if (changes.accessed != null or changes.modified != null) {
                const atime: ?i128 = if (changes.accessed) |v| filetime.toUnixNs(v) else null;
                const mtime: ?i128 = if (changes.modified) |v| filetime.toUnixNs(v) else null;
                sys.setTimes(node.fd, atime, mtime) catch |err| return mapError(err);
            }
            // Creation time cannot be set on Linux at all and needs a
            // filesystem-specific call on macOS; a client that sets it is told
            // nothing went wrong, because from its side nothing did.
            if (changes.attributes) |attributes| {
                const stat = sys.fstatFd(node.fd) catch |err| return mapError(err);
                const base: u32 = if (node.is_dir) s.dir_mode else s.file_mode;
                const mode: u32 = if (attributes.read_only) base & ~@as(u32, 0o222) else base;
                if (mode != stat.mode & 0o777) {
                    sys.chmodFd(node.fd, mode) catch |err| return mapError(err);
                }
            }
        }

        fn vRename(ctx: *anyopaque, handle: Share.Handle, new_path: []const u8, replace: bool) Share.Error!void {
            const s = self(ctx);
            const node = try s.resolve(handle);
            if (new_path.len > opts.max_path) return error.NameTooLong;

            const source = try s.openParent(node.path_());
            defer source.release();
            const target = try s.openParent(new_path);
            defer target.release();

            if (!replace) {
                // renameat(2) replaces silently; SMB says the client decides.
                if (sys.fstatAt(target.fd, target.name)) |_| {
                    return error.Exists;
                } else |_| {}
            }
            sys.renameat(source.fd, source.name, target.fd, target.name) catch |err| return mapError(err);
            @memcpy(node.path[0..new_path.len], new_path);
            node.path_len = new_path.len;
        }

        fn vRemove(ctx: *anyopaque, handle: Share.Handle) Share.Error!void {
            const s = self(ctx);
            const node = try s.resolve(handle);
            if (node.path_len == 0) return error.AccessDenied; // never the share root

            const parent = try s.openParent(node.path_());
            defer parent.release();
            sys.unlinkat(parent.fd, parent.name, node.is_dir) catch |err| return mapError(err);
        }

        fn vStatFs(ctx: *anyopaque) Share.Error!Share.FsInfo {
            const s = self(ctx);
            const fs = sys.fstatFs(s.root) catch |err| return mapError(err);
            return .{
                .total_bytes = fs.total_blocks * fs.block_size,
                .free_bytes = fs.free_blocks * fs.block_size,
                .block_size = @intCast(@max(fs.block_size, 512)),
                .label = "easysamba",
                .serial = 0x45415359,
            };
        }
    };
}

const testing = std.testing;
const TestFs = PosixFs(.{ .max_nodes = 16, .max_path = 256 });

/// Builds a scratch directory to export. Nothing here uses `std.fs`, which in
/// 0.16 needs the `Io` machinery this server avoids.
fn scratchDir(name: []const u8) ![]const u8 {
    const base = "/tmp/easysamba-test";
    sys.mkdirat(sys.at_fdcwd, base, 0o755) catch {};
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ base, name });
    // Start from a clean directory even if a previous run left one behind.
    removeTree(path);
    try sys.mkdirat(sys.at_fdcwd, path, 0o755);
    const owned = try testing.allocator.dupe(u8, path);
    return owned;
}

fn removeTree(path: []const u8) void {
    const dir = sys.openat(sys.at_fdcwd, path, .{ .directory = true }, 0) catch return;
    var stream = sys.DirStream.open(dir) catch {
        sys.close(dir);
        return;
    };
    var name_buf: [256]u8 = undefined;
    while (stream.next(&name_buf) catch null) |name| {
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        const stat = sys.fstatAt(dir, name) catch continue;
        if (stat.isDir()) {
            var child: [512]u8 = undefined;
            const child_path = std.fmt.bufPrint(&child, "{s}/{s}", .{ path, name }) catch continue;
            removeTree(child_path);
        } else {
            sys.unlinkat(dir, name, false) catch {};
        }
    }
    stream.deinit();
    sys.close(dir);
    sys.unlinkat(sys.at_fdcwd, path, true) catch {};
}

const Fixture = struct {
    fs: *TestFs,
    path: []const u8,

    fn init(name: []const u8) !Fixture {
        const path = try scratchDir(name);
        const fs = try testing.allocator.create(TestFs);
        try fs.init(path);
        return .{ .fs = fs, .path = path };
    }

    fn deinit(f: *Fixture) void {
        f.fs.deinit();
        testing.allocator.destroy(f.fs);
        removeTree(f.path);
        testing.allocator.free(f.path);
    }
};

test "create, write, read back and stat a real file" {
    var f = try Fixture.init("basic");
    defer f.deinit();
    const share = f.fs.share("data");

    const created = try share.open("hello.txt", .{ .write = true, .disposition = .create });
    try testing.expectEqual(Share.Action.created, created.action);
    try testing.expectEqual(@as(usize, 11), try share.write(created.handle, 0, "hello world"));
    try share.flush(created.handle);

    var buf: [32]u8 = undefined;
    const opened = try share.open("hello.txt", .{});
    try testing.expectEqual(Share.Action.opened, opened.action);
    const n = try share.read(opened.handle, 0, &buf);
    try testing.expectEqualStrings("hello world", buf[0..n]);

    const meta = try share.stat(opened.handle);
    try testing.expectEqual(@as(u64, 11), meta.size);
    try testing.expect(!meta.isDir());
    try testing.expect(meta.file_id != 0);
    try testing.expect(meta.modified > 0);

    share.close(created.handle);
    share.close(opened.handle);
}

test "dispositions behave the way the protocol expects" {
    var f = try Fixture.init("dispositions");
    defer f.deinit();
    const share = f.fs.share("data");

    _ = try share.open("a.txt", .{ .write = true, .disposition = .create });
    try testing.expectError(error.Exists, share.open("a.txt", .{ .disposition = .create }));
    try testing.expectError(error.NotFound, share.open("b.txt", .{}));
    try testing.expectEqual(Share.Action.opened, (try share.open("a.txt", .{ .disposition = .open_if })).action);
    try testing.expectEqual(Share.Action.created, (try share.open("c.txt", .{ .write = true, .disposition = .open_if })).action);

    const h = (try share.open("a.txt", .{ .write = true })).handle;
    _ = try share.write(h, 0, "content");
    const overwritten = try share.open("a.txt", .{ .write = true, .disposition = .overwrite_if });
    try testing.expectEqual(Share.Action.overwritten, overwritten.action);
    try testing.expectEqual(@as(u64, 0), (try share.stat(overwritten.handle)).size);
}

test "directories: create, list, and refuse to remove while occupied" {
    var f = try Fixture.init("dirs");
    defer f.deinit();
    const share = f.fs.share("data");

    const dir = try share.open("sub", .{ .write = true, .disposition = .create, .directory = true });
    try testing.expectEqual(Share.Action.created, dir.action);
    try testing.expect(dir.meta.isDir());
    _ = try share.open("sub/inner.txt", .{ .write = true, .disposition = .create });

    var cursor: Share.Cursor = .{};
    var name_buf: [256]u8 = undefined;
    var entry: Share.DirEntry = undefined;
    var count: usize = 0;
    var saw_inner = false;
    while (try share.readDir(dir.handle, &cursor, &name_buf, &entry)) {
        count += 1;
        if (std.mem.eql(u8, entry.name, "inner.txt")) saw_inner = true;
    }
    try testing.expectEqual(@as(usize, 1), count); // . and .. are the server's job
    try testing.expect(saw_inner);

    try testing.expectError(error.NotEmpty, share.remove(dir.handle));
}

test "a listing can be restarted from the beginning" {
    var f = try Fixture.init("restart");
    defer f.deinit();
    const share = f.fs.share("data");
    _ = try share.open("one.txt", .{ .write = true, .disposition = .create });
    _ = try share.open("two.txt", .{ .write = true, .disposition = .create });

    const root = (try share.open("", .{})).handle;
    var cursor: Share.Cursor = .{};
    var name_buf: [256]u8 = undefined;
    var entry: Share.DirEntry = undefined;

    var first_pass: usize = 0;
    while (try share.readDir(root, &cursor, &name_buf, &entry)) first_pass += 1;
    try testing.expectEqual(@as(usize, 2), first_pass);

    cursor = .{}; // what the server does for RESTART_SCANS
    var second_pass: usize = 0;
    while (try share.readDir(root, &cursor, &name_buf, &entry)) second_pass += 1;
    try testing.expectEqual(@as(usize, 2), second_pass);
}

test "rename moves a file and refuses to clobber unless asked" {
    var f = try Fixture.init("rename");
    defer f.deinit();
    const share = f.fs.share("data");

    const a = (try share.open("a.txt", .{ .write = true, .disposition = .create })).handle;
    _ = try share.write(a, 0, "payload");
    _ = try share.open("b.txt", .{ .write = true, .disposition = .create });

    try testing.expectError(error.Exists, share.rename(a, "b.txt", false));
    try share.rename(a, "b.txt", true);
    try testing.expectError(error.NotFound, share.open("a.txt", .{}));

    var buf: [16]u8 = undefined;
    const moved = (try share.open("b.txt", .{})).handle;
    try testing.expectEqual(@as(usize, 7), try share.read(moved, 0, &buf));
}

test "truncate, timestamps and the read-only attribute survive a round trip" {
    var f = try Fixture.init("meta");
    defer f.deinit();
    const share = f.fs.share("data");

    const h = (try share.open("file.bin", .{ .write = true, .disposition = .create })).handle;
    _ = try share.write(h, 0, "0123456789");
    try share.truncate(h, 4);
    try testing.expectEqual(@as(u64, 4), (try share.stat(h)).size);

    const when = filetime.fromUnixSec(1_600_000_000);
    try share.setMeta(h, .{ .modified = when });
    const meta = try share.stat(h);
    try testing.expectEqual(@as(i128, 1_600_000_000), @divFloor(filetime.toUnixNs(meta.modified), std.time.ns_per_s));

    try share.setMeta(h, .{ .attributes = .{ .read_only = true } });
    try testing.expect((try share.stat(h)).attributes.read_only);
}

test "a path cannot escape the share root" {
    var f = try Fixture.init("escape");
    defer f.deinit();
    const share = f.fs.share("data");

    // The normalizer rejects `..` before an adapter ever sees it, so what is
    // actually being checked here is that a name that merely looks like an
    // escape lands inside the share.
    _ = try share.open("..safe", .{ .write = true, .disposition = .create });
    var stat_buf: [512]u8 = undefined;
    const inside = try std.fmt.bufPrint(&stat_buf, "{s}/..safe", .{f.path});
    _ = try sys.fstatAt(sys.at_fdcwd, inside);

    try testing.expectError(error.PathNotFound, share.open("nowhere/file.txt", .{ .disposition = .create }));
}

test "free space comes from the real filesystem" {
    var f = try Fixture.init("statfs");
    defer f.deinit();
    const info = try f.fs.share("data").statFs();
    try testing.expect(info.total_bytes > 0);
    try testing.expect(info.free_bytes <= info.total_bytes);
    try testing.expect(info.block_size >= 512);
}

test "handles are released and the table is reusable" {
    var f = try Fixture.init("handles");
    defer f.deinit();
    const share = f.fs.share("data");

    var i: usize = 0;
    while (i < 64) : (i += 1) { // four times the table size
        const h = (try share.open("churn.txt", .{ .write = true, .disposition = .open_if })).handle;
        share.close(h);
    }
}
