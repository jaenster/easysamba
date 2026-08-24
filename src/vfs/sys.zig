//! The filesystem syscalls the POSIX adapter needs, normalized across Linux and
//! macOS/BSD.
//!
//! Zig 0.16 moved most of `std.posix`'s file operations behind `std.Io`, which
//! implies an event loop this server does not use, so these are raw syscalls on
//! Linux and libc calls everywhere else — the same split `net/socket.zig` makes
//! and for the same reason.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const c = std.c;

const use_linux_syscalls = builtin.os.tag == .linux;

pub const Fd = posix.fd_t;
pub const invalid_fd: Fd = -1;
/// "resolve this relative to the process's working directory".
pub const at_fdcwd: Fd = if (use_linux_syscalls) -100 else -2;
// The AT_* flags are not the same numbers on Linux and Darwin, and passing the
// wrong one is silent: unlinkat just refuses to remove a directory.
const at_symlink_nofollow: u32 = if (use_linux_syscalls) 0x100 else 0x0020;
const at_removedir: u32 = if (use_linux_syscalls) 0x200 else 0x0080;
const at_empty_path: u32 = 0x1000; // Linux only

pub const Error = error{
    NotFound,
    Exists,
    AccessDenied,
    IsDirectory,
    NotDirectory,
    NotEmpty,
    NoSpace,
    TooManyOpen,
    NameTooLong,
    Loop,
    Io,
};

fn errnoOf(rc: anytype) posix.E {
    if (use_linux_syscalls) return linux.errno(rc);
    return @enumFromInt(c._errno().*);
}

/// libc reports failure through the return value and only THEN is `errno`
/// meaningful. Reading errno after a successful call returns whatever the last
/// failure left behind, which is how a working mkdir turns into ENOENT.
fn checkC(rc: c_int) Error!void {
    if (rc != 0) return translate(@enumFromInt(c._errno().*));
}

fn checkCount(rc: isize) Error!usize {
    if (rc < 0) return translate(@enumFromInt(c._errno().*));
    return @intCast(rc);
}

fn translate(e: posix.E) Error {
    return switch (e) {
        .NOENT => error.NotFound,
        .EXIST => error.Exists,
        .ACCES, .PERM, .ROFS => error.AccessDenied,
        .ISDIR => error.IsDirectory,
        .NOTDIR => error.NotDirectory,
        .NOTEMPTY => error.NotEmpty,
        .NOSPC, .DQUOT, .FBIG => error.NoSpace,
        .MFILE, .NFILE => error.TooManyOpen,
        .NAMETOOLONG => error.NameTooLong,
        .LOOP => error.Loop,
        else => error.Io,
    };
}

pub const OpenFlags = struct {
    write: bool = false,
    create: bool = false,
    exclusive: bool = false,
    truncate: bool = false,
    directory: bool = false,
    /// Follow a symlink at the final component. Only ever set for a path an
    /// administrator supplied — a share root may well be a symlink, and `/tmp`
    /// is one on macOS — never for a path that came from a client.
    follow: bool = false,
};

/// Opens one path component relative to `dir`. Symlinks are not followed unless
/// the caller asks: a share is a subtree, and following a link is how a subtree
/// stops being one.
pub fn openat(dir: Fd, name: []const u8, flags: OpenFlags, mode: u32) Error!Fd {
    var o: posix.O = .{ .ACCMODE = if (flags.write) .RDWR else .RDONLY, .NOFOLLOW = !flags.follow };
    if (flags.create) o.CREAT = true;
    if (flags.exclusive) o.EXCL = true;
    if (flags.truncate) o.TRUNC = true;
    if (flags.directory) {
        o.DIRECTORY = true;
        o.ACCMODE = .RDONLY;
    }
    if (@hasField(posix.O, "CLOEXEC")) o.CLOEXEC = true;

    return posix.openat(dir, name, o, @intCast(mode)) catch |err| switch (err) {
        error.FileNotFound => error.NotFound,
        error.PathAlreadyExists => error.Exists,
        error.AccessDenied, error.PermissionDenied => error.AccessDenied,
        error.IsDir => error.IsDirectory,
        error.NotDir => error.NotDirectory,
        error.NoSpaceLeft => error.NoSpace,
        error.SystemFdQuotaExceeded, error.ProcessFdQuotaExceeded => error.TooManyOpen,
        error.NameTooLong => error.NameTooLong,
        error.SymLinkLoop => error.Loop,
        else => error.Io,
    };
}

pub fn close(fd: Fd) void {
    if (use_linux_syscalls) {
        _ = linux.close(fd);
    } else {
        _ = c.close(fd);
    }
}

pub fn pread(fd: Fd, buf: []u8, offset: u64) Error!usize {
    while (true) {
        if (use_linux_syscalls) {
            const rc = linux.pread(fd, buf.ptr, buf.len, @intCast(offset));
            const e = errnoOf(rc);
            if (e == .SUCCESS) return @intCast(rc);
            if (e == .INTR) continue;
            return translate(e);
        }
        return checkCount(c.pread(fd, buf.ptr, buf.len, @intCast(offset))) catch |err| {
            if (err == error.Io and @as(posix.E, @enumFromInt(c._errno().*)) == .INTR) continue;
            return err;
        };
    }
}

pub fn pwrite(fd: Fd, data: []const u8, offset: u64) Error!usize {
    while (true) {
        if (use_linux_syscalls) {
            const rc = linux.pwrite(fd, data.ptr, data.len, @intCast(offset));
            const e = errnoOf(rc);
            if (e == .SUCCESS) return @intCast(rc);
            if (e == .INTR) continue;
            return translate(e);
        }
        return checkCount(c.pwrite(fd, data.ptr, data.len, @intCast(offset))) catch |err| {
            if (err == error.Io and @as(posix.E, @enumFromInt(c._errno().*)) == .INTR) continue;
            return err;
        };
    }
}

pub fn ftruncate(fd: Fd, length: u64) Error!void {
    if (use_linux_syscalls) {
        const e = errnoOf(linux.ftruncate(fd, @intCast(length)));
        if (e != .SUCCESS) return translate(e);
        return;
    }
    return checkC(c.ftruncate(fd, @intCast(length)));
}

pub fn fsync(fd: Fd) Error!void {
    if (use_linux_syscalls) {
        const e = errnoOf(linux.fsync(fd));
        if (e != .SUCCESS) return translate(e);
        return;
    }
    return checkC(c.fsync(fd));
}

pub fn mkdirat(dir: Fd, name: []const u8, mode: u32) Error!void {
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&path, name) catch return error.NameTooLong;
    if (use_linux_syscalls) {
        const e = errnoOf(linux.mkdirat(dir, z, @intCast(mode)));
        if (e != .SUCCESS) return translate(e);
        return;
    }
    return checkC(c.mkdirat(dir, z, @intCast(mode)));
}

pub fn unlinkat(dir: Fd, name: []const u8, is_dir: bool) Error!void {
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&path, name) catch return error.NameTooLong;
    const flags: u32 = if (is_dir) at_removedir else 0;
    if (use_linux_syscalls) {
        const e = errnoOf(linux.unlinkat(dir, z, flags));
        if (e != .SUCCESS) return translate(e);
        return;
    }
    return checkC(c.unlinkat(dir, z, flags));
}

pub fn renameat(old_dir: Fd, old: []const u8, new_dir: Fd, new: []const u8) Error!void {
    var old_path: [std.fs.max_path_bytes]u8 = undefined;
    var new_path: [std.fs.max_path_bytes]u8 = undefined;
    const old_z = toZ(&old_path, old) catch return error.NameTooLong;
    const new_z = toZ(&new_path, new) catch return error.NameTooLong;
    if (use_linux_syscalls) {
        const e = errnoOf(linux.renameat(old_dir, old_z, new_dir, new_z));
        if (e != .SUCCESS) return translate(e);
        return;
    }
    return checkC(c.renameat(old_dir, old_z, new_dir, new_z));
}

fn toZ(buf: []u8, name: []const u8) ![:0]const u8 {
    if (name.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    return buf[0..name.len :0];
}

pub const Stat = struct {
    size: u64,
    /// Allocated bytes, from the 512-byte block count every unix reports.
    allocated: u64,
    mode: u32,
    ino: u64,
    nlink: u32,
    atime_ns: i128,
    mtime_ns: i128,
    ctime_ns: i128,
    /// Creation time, where the platform records one.
    btime_ns: ?i128,

    pub fn isDir(s: Stat) bool {
        return s.mode & 0o170000 == 0o040000;
    }
    pub fn isRegular(s: Stat) bool {
        return s.mode & 0o170000 == 0o100000;
    }
};

extern "c" fn fstat(fd: c_int, st: *c.Stat) c_int;
extern "c" fn fstatat(dir: c_int, path: [*:0]const u8, st: *c.Stat, flags: c_int) c_int;
extern "c" fn futimens(fd: c_int, times: *const [2]c.timespec) c_int;
extern "c" fn fchmod(fd: c_int, mode: c.mode_t) c_int;

pub fn fstatFd(fd: Fd) Error!Stat {
    if (use_linux_syscalls) {
        // aarch64 has no fstat syscall at all, so statx is the portable choice
        // across Linux architectures rather than a preference.
        var stx: linux.Statx = undefined;
        const rc = linux.statx(fd, "", at_empty_path, .{
            .TYPE = true,
            .MODE = true,
            .NLINK = true,
            .INO = true,
            .SIZE = true,
            .BLOCKS = true,
            .ATIME = true,
            .MTIME = true,
            .CTIME = true,
            .BTIME = true,
        }, &stx);
        const e = errnoOf(rc);
        if (e != .SUCCESS) return translate(e);
        return fromStatx(stx);
    }
    var st: c.Stat = undefined;
    try checkC(fstat(fd, &st));
    return fromDarwinStat(st);
}

fn fromStatx(stx: linux.Statx) Stat {
    return .{
        .size = stx.size,
        .allocated = stx.blocks * 512,
        .mode = stx.mode,
        .ino = stx.ino,
        .nlink = stx.nlink,
        .atime_ns = tsNs(stx.atime.sec, stx.atime.nsec),
        .mtime_ns = tsNs(stx.mtime.sec, stx.mtime.nsec),
        .ctime_ns = tsNs(stx.ctime.sec, stx.ctime.nsec),
        .btime_ns = if (stx.mask.BTIME) tsNs(stx.btime.sec, stx.btime.nsec) else null,
    };
}

fn fromDarwinStat(st: c.Stat) Stat {
    const has_birthtime = @hasField(c.Stat, "birthtimespec");
    return .{
        .size = @intCast(st.size),
        .allocated = @as(u64, @intCast(@max(st.blocks, 0))) * 512,
        .mode = st.mode,
        .ino = st.ino,
        .nlink = @intCast(st.nlink),
        .atime_ns = tsNs(st.atime().sec, st.atime().nsec),
        .mtime_ns = tsNs(st.mtime().sec, st.mtime().nsec),
        .ctime_ns = tsNs(st.ctime().sec, st.ctime().nsec),
        .btime_ns = if (has_birthtime) tsNs(st.birthtimespec.sec, st.birthtimespec.nsec) else null,
    };
}

/// Stat one name inside a directory without opening it, and without following
/// it if it turns out to be a symlink.
pub fn fstatAt(dir: Fd, name: []const u8) Error!Stat {
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&path, name) catch return error.NameTooLong;
    if (use_linux_syscalls) {
        var stx: linux.Statx = undefined;
        const rc = linux.statx(dir, z, at_symlink_nofollow, .{
            .TYPE = true,
            .MODE = true,
            .NLINK = true,
            .INO = true,
            .SIZE = true,
            .BLOCKS = true,
            .ATIME = true,
            .MTIME = true,
            .CTIME = true,
            .BTIME = true,
        }, &stx);
        const e = errnoOf(rc);
        if (e != .SUCCESS) return translate(e);
        return fromStatx(stx);
    }
    var st: c.Stat = undefined;
    try checkC(fstatat(dir, z, &st, @intCast(at_symlink_nofollow)));
    return fromDarwinStat(st);
}

fn tsNs(sec: anytype, nsec: anytype) i128 {
    return @as(i128, @intCast(sec)) * std.time.ns_per_s + @as(i128, @intCast(nsec));
}

/// A null timestamp means "leave this one alone" (UTIME_OMIT).
pub fn setTimes(fd: Fd, atime_ns: ?i128, mtime_ns: ?i128) Error!void {
    const utime_omit: isize = (1 << 30) - 2;
    var times: [2]c.timespec = undefined;
    times[0] = tsOf(atime_ns, utime_omit);
    times[1] = tsOf(mtime_ns, utime_omit);

    if (use_linux_syscalls) {
        const rc = linux.syscall4(.utimensat, @bitCast(@as(isize, fd)), 0, @intFromPtr(&times), 0);
        const e = errnoOf(rc);
        if (e != .SUCCESS) return translate(e);
        return;
    }
    return checkC(futimens(fd, &times));
}

fn tsOf(value: ?i128, omit: isize) c.timespec {
    const v = value orelse return .{ .sec = 0, .nsec = @intCast(omit) };
    return .{
        .sec = @intCast(@divFloor(v, std.time.ns_per_s)),
        .nsec = @intCast(@mod(v, std.time.ns_per_s)),
    };
}

pub fn chmodFd(fd: Fd, mode: u32) Error!void {
    if (use_linux_syscalls) {
        const rc = linux.fchmod(fd, mode);
        const e = errnoOf(rc);
        if (e != .SUCCESS) return translate(e);
        return;
    }
    return checkC(fchmod(fd, @intCast(mode)));
}

pub const FsStat = struct {
    block_size: u64,
    total_blocks: u64,
    free_blocks: u64,
};

const LinuxStatfs = extern struct {
    type: i64,
    bsize: i64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32,
    namelen: i64,
    frsize: i64,
    flags: i64,
    spare: [4]i64,
};

/// Darwin's `struct statfs`. Only the leading numbers are read, but the whole
/// layout has to be right or the kernel writes past what we reserved.
const DarwinStatfs = extern struct {
    bsize: u32,
    iosize: i32,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32,
    owner: u32,
    type: u32,
    flags: u32,
    fssubtype: u32,
    fstypename: [16]u8,
    mntonname: [1024]u8,
    mntfromname: [1024]u8,
    flags_ext: u32,
    reserved: [7]u32,
};

extern "c" fn fstatfs(fd: c_int, buf: *DarwinStatfs) c_int;

pub fn fstatFs(fd: Fd) Error!FsStat {
    if (use_linux_syscalls) {
        var buf: LinuxStatfs = undefined;
        const rc = linux.syscall2(.fstatfs, @bitCast(@as(isize, fd)), @intFromPtr(&buf));
        const e = errnoOf(rc);
        if (e != .SUCCESS) return translate(e);
        return .{
            .block_size = @intCast(buf.bsize),
            .total_blocks = buf.blocks,
            .free_blocks = buf.bavail,
        };
    }
    var buf: DarwinStatfs = undefined;
    try checkC(fstatfs(fd, &buf));
    return .{
        .block_size = buf.bsize,
        .total_blocks = buf.blocks,
        .free_blocks = buf.bavail,
    };
}

// ------------------------------------------------------------- directories

extern "c" fn fdopendir(fd: c_int) ?*c.DIR;
extern "c" fn readdir(dir: *c.DIR) ?*c.dirent;
extern "c" fn rewinddir(dir: *c.DIR) void;
extern "c" fn closedir(dir: *c.DIR) c_int;
extern "c" fn dup(fd: c_int) c_int;

/// How many bytes of directory entries to fetch per syscall on Linux. Entries
/// average well under 64 bytes, so one call typically covers a whole small
/// directory.
pub const dirent_buffer_bytes = 4096;

/// Sequential directory reading, one entry at a time.
///
/// Linux fills a buffer with `getdents64` and walks it; macOS goes through
/// libc's DIR, which owns a duplicate of the descriptor and buffers for us.
/// Both give the same thing: `next` walks forward, `rewind` starts over.
pub const DirStream = struct {
    fd: Fd,
    dir: if (use_linux_syscalls) void else ?*c.DIR,
    buf: if (use_linux_syscalls) [dirent_buffer_bytes]u8 else void align(8) = undefined,
    len: usize = 0,
    pos: usize = 0,

    pub fn open(fd: Fd) Error!DirStream {
        if (use_linux_syscalls) return .{ .fd = fd, .dir = {} };
        const copy = dup(fd);
        if (copy < 0) return error.Io;
        const dir = fdopendir(copy) orelse {
            close(copy);
            return error.Io;
        };
        return .{ .fd = fd, .dir = dir };
    }

    pub fn deinit(s: *DirStream) void {
        if (!use_linux_syscalls) {
            if (s.dir) |dir| _ = closedir(dir);
            s.dir = null;
        }
    }

    pub fn rewind(s: *DirStream) void {
        if (use_linux_syscalls) {
            _ = linux.lseek(s.fd, 0, 0); // SEEK_SET
            s.len = 0;
            s.pos = 0;
        } else if (s.dir) |dir| {
            rewinddir(dir);
        }
    }

    /// Copies the next entry's name into `name_buf`. Null at the end.
    pub fn next(s: *DirStream, name_buf: []u8) Error!?[]const u8 {
        if (use_linux_syscalls) {
            if (s.pos == s.len) {
                const rc = linux.getdents64(s.fd, &s.buf, s.buf.len);
                const e = errnoOf(rc);
                if (e != .SUCCESS) return translate(e);
                if (rc == 0) return null;
                s.len = rc;
                s.pos = 0;
            }
            const entry: *align(8) const Dirent64 = @alignCast(@ptrCast(&s.buf[s.pos]));
            // A record length that does not advance, or runs past what the
            // kernel said it wrote, would loop forever or read off the end.
            if (entry.reclen < @sizeOf(Dirent64) or s.pos + entry.reclen > s.len) return error.Io;
            const name_ptr: [*:0]const u8 = @ptrCast(&s.buf[s.pos + @offsetOf(Dirent64, "name")]);
            s.pos += entry.reclen;
            const name = std.mem.span(name_ptr);
            if (name.len > name_buf.len) return error.NameTooLong;
            @memcpy(name_buf[0..name.len], name);
            return name_buf[0..name.len];
        }
        const dir = s.dir orelse return null;
        const entry = readdir(dir) orelse return null;
        const name = std.mem.sliceTo(&entry.name, 0);
        if (name.len > name_buf.len) return error.NameTooLong;
        @memcpy(name_buf[0..name.len], name);
        return name_buf[0..name.len];
    }

    const Dirent64 = extern struct {
        ino: u64,
        off: i64,
        reclen: u16,
        type: u8,
        name: [0]u8,
    };
};

const testing = std.testing;

test "errno translation keeps the distinctions the protocol needs" {
    try testing.expectEqual(Error.NotFound, translate(.NOENT));
    try testing.expectEqual(Error.Exists, translate(.EXIST));
    try testing.expectEqual(Error.NotEmpty, translate(.NOTEMPTY));
    try testing.expectEqual(Error.AccessDenied, translate(.ROFS));
    try testing.expectEqual(Error.Io, translate(.IO));
}

test "Stat classifies modes the way the caller asks about them" {
    const dir: Stat = .{
        .size = 0,      .allocated = 0, .mode = 0o040755, .ino = 1, .nlink = 2,
        .atime_ns = 0,  .mtime_ns = 0,  .ctime_ns = 0,    .btime_ns = null,
    };
    var file = dir;
    file.mode = 0o100644;
    try testing.expect(dir.isDir() and !dir.isRegular());
    try testing.expect(file.isRegular() and !file.isDir());
}
