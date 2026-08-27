//! easysamba — a single-threaded, zero-heap SMB2 file server.

pub const poller = @import("net/poller.zig");
pub const Poller = poller.Poller;
pub const socket = @import("net/socket.zig");

pub const wire = @import("smb/wire.zig");
pub const status = @import("smb/status.zig");
pub const filetime = @import("smb/time.zig");
pub const unicode = @import("smb/unicode.zig");
pub const header = @import("smb/header.zig");
pub const sign = @import("smb/sign.zig");
pub const info = @import("smb/info.zig");

pub const md4 = @import("auth/md4.zig");
pub const rc4 = @import("auth/rc4.zig");
pub const ntlm = @import("auth/ntlm.zig");
pub const spnego = @import("auth/spnego.zig");
pub const Authenticator = @import("auth/Authenticator.zig");
pub const UserTable = Authenticator.UserTable;

pub const log = @import("log.zig");
pub const random = @import("random.zig");
pub const server = @import("server/Server.zig");
pub const loopback = @import("server/LoopbackClient.zig");
pub const LoopbackClient = loopback.LoopbackClient;
pub const Server = server.Server;

pub const sys = @import("vfs/sys.zig");
pub const Share = @import("vfs/Share.zig");
pub const posixfs = @import("vfs/PosixFs.zig");
pub const PosixFs = posixfs.PosixFs;
pub const memfs = @import("vfs/MemFs.zig");
pub const MemFs = memfs.MemFs;

test {
    _ = poller;
    _ = socket;
    _ = wire;
    _ = status;
    _ = filetime;
    _ = unicode;
    _ = header;
    _ = sign;
    _ = info;
    _ = md4;
    _ = rc4;
    _ = ntlm;
    _ = spnego;
    _ = Authenticator;
    _ = random;
    _ = server;
    _ = loopback;
    _ = @import("server/protocol_test.zig");
    _ = @import("server/fuzz_test.zig");
    _ = sys;
    _ = Share;
    _ = posixfs;
    _ = memfs;
}
