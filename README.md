# easysamba

[![ci](https://github.com/jaenster/easysamba/actions/workflows/ci.yml/badge.svg)](https://github.com/jaenster/easysamba/actions/workflows/ci.yml)

A small SMB2 file server. One thread, one poll loop, no heap.

```sh
easysambad --share files=/srv/files --user alice:hunter2
```

Mount it from macOS, Linux or Windows:

```sh
mount_smbfs //alice:hunter2@server/files /mnt              # macOS
mount -t cifs //server/files /mnt -o username=alice        # Linux
smbclient //server/files -U alice
```

Port 445 needs root. Anything above 1024 does not (`--port 4445`).

## Options

```
shares
  --share NAME=PATH        export PATH as \\server\NAME (repeatable)
  --share-ro NAME=PATH     export it read-only

accounts (there is no guest access; every client authenticates)
  --user NAME:PASSWORD     add an account, :ro at the end for read-only
  --users FILE             one account per line; #<32 hex digits> is an NT hash

network
  --bind ADDR              address to listen on (default: all)
  --port N                 port (default 445)
  --name NAME              NetBIOS server name (default EASYSAMBA)
  --workgroup NAME         workgroup (default WORKGROUP)
  --require-signing        refuse clients that will not sign

  --log LEVEL              error, warn, info (default) or debug
```

## What works

SMB 2.0.2 and 2.1 with NTLMv2 and HMAC-SHA256 signing. Compounded requests,
which macOS leans on heavily. Read, write, directory listing, rename, delete,
file info, disk space.

**Byte-range locks** are enforced, not just acknowledged. A lock is visible to
every other handle on the file, and reads and writes that overlap it are
refused. Locks go away with the handle.

**Leases and oplocks** let a client keep reading what it already read. The
server takes the lease back when someone else writes, truncates, renames or
deletes the file. A client's own writes don't break its own cache.

**Change notification** works the async way: `STATUS_PENDING` now, the answer
later in its own frame. It reports changes made through the server, not changes
made behind its back on the disk.

**Server-side copy.** Copying a file inside a share doesn't send it to the
client and back. Four megabytes cost three small requests. Windows and
`smbclient` use it; macOS asks for the resume key and then copies by hand
anyway.

**Share modes** are enforced, so "the file is open in another program" works.
A handle says what it wants and what it will let others do, and both have to
agree with every handle already on the file. A file marked for deletion can't
be opened again.

**Write-through** means what it says. A client that asks for a durable write
isn't told the write succeeded until it's through to the adapter.

**Browsing** works: `smbclient -L //server` lists the shares. That is an RPC
call over a named pipe rather than a file operation, and it's the reason a lot
of small servers can be mounted but never found.

## What doesn't

* **SMB 3.x** — the dialect list stops at 2.1. Encryption, CMAC signing and
  preauth integrity are all-or-nothing, and a client offered 2.1 uses 2.1.
* **Write and handle caching** — only read caching is granted. Both of the
  others mean parking a request half-answered, and there's nowhere in a
  single-threaded server to park one.
* **Any other RPC call** — the pipe answers NetShareEnumAll and faults on the
  rest. That's enough to list shares; it is not a DCE/RPC server.
* **Symlinks** — not followed, not listed. The share root itself may be one.
* Everything else is refused with a clear NTSTATUS rather than a half-truth.

## Shares don't have to be directories

`vfs/Share.zig` is a vtable: `open`, `read`, `write`, `readDir`, `rename`,
`remove`, `statFs` and a few more. No filesystem concept leaks into it, so a
share can be a database view, an archive, or an object store. Paths arrive
normalized, calls arrive from one thread in order, and errors map to the
NTSTATUS a client knows how to react to.

```zig
try server.addShare(.{ .ctx = &backend, .vtable = &Thing.vtable, .name = "stuff" });
```

Two backends ship: a directory on disk (resolved one `O_NOFOLLOW` component at
a time, so nothing walks out of the share) and one in memory.

`auth/Authenticator.zig` is the same idea for accounts. It answers one question:
what is this user's NT hash? NTLMv2 gives the server no choice — the client
never sends the password, so the hash is what the server has to hold.

## Memory

Everything is one value. Connections, sessions, trees, handles, buffers: fixed
arrays sized at compile time. Nothing allocates, so the ceiling is known before
the process starts, and it says so on the way up.

```
[info] easysambad listening on *:445 (epoll backend, 32 connections max, 34 MiB ceiling)
```

That's the reservation, not the bill. Idle it holds about 2 MiB; a client moving
a gigabyte pushes it to 3. The binary is under 350 KiB.

Reads run around 2 GB/s over loopback with a real client, and cost three
syscalls per request. Signing costs about 15x on bulk reads, which is HMAC over
every byte and unavoidable.

```sh
zig build -Dmax-io=1024 -Dconnections=8     # fewer, fatter connections
zig build -Dmax-io=64 -Dconnections=128     # many small ones
```

## Testing

```sh
zig build test          # 206 unit and protocol tests
test/integration.sh     # mount it with the OS's own client and use it
test/docker-linux.sh    # browsing, locks, leases, notify, server copy on Linux
test/footprint.sh       # memory and CPU while serving a GiB
```

The protocol tests build every request byte by byte and hand it to the server
with no socket in between. The mount scripts are what catch the rest — three of
the bugs in this repo's history were only ever visible there, including a
`FileAllInformation` record one byte short of what Linux accepts.

Some of the tests are fuzzers: random bytes, real requests with bytes flipped,
requests that stop halfway, compound chains that lie about their own length.
The rule is that no input makes the daemon stop. `-Dfuzz-rounds=1000000` turns
them up.

## License

MIT. See [LICENSE](LICENSE).
