# easysamba

An SMB2 file server in Zig. One thread, one poll loop, no heap after startup,
and an adapter interface so what gets exported does not have to be a filesystem.

```sh
easysambad --share files=/srv/files --user alice:hunter2
```

Mounts from macOS (`mount_smbfs`), Linux (kernel `cifs`, `smbclient`) and
Windows. Every client authenticates with NTLMv2 — there is no guest access and
no anonymous access anywhere in it.

## Quick start

```sh
zig build -Doptimize=ReleaseSafe
zig-out/bin/easysambad --port 4445 --share files=/srv/files --user alice:hunter2
```

```sh
# macOS
mount_smbfs //alice:hunter2@server:4445/files /mnt

# Linux
mount -t cifs //server/files /mnt -o username=alice,port=4445,vers=2.1
smbclient //server/files -U alice -p 4445
```

Port 445 is the default and needs root. Anything above 1024 does not.

```
usage: easysambad --share NAME=PATH --user NAME:PASSWORD [options]

shares
  --share NAME=PATH        export PATH as \\server\NAME (repeatable)
  --share-ro NAME=PATH     export it read-only (same as PATH:ro)

accounts (there is no guest access; every client authenticates)
  --user NAME:PASSWORD     add an account, :ro at the end for read-only
  --users FILE             read accounts from a file, one per line;
                           a password of #<32 hex digits> is an NT hash

network
  --bind ADDR              address to listen on (default: all)
  --port N                 port (default 445; below 1024 needs root)
  --name NAME              NetBIOS server name (default EASYSAMBA)
  --workgroup NAME         workgroup (default WORKGROUP)
  --require-signing        refuse clients that will not sign

  --log LEVEL              error, warn, info (default) or debug
  --help
```

## Design

The whole server is one value. Connections, the sessions on each connection,
the trees on each session, the handles on each tree, the send and receive
buffers: all fixed-size arrays inside one `Server(limits)` struct that lives in
`main`'s frame. Nothing allocates after startup, so the memory ceiling is a
compile-time constant — the daemon prints it on the way up.

```
[info] easysambad listening on *:445 (epoll backend, 32 connections max, 34 MiB resident)
```

One thread multiplexes every connection through `epoll` on Linux, `kqueue` on
macOS, `poll` anywhere else (`-Dpoll` forces it). A connection stops being read
while its output buffer is too full to hold another answer, which is the
backpressure that stops one slow client from making the server buffer without
bound.

```
src/
  net/            poll/epoll/kqueue multiplexer, bare non-blocking sockets
  smb/            the protocol: header, wire cursors, info classes, signing
  auth/           NTLMv2, SPNEGO, MD4, RC4, the credential adapter
  vfs/            the share adapter, a filesystem backend, an in-memory backend
  server/         connection state machine, command handlers, a wire-level client
```

`net/` is lifted from [zircd](../ircd), where the same trade-offs applied.

## Adapters

Two interfaces, both a vtable and an opaque context, neither allowed to
allocate.

**`vfs/Share.zig`** is what gets exported. `open`, `read`, `write`, `readDir`,
`rename`, `remove`, `statFs` and a handful more — no filesystem concept leaks
into it, so a share can be a directory, a database view, an archive, or an
object store. Paths arrive normalized (UTF-8, `/`-separated, no `..`, no NUL, no
stream suffix), calls arrive from one thread in order, and every error maps to
the one NTSTATUS a client knows how to react to.

Two backends ship with it:

* `vfs/PosixFs.zig` — a directory on disk. Resolves every client path one
  component at a time against the share's root descriptor with `O_NOFOLLOW`, so
  no symlink can walk out of the share.
* `vfs/MemFs.zig` — in memory. It is what the protocol tests run against, and
  the proof that the interface is a real interface.

Writing another one means filling in a `VTable` and handing back a `Share`:

```zig
var backend: Thing = ...;
try server.addShare(.{
    .ctx = &backend,
    .vtable = &Thing.vtable,
    .name = "stuff",
});
```

**`auth/Authenticator.zig`** is who may connect. It answers one question —
"what is this user's NT hash?" — because NTLMv2 gives the server no choice: the
client never sends the password, it sends an HMAC keyed by the hash, so the hash
is what the server must hold. An NT hash is password-equivalent; storing one is
storing the password. `UserTable` is the built-in backend, configured from
`--user` or a file.

A backend that cannot produce a hash — a domain controller, PAM, an OAuth
provider — cannot be adapted through this interface. That would need a vtable
entry taking the whole NTLMv2 response and returning a session key, which is the
natural place to extend it.

## Performance

Two things were measured, because they answer different questions.

**Through a real client**, macOS `mount_smbfs` over loopback, 200 MB with a warm
cache:

| max I/O | read | write | daemon CPU for 400 MB |
|-|-|-|-|
| 64 KiB | 1.4 GB/s | 1.6 GB/s | 0.13 s |
| 256 KiB | 2.2 GB/s | 1.9 GB/s | 0.10 s |
| 1 MiB | 2.6 GB/s | 1.5 GB/s | 0.09 s |

Past 256 KiB the gain is inside the noise while the memory per connection keeps
doubling, so that is the default. Both ends of the trade are build options:

```sh
zig build -Dmax-io=1024 -Dconnections=8    # fewer, fatter connections
zig build -Dmax-io=64  -Dconnections=128   # many small ones
```

**The dispatch path itself**, in process, no sockets (`zig build bench
-Doptimize=ReleaseFast`, Apple M-series):

```
posixfs share
  operation                               ops/sec     throughput
  echo (dispatch floor)                  18386877              -
  create + close                           111472              -
  create+query_info+close (1 frame)        105434              -
  query_info (FileAllInformation)         2128587              -
  query_directory (34 entries)              15300              -
  read 64 KiB                              528357    33022 MiB/s
  write 64 KiB                             185796    11612 MiB/s
  read 64 KiB, signed                       34857     2179 MiB/s
```

What that says: the protocol layer is not the bottleneck for anything, the
filesystem syscalls dominate metadata operations, and **signing costs about 15×
on bulk reads** — it is HMAC-SHA256 over every byte, and it is what a Windows 11
client asks for by default.

Blocking file I/O on the one thread is the shape of this design: a share backed
by something slow stalls every client for as long as it is slow. Cold reads from
a disk are disk-bound, and the daemon sits idle inside `pread` while they are.

## What it speaks

SMB 2.0.2 and 2.1. NTLMv2 inside SPNEGO or raw, HMAC-SHA256 signing (verified on
every request that claims it, required when the client or `--require-signing`
says so), and compounded requests — which matters, because macOS opens, queries
and closes a file in a single round trip.

Implemented: negotiate, session setup, logoff, tree connect/disconnect, create,
close, flush, read, write, query directory, query info, set info, echo, cancel.

Deliberately not implemented, and answered with a clear "no" rather than
silence:

* **SMB 3.x.** The dialect list stops at 2.1. Every 3.x feature a client would
  then expect — CMAC signing, negotiate contexts, preauth integrity, encryption
  — is a correctness cliff rather than an optimisation, and a client offered 2.1
  uses 2.1.
* **Oplocks and leases.** Never granted, so no client caches data this server
  might invalidate.
* **Byte-range locks.** Accepted and not enforced. Refusing them outright breaks
  clients that lock before every write; pretending is the workable answer, and
  it means nothing.
* **Change notification, DFS, named pipes.** `IPC$` connects and is empty, which
  is what a client needs to get on with mounting a real share. Browsing a server
  for its share list needs RPC over that pipe and does not work; mounting a share
  by name does.
* **Symlinks.** Not followed, not listed. The share root itself may be one.

## Security

* NTLMv2 only. An NTLMv1 response is refused rather than downgraded, and a null
  session is refused outright — there is no code path that serves an
  unauthenticated client.
* The server challenge comes from the kernel's CSPRNG, and the daemon refuses to
  start if it cannot get one.
* Signing is verified on every request that claims to be signed, and required
  for every request once the session says so.
* NTLM keying material is wiped as soon as the session key exists, and again
  when the session ends.
* Client paths cannot escape a share: `..`, absolute paths, NULs and stream
  suffixes are rejected before any adapter sees them, and the filesystem backend
  resolves what is left one `O_NOFOLLOW` component at a time.
* A handle is identified by a generation-stamped id, so a FileId from a closed
  handle cannot reach whatever now occupies its slot.
* Connections that do not authenticate are dropped after 30 seconds, so opening
  sockets and saying nothing does not fill the connection table.

## Building and testing

```sh
zig build                                # zig-out/bin/easysambad
zig build test                           # 138 unit and protocol tests
zig build check -Dtarget=x86_64-linux    # type-check another platform's backend
zig build bench -Doptimize=ReleaseFast   # the numbers above
test/integration.sh                      # mount it for real and use it
test/docker-linux.sh                     # same, on Linux, both clients
```

The tests are the protocol, not a mock of it. `src/server/LoopbackClient.zig` is
a client that builds every request byte by byte and hands it straight to the
server, so `src/server/protocol_test.zig` exercises negotiation, the two-round
NTLMv2 exchange, signing, compounding, backpressure and every handler without a
socket in the way. `src/vfs/PosixFs.zig` tests against real files. The rest are
worked examples from the specifications: MD4 against RFC 1320, NTOWFv2 against
MS-NLMP's own sample, and the info-class records against byte offsets from
MS-FSCC.

`test/integration.sh` is the one that catches what unit tests cannot — it mounts
the share with the operating system's own client and checks the bytes that come
back. Two of the bugs in this repo's history were only ever visible there: a
missing transport header, and a `FileAllInformation` record one byte shorter
than the Linux client accepts.
