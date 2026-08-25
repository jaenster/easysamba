# easysamba

[![ci](https://github.com/jaenster/easysamba/actions/workflows/ci.yml/badge.svg)](https://github.com/jaenster/easysamba/actions/workflows/ci.yml)

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
buffers: all fixed-size arrays inside one `Server(limits)` struct. Nothing
allocates, ever — not at startup either — so the memory ceiling is a
compile-time constant, and the daemon prints it on the way up.

```
[info] easysambad listening on *:445 (epoll backend, 32 connections max, 34 MiB ceiling)
```

That is the ceiling, not the bill. The tables are reserved but never written
until a client arrives to use them, so an idle daemon holds about 2 MiB and
grows from there. [Performance](#performance) has the measurements.

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

### What it costs the machine

`test/footprint.sh` mounts the share with the OS's own client, moves a gigabyte
through it, and reports what the daemon held and burned while doing it. Both
columns are the same laptop — the Linux one inside a container, which is why its
write figure is an overlay filesystem's and not a disk's.

| | macOS (arm64) | Linux (static musl, arm64) |
|-|-|-|
| binary on disk | 297 KiB | 345 KiB |
| resident, idle | 1.6 MiB | 2.5 MiB |
| resident, one client, 1 GiB moved | 2.5 MiB | 3.2 MiB |
| reserved ceiling | 34 MiB | 34 MiB |
| CPU per GiB read | 200 ms | 140 ms |
| CPU per GiB written | 360 ms | 640 ms |

The gap between 34 MiB reserved and 2.5 MiB held is the whole point of the
fixed-table design, and it is easy to lose. Writing one byte into each of the 32
connection slots at startup — which is all `init` used to do — made the entire
pool resident, because Linux backs an anonymous fault with a 2 MiB huge page and
the slots are a megabyte apart. The daemon started out holding 35 MiB of memory
it was not using. Nothing now touches a connection slot until a client occupies
it.

Syscalls, counted with `strace -c` while serving 256 MiB as 1024 reads of
256 KiB:

```
 47.24    0.048161          47      1024           pread64
 38.83    0.039591          38      1028           write
  6.88    0.007014          13       516           read
  6.77    0.006901          13       516           epoll_pwait
```

Three syscalls per request, and none of them spare: one `pread` to get the data,
one `write` to send it, and one socket read and one `epoll_pwait` shared between
every two requests the client pipelines. There is no `epoll_ctl` in the list at
all — a connection's poller registration is only rewritten when what it is
waiting for actually changes, which for a client that is reading steadily is
never.

### Throughput

Through a real client, macOS `mount_smbfs` over loopback, 200 MB with a warm
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

### The server's own path

`zig build bench -Doptimize=ReleaseFast` runs the real server against a real
share with the real wire format and no socket in between, so what it times is
the part this project can actually make faster.

```
posixfs share
  operation                               ops/sec     throughput
  echo (dispatch floor)                  18944040              -
  create + close                           113320              -
  create+query_info+close (1 frame)        109467              -
  query_info (FileAllInformation)         2183880              -
  query_directory (34 entries)              15309              -
  read 4 KiB                              1920440     7502 MiB/s
  read 64 KiB                              524422    32776 MiB/s
  read 512 KiB                              67985    33992 MiB/s
  write 64 KiB                             191620    11976 MiB/s
  echo, 64 pipelined                     27005705              -
  read 64 KiB, 32 pipelined                469687    29355 MiB/s
  read 64 KiB, signed                       35097     2194 MiB/s
```

Absolute numbers move with the machine and with what else it is doing; run it
yourself. The shape is what matters, and it is stable:

* The protocol layer is not the bottleneck for anything. A read at 32 GiB/s
  through the dispatcher is one `memcpy` away from the memory bandwidth
  ceiling — there is no headroom left to win there.
* Filesystem syscalls dominate metadata operations. A `create + close` costs
  nineteen times what a `query_info` on an already-open handle does, and the
  difference is `openat` and `close`, not anything this code does.
* **Signing costs about 15× on bulk reads.** It is HMAC-SHA256 over every
  byte, and it is what a Windows 11 client asks for by default.
* The `pipelined` rows go through the connection's buffers rather than
  straight into the dispatcher, which is the path a socket takes: framing, the
  input cursor, and the pause and resume of a full output buffer. Pipelining
  buys about 40% on small requests by amortising the per-wakeup work.

Two things deliberately left on the table. `sendfile`/`splice` would remove one
of the two copies on a read, but it cannot sign what it never sees, it cannot be
compounded with anything, and it would need the share adapter to hand out a file
descriptor — which the adapter interface exists specifically to avoid requiring.
And file I/O blocks the one thread: a share backed by something slow stalls
every client for as long as it is slow. Cold reads from a disk are disk-bound,
and the daemon sits idle inside `pread` while they are.

## What it speaks

SMB 2.0.2 and 2.1. NTLMv2 inside SPNEGO or raw, HMAC-SHA256 signing (verified on
every request that claims it, required when the client or `--require-signing`
says so), and compounded requests — which matters, because macOS opens, queries
and closes a file in a single round trip.

Implemented: negotiate, session setup, logoff, tree connect/disconnect, create,
close, flush, read, write, lock, query directory, query info, set info, echo,
cancel, change notify, oplock break, and the two control codes that make a
server-side copy.

A copy inside a share does not leave the machine. A client asks for a key
naming the file it wants to copy from and then asks the server to move the
ranges itself, so four megabytes copied between two files on the same share cost
three small requests and no read or write on the wire at all. Windows and
`smbclient` both use it; macOS asks for the key and then copies by hand anyway,
which is its choice to make.

Change notification is answered the way the protocol means it: a request the
server cannot answer yet is acknowledged with `STATUS_PENDING`, an async id, and
nothing else, and the answer arrives later in a frame of its own. Closing the
directory ends the wait with `STATUS_NOTIFY_CLEANUP` and a `CANCEL` ends it with
`STATUS_CANCELLED`, so a client is never left waiting for something that will
not come. What it sees is every change made **through this server** — created,
written, truncated, renamed and deleted files. A change made directly on the
disk underneath is invisible: the share adapter deliberately exposes no
filesystem to watch, which is what lets a share be an archive or a database view
instead of a directory.

Clients cache. A 2.1 client is offered a lease and an older one a level-II
oplock, both granting the right to keep reading what it has already read — and
both taken back with a break notification the moment another client writes,
truncates, renames or deletes the file. A break needs no acknowledgement,
because nothing is granted that a client would have to hand back first: it drops
what it cached and carries on. A client's own writes never break its own cache,
which is what the lease key is for — every handle a client opens on a file
carries the same one, so the server can tell one client with two handles from
two clients. Both real clients take it up: `mount_smbfs` and the kernel `cifs`
module each ask for a lease and get one.

Byte-range locks are real, not acknowledged and forgotten. A lock belongs to the
handle that took it and is visible to every other handle on the file, including
one another session opened; a read is stopped by an overlapping exclusive lock
and a write by any overlapping lock, both with `STATUS_FILE_LOCK_CONFLICT`. A
request that asks for several ranges gets all of them or none. Locks are dropped
when the handle closes, which is also what happens when a client disappears
mid-edit. The one deviation from MS-SMB2: a request that would have to wait is
refused with `STATUS_LOCK_NOT_GRANTED` instead of being parked, because there is
nowhere in a single-threaded server to park a half-answered request, and a
client told "no" copes better than a client left waiting forever.

Deliberately not implemented, and answered with a clear "no" rather than
silence:

* **SMB 3.x.** The dialect list stops at 2.1. Every 3.x feature a client would
  then expect — CMAC signing, negotiate contexts, preauth integrity, encryption
  — is a correctness cliff rather than an optimisation, and a client offered 2.1
  uses 2.1.
* **Write and handle caching.** Only read caching is granted. Giving a client
  the newest copy of a file means the next reader waits for that client to write
  it back, and giving it the right to keep a handle open means the next opener
  waits for it to close — both are requests parked half-answered, which this
  server has nowhere to put.
* **Every other control code.** DFS referrals, network interface queries,
  pipe transceive and the rest are refused plainly. A client told no falls back
  to doing the work itself, which always works; a client told a half-truth does
  not.
* **Named pipes.** `IPC$` connects and is empty, which
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
zig build test                           # 166 unit and protocol tests
zig build check -Dtarget=x86_64-linux    # type-check another platform's backend
zig build bench -Doptimize=ReleaseFast   # the numbers above
test/integration.sh                      # mount it for real and use it
test/docker-linux.sh                     # Linux: locks, leases, notify, server copy
test/footprint.sh                        # memory and CPU while serving a GiB
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
back. Three of the bugs in this repo's history were only ever visible there: a
missing transport header, a `FileAllInformation` record one byte shorter than
the Linux client accepts, and a startup path that made 35 MiB resident before
the first client connected.

CI runs the same three: unit tests and the mount battery on Linux and macOS, and
`zig build check` across x86_64/aarch64, glibc/musl, both poll backends and a
non-default `Limits` — because Zig only analyzes code it can reach, so a build
that merely succeeds for another target proves very little.

## License

MIT. See [LICENSE](LICENSE).
