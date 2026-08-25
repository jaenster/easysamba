#!/bin/sh
# Runs the integration test on Linux, in a container, against both SMB clients:
# the kernel's cifs module and smbclient. Cross-compiles a static binary first,
# so it also proves the epoll backend works — which cannot be exercised from a
# macOS host any other way.
#
#   test/docker-linux.sh
#
# Needs docker. --privileged is for mount(8), not for the server.
set -eu

arch=$(uname -m)
case "$arch" in
    arm64|aarch64) target=aarch64-linux-musl; platform=linux/arm64 ;;
    x86_64|amd64)  target=x86_64-linux-musl;  platform=linux/amd64 ;;
    *) echo "unknown architecture $arch"; exit 1 ;;
esac

echo "cross-compiling for $target"
zig build -Doptimize=ReleaseSafe -Dtarget="$target" --prefix zig-out/"$target"

cat > /tmp/easysamba-docker-test.sh <<'INNER'
set -eu
apk add --no-cache cifs-utils samba-client python3 >/dev/null 2>&1
cd /work

echo "=== kernel cifs client ==="
DAEMON=/easysambad sh test/integration.sh

echo
echo "=== smbclient ==="
mkdir -p /tmp/smbshare && echo "smbclient sees this" > /tmp/smbshare/file.txt
/easysambad --port 4446 --bind 127.0.0.1 \
    --share files=/tmp/smbshare --user alice:hunter2 --log warn &
sleep 1
smbclient //127.0.0.1/files -U alice%hunter2 -p 4446 -m SMB2 -c 'ls; get file.txt /tmp/got.txt; put /etc/hostname up.txt; ls; rm up.txt' \
    | sed 's/^/  /'
grep -q "smbclient sees this" /tmp/got.txt && echo "  ok    smbclient round trip"
smbclient //127.0.0.1/files -U alice%wrongpass -p 4446 -m SMB2 -c 'ls' 2>&1 \
    | grep -q NT_STATUS_LOGON_FAILURE && echo "  ok    smbclient wrong password refused"

echo
echo "=== byte-range locks ==="
# The kernel cifs client sends these for real; macOS answers advisory locks
# itself with ENOTSUP and never puts them on the wire, so this is the only
# place a lock taken by an operating system reaches the server.
mkdir -p /tmp/lockmnt && printf 'hello lock test\n' > /tmp/smbshare/locked.txt
mount -t cifs //127.0.0.1/files /tmp/lockmnt \
    -o "username=alice,password=hunter2,port=4446,vers=2.1,actimeo=0"
result=$(python3 /work/test/lockcheck.py /tmp/lockmnt/locked.txt)
[ "$result" = "conflict" ] \
    && echo "  ok    a second process is refused the locked range" \
    || echo "  FAIL  second process saw: $result"
umount /tmp/lockmnt

echo
echo "=== leases ==="
# The point of a lease is that the client stops asking. Metadata caching is
# turned up to a minute so that nothing but a break from the server can make
# the client notice a change -- if the break never arrives, or arrives in a
# shape the client throws away, it keeps serving the old contents and this
# fails.
printf 'before\n' > /tmp/smbshare/leased.txt
printf 'after\n' > /tmp/second.txt
/easysambad --port 4447 --bind 127.0.0.1 \
    --share files=/tmp/smbshare --user alice:hunter2 --log debug > /tmp/lease.log 2>&1 &
sleep 1
mkdir -p /tmp/leasemnt
mount -t cifs //127.0.0.1/files /tmp/leasemnt \
    -o "username=alice,password=hunter2,port=4447,vers=2.1"

# Something has to hold the file open, or the client hands the lease back as
# soon as the read finishes and there is nothing left to break.
sleep 30 < /tmp/leasemnt/leased.txt &
holder=$!
sleep 1
[ "$(cat /tmp/leasemnt/leased.txt)" = "before" ] && echo "  ok    the leased file reads"
grep -q "granted on" /tmp/lease.log \
    && echo "  ok    the client asked for a lease and got one" \
    || echo "  FAIL  no lease was granted"

smbclient //127.0.0.1/files -U alice%hunter2 -p 4447 -m SMB2 \
    -c 'put /tmp/second.txt leased.txt' >/dev/null 2>&1
sleep 1
grep -q "break sent" /tmp/lease.log \
    && echo "  ok    the server broke the lease when another client wrote" \
    || echo "  FAIL  no break was sent"
seen=$(cat /tmp/leasemnt/leased.txt)
[ "$seen" = "after" ] \
    && echo "  ok    the client dropped what it had cached" \
    || echo "  FAIL  the client is still serving: $seen"
kill $holder 2>/dev/null || true
umount /tmp/leasemnt
INNER

docker run --rm --privileged --platform "$platform" \
    -v "$(pwd)":/work \
    -v "$(pwd)/zig-out/$target/bin/easysambad":/easysambad:ro \
    -v /tmp/easysamba-docker-test.sh:/test.sh:ro \
    alpine:3.20 sh /test.sh
