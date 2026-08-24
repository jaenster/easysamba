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
apk add --no-cache cifs-utils samba-client >/dev/null 2>&1
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
INNER

docker run --rm --privileged --platform "$platform" \
    -v "$(pwd)":/work \
    -v "$(pwd)/zig-out/$target/bin/easysambad":/easysambad:ro \
    -v /tmp/easysamba-docker-test.sh:/test.sh:ro \
    alpine:3.20 sh /test.sh
