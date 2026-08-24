#!/bin/sh
# End-to-end test against a real SMB client: mounts the share, exercises it, and
# checks the bytes that come back.
#
#   test/integration.sh [--keep]
#
# macOS uses mount_smbfs; Linux uses the kernel cifs client and needs root.
# Everything happens in a scratch directory under /tmp and on port 4445.
set -eu

port=4445
root=${TMPDIR:-/tmp}/easysamba-integration
# Override with DAEMON= to test a binary built elsewhere (see docker-linux.sh).
daemon=${DAEMON:-zig-out/bin/easysambad}
user=alice
pass=hunter2
keep=${1:-}
failures=0

say() { printf '%s\n' "$*"; }
ok()  { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; failures=$((failures + 1)); }
check() { if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (got '$1', want '$2')"; fi; }

cleanup() {
    [ -n "${mounted:-}" ] && umount "$root/mnt" 2>/dev/null || true
    [ -n "${daemon_pid:-}" ] && kill "$daemon_pid" 2>/dev/null || true
    [ "$keep" = "--keep" ] || rm -rf "$root"
}
trap cleanup EXIT

[ -x "$daemon" ] || { say "build it first: zig build -Doptimize=ReleaseSafe"; exit 1; }

rm -rf "$root"
mkdir -p "$root/share/docs" "$root/mnt"
printf 'hello from easysamba\n' > "$root/share/hello.txt"
printf 'nested\n' > "$root/share/docs/nested.txt"
dd if=/dev/urandom of="$root/big.bin" bs=1048576 count=64 2>/dev/null
cp "$root/big.bin" "$root/share/big.bin"

say "starting the daemon on port $port"
"$daemon" --port "$port" --bind 127.0.0.1 \
    --share files="$root/share" --share-ro readonly="$root/share" \
    --user "$user:$pass" --user reader:"$pass":ro \
    --log info > "$root/daemon.log" 2>&1 &
daemon_pid=$!
sleep 1
kill -0 "$daemon_pid" 2>/dev/null || { say "daemon exited:"; cat "$root/daemon.log"; exit 1; }

case "$(uname -s)" in
Darwin)
    mount_smbfs -N "//$user:$pass@127.0.0.1:$port/files" "$root/mnt"
    ;;
Linux)
    [ "$(id -u)" = 0 ] || { say "the Linux cifs client needs root"; exit 1; }
    mount -t cifs "//127.0.0.1/files" "$root/mnt" \
        -o "username=$user,password=$pass,port=$port,vers=2.1"
    ;;
*)
    say "no mount command known for $(uname -s)"; exit 1
    ;;
esac
mounted=1
say "mounted; running the battery"

check "$(cat "$root/mnt/hello.txt")" "hello from easysamba" "read a file"
check "$(cat "$root/mnt/docs/nested.txt")" "nested" "read through a subdirectory"
check "$(ls "$root/mnt" | tr '\n' ' ')" "big.bin docs hello.txt " "list the root"

printf 'written over smb\n' > "$root/mnt/written.txt"
check "$(cat "$root/share/written.txt")" "written over smb" "write a new file"

printf 'appended\n' >> "$root/mnt/written.txt"
check "$(wc -l < "$root/mnt/written.txt" | tr -d ' ')" "2" "append to a file"

mkdir -p "$root/mnt/made/deeper"
check "$([ -d "$root/share/made/deeper" ] && echo yes)" "yes" "create directories"

mv "$root/mnt/written.txt" "$root/mnt/made/moved.txt"
check "$([ -f "$root/share/made/moved.txt" ] && echo yes)" "yes" "rename across directories"

rm "$root/mnt/made/moved.txt"
rmdir "$root/mnt/made/deeper" "$root/mnt/made"
check "$([ -e "$root/share/made" ] && echo yes || echo no)" "no" "delete files and directories"

cp "$root/mnt/big.bin" "$root/out.bin"
check "$(cksum < "$root/out.bin")" "$(cksum < "$root/big.bin")" "read 64 MiB unchanged"

cp "$root/big.bin" "$root/mnt/uploaded.bin"
check "$(cksum < "$root/share/uploaded.bin")" "$(cksum < "$root/big.bin")" "write 64 MiB unchanged"
rm "$root/mnt/uploaded.bin"

check "$(dd if="$root/mnt/big.bin" bs=1024 skip=1000 count=1 2>/dev/null | cksum)" \
      "$(dd if="$root/big.bin"     bs=1024 skip=1000 count=1 2>/dev/null | cksum)" \
      "read from the middle of a file"

check "$(df -P "$root/mnt" | awk 'NR==2 && $2 > 0 {print "yes"}')" "yes" "report free space"

say "checking what must NOT work"
umount "$root/mnt"; mounted=

case "$(uname -s)" in
Darwin)
    if mount_smbfs -N "//$user:wrongpassword@127.0.0.1:$port/files" "$root/mnt" 2>/dev/null; then
        bad "a wrong password was accepted"; umount "$root/mnt"
    else
        ok "a wrong password is refused"
    fi
    mount_smbfs -N "//reader:$pass@127.0.0.1:$port/readonly" "$root/mnt"
    ;;
Linux)
    if mount -t cifs "//127.0.0.1/files" "$root/mnt" \
        -o "username=$user,password=wrongpassword,port=$port,vers=2.1" 2>/dev/null; then
        bad "a wrong password was accepted"; umount "$root/mnt"
    else
        ok "a wrong password is refused"
    fi
    mount -t cifs "//127.0.0.1/readonly" "$root/mnt" \
        -o "username=reader,password=$pass,port=$port,vers=2.1"
    ;;
esac
mounted=1

check "$(cat "$root/mnt/hello.txt")" "hello from easysamba" "a read-only account can read"
if (printf 'nope\n' > "$root/mnt/denied.txt") 2>/dev/null; then
    bad "a read-only account wrote to a read-only share"
else
    ok "a read-only account cannot write"
fi

say ""
if [ "$failures" -eq 0 ]; then
    say "all checks passed"
else
    say "$failures check(s) failed"
    say "daemon log:"
    sed 's/^/  /' "$root/daemon.log"
fi
exit "$failures"
