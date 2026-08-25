#!/bin/sh
# What the daemon costs the machine: how much memory it holds while idle, how
# much more it holds after moving real data, and how much CPU it spends per
# gigabyte served.
#
#   test/footprint.sh
#
# Mounts the share with the OS's own client, so the numbers include everything
# between the client and the disk. macOS uses mount_smbfs; Linux uses the kernel
# cifs client and needs root. Override the binary with DAEMON=.
set -eu

port=4447
root=${TMPDIR:-/tmp}/easysamba-footprint
daemon=${DAEMON:-zig-out/bin/easysambad}
size_mib=${SIZE_MIB:-512}

cleanup() {
    [ -n "${mounted:-}" ] && umount "$root/mnt" 2>/dev/null || true
    if [ -n "${daemon_pid:-}" ]; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
    rm -rf "$root"
}
trap cleanup EXIT

[ -x "$daemon" ] || { echo "build it first: zig build -Doptimize=ReleaseFast"; exit 1; }

# Resident kilobytes, and the CPU centiseconds the process has burned.
if [ -d /proc ]; then
    rss() { awk '/VmRSS/{print $2}' /proc/"$daemon_pid"/status; }
    cpu() { awk '{print ($14 + $15) * 10}' /proc/"$daemon_pid"/stat; }
else
    rss() { ps -o rss= -p "$daemon_pid" | tr -d ' '; }
    # macOS reports the times as [dd-]hh:mm:ss.ff.
    cpu() {
        ps -o utime=,stime= -p "$daemon_pid" | awk '{
            t = 0
            for (i = 1; i <= NF; i++) {
                split($i, p, ":")
                t += (p[1] * 60 + p[2]) * 1000
            }
            print int(t)
        }'
    }
fi

report() { printf '  %-28s %s\n' "$1" "$2"; }
mib() { awk -v kb="$1" 'BEGIN { printf "%.1f MiB", kb / 1024 }'; }

rm -rf "$root"
mkdir -p "$root/share" "$root/mnt"
dd if=/dev/zero of="$root/share/big.bin" bs=1048576 count="$size_mib" 2>/dev/null

"$daemon" --port "$port" --bind 127.0.0.1 --share files="$root/share" \
    --user alice:hunter2 --log warn > "$root/daemon.log" 2>&1 &
daemon_pid=$!
sleep 1
kill -0 "$daemon_pid" 2>/dev/null || { cat "$root/daemon.log"; exit 1; }

echo "footprint"
report "binary on disk" "$(($(wc -c < "$daemon") / 1024)) KiB"
report "resident, idle" "$(mib "$(rss)")"

if [ "$(uname)" = "Darwin" ]; then
    mount_smbfs -N "//alice:hunter2@127.0.0.1:$port/files" "$root/mnt"
else
    mount -t cifs "//127.0.0.1/files" "$root/mnt" \
        -o username=alice,password=hunter2,port="$port",vers=2.1
fi
mounted=1
report "resident, one client" "$(mib "$(rss)")"

echo
echo "throughput"
# dd's own summary line rather than a shell timer: `date` has no sub-second
# resolution on either platform, and a gigabyte over loopback takes well under
# a second.
before_cpu=$(cpu)
rate=$(dd if="$root/mnt/big.bin" of=/dev/null bs=1048576 2>&1 | tail -1)
after_cpu=$(cpu)
report "read $size_mib MiB" "$rate"
report "server cpu" "$(((after_cpu - before_cpu) * 1024 / size_mib)) ms per GiB"

before_cpu=$(cpu)
rate=$(dd if=/dev/zero of="$root/mnt/out.bin" bs=1048576 count="$size_mib" 2>&1 | tail -1)
after_cpu=$(cpu)
report "write $size_mib MiB" "$rate"
report "server cpu" "$(((after_cpu - before_cpu) * 1024 / size_mib)) ms per GiB"

echo
report "resident, after $((size_mib * 2)) MiB" "$(mib "$(rss)")"
