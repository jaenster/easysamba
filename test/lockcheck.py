"""Takes a byte-range lock over the mount and checks a second process cannot.

Run as `lockcheck.py <file>`; prints what the second process saw. Whether the
conflict is decided by the SMB client or by the server, the point of the check
is that a real client's lock and unlock survive the round trip and the file is
still usable afterwards.
"""

import fcntl
import subprocess
import sys

path = sys.argv[1]
is_child = len(sys.argv) > 2

handle = open(path, "r+b")
try:
    fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB, 4, 0)
except OSError:
    print("conflict" if is_child else "the first lock was refused")
    sys.exit(0)

if is_child:
    print("granted")
    sys.exit(0)

second = subprocess.run(
    [sys.executable, __file__, path, "child"], capture_output=True, text=True
)
fcntl.lockf(handle, fcntl.LOCK_UN, 4, 0)
handle.write(b"ok")
print(second.stdout.strip())
