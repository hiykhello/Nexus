"""Run the kernel TCP/TUN interop fixture in a disposable network namespace."""
import fcntl
import os
import pathlib
import struct
import subprocess
import sys

binary = str(pathlib.Path(sys.argv[1]).resolve())
if len(sys.argv) == 2:
    parent_net = str(os.stat('/proc/self/ns/net').st_ino)
    subprocess.run(["unshare", "-Urn", sys.executable, __file__, binary, parent_net], check=True, timeout=90)
else:
    if os.stat('/proc/self/ns/net').st_ino == int(sys.argv[2]):
        raise RuntimeError('fixture must run in a separate network namespace')
    for family, mode in ((family, mode) for family in (4, 6) for mode in ("normal", "loss", "fin-loss")):
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", b"nx-test", 0x0001 | 0x1000))
            subprocess.run(["ip", "addr", "add", "10.77.0.1/24", "dev", "nx-test"], check=True)
            subprocess.run(["ip", "-6", "addr", "add", "fd77::1/64", "dev", "nx-test", "nodad"], check=True)
            subprocess.run(["ip", "link", "set", "nx-test", "up"], check=True)
            subprocess.run([binary, str(fd), mode, str(family)], pass_fds=(fd,), check=True, timeout=20)
        finally:
            os.close(fd)
