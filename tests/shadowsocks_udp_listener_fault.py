"""Verify that an asynchronous listener failure is drained and reported."""
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile

fixture, shim = (pathlib.Path(arg).resolve() for arg in sys.argv[1:3])
with tempfile.TemporaryDirectory(prefix="nexus-udp-listener-fault-") as directory:
    marker = pathlib.Path(directory) / "bad-clock"
    env = os.environ.copy()
    env.update(LD_PRELOAD=str(shim), NEXUS_TEST_BAD_WALL_CLOCK=str(marker))
    for size in (16, 32):
        for mode, family, host in (("normal", socket.AF_INET, "127.0.0.1"),
                                   ("ipv6", socket.AF_INET6, "::1")):
            marker.unlink(missing_ok=True)
            listener = subprocess.Popen([fixture, str(size), "53", mode], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                if not select.select([listener.stdout], [], [], 5)[0]:
                    raise RuntimeError(f"{size}/{mode}: listener did not start")
                port = int(listener.stdout.readline())
                marker.touch()
                _, error = listener.communicate(timeout=5)
                if listener.returncode != 4:
                    raise RuntimeError(f"{size}/{mode}: exit {listener.returncode}: {error}")
                with socket.socket(family, socket.SOCK_DGRAM) as probe:
                    probe.bind((host, port))
            finally:
                if listener.poll() is None:
                    listener.kill()
                    listener.communicate()
print("SS-2022 UDP listener asynchronous failure and drain passed")
