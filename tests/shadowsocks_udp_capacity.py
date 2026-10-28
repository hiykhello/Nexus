"""Verify listener session limit with authenticated loopback clients."""
import pathlib
import subprocess
import sys

listener = pathlib.Path(sys.argv[1]).resolve()
client = pathlib.Path(sys.argv[2]).resolve()
for size in (16, 32):
    server = subprocess.Popen([listener, str(size), "53", "capacity"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = int(server.stdout.readline())
        subprocess.run([client, str(port), str(size), "capacity"], check=True, timeout=3)
        if server.wait(timeout=5) != 0:
            raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()
print("SS-2022 UDP listener capacity and stop for both AES methods passed")
