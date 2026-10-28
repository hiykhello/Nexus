"""Verify same-key listeners share replay and route responses by ingress."""
import pathlib
import subprocess
import sys

listener = pathlib.Path(sys.argv[1]).resolve()
client = pathlib.Path(sys.argv[2]).resolve()
for mode in ("multi", "multi6"):
    for size in (16, 32):
        server = subprocess.Popen([listener, str(size), "53", mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            first, second = int(server.stdout.readline()), int(server.stdout.readline())
            if first == second and mode == "multi":
                raise RuntimeError("listeners share an unexpected port")
            subprocess.run([client, str(first), str(size), mode, str(second)], check=True, timeout=3)
            if server.wait(timeout=5):
                raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()
print("SS-2022 UDP IPv4 and mixed-family listeners for both AES methods passed")
