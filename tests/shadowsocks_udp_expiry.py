"""Verify timer-driven session expiry and quota recovery over real time."""
import concurrent.futures
import pathlib
import subprocess
import sys

listener = pathlib.Path(sys.argv[1]).resolve()
client = pathlib.Path(sys.argv[2]).resolve()

def check(size):
    server = subprocess.Popen([listener, str(size), "53", "expiry"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = int(server.stdout.readline())
        subprocess.run([client, str(port), str(size), "expiry"], check=True, timeout=66)
        if server.wait(timeout=6):
            raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    list(pool.map(check, (16, 32)))
print("SS-2022 UDP timer-driven expiry for both AES methods passed")
