"""Two independent Corosio contexts share a loopback TCP port."""
import socket
import subprocess
import sys
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
mode = sys.argv[2] if len(sys.argv) > 2 else "epoll"
process = subprocess.Popen([binary, mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
try:
    port = int(process.stdout.readline())
    counts = {b"A": 0, b"B": 0}
    for _ in range(128):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            response = client.recv(1)
            if response not in counts:
                raise RuntimeError(f"unexpected response {response!r}")
            counts[response] += 1
    process.stdin.write("stop\n")
    process.stdin.flush()
    if process.wait(timeout=5):
        raise RuntimeError(f"listener fixture exit {process.returncode}")
    print(f"{mode} reuseport loopback responses: {counts}")
finally:
    if process.poll() is None:
        process.kill()
        process.wait()
