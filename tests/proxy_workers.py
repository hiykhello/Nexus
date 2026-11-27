"""Exercise configured worker count through the real CLI."""
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

binary = Path(sys.argv[1]).resolve()
with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
config = f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{
    listen host="127.0.0.1" port={port}
    authentication "none"
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
'''
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "config.kdl"
    path.write_text(config)
    process = subprocess.Popen([binary, "run", "--config", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                break
            except OSError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("proxy did not start")
                time.sleep(0.02)
        client.settimeout(2)
        client.sendall(b"\x05\x01\x00")
        if client.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        process.send_signal(signal.SIGTERM)
        _, err = process.communicate(timeout=5)
        if client.recv(1) != b"":
            raise RuntimeError("active client was not closed")
        client.close()
        if process.returncode:
            raise RuntimeError(f"proxy exit {process.returncode}: {err!r}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
print("configured two-worker CLI starts, serves SOCKS and stops")
