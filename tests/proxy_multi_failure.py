"""Inject one accept failure into a configured listener and verify shutdown."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
fault = pathlib.Path(sys.argv[2]).resolve()


def reserve():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock


for workers in (1, 2):
    with reserve() as first, reserve() as second:
        ports = [first.getsockname()[1], second.getsockname()[1]]
    with tempfile.TemporaryDirectory() as directory:
        config = pathlib.Path(directory) / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbounds {{
  socks5 "first" {{ listen host="127.0.0.1" port={ports[0]}; authentication "none"; }}
  socks5 "second" {{ listen host="127.0.0.1" port={ports[1]}; authentication "none"; }}
}}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        env = os.environ.copy()
        env.update(LD_PRELOAD=str(fault), NEXUS_START_FAULT="accept-target", NEXUS_FAULT_PORT=str(ports[1]))
        process = subprocess.Popen([binary, "run", "--config", config], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        client = None
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"proxy exited before connection: {process.stderr.read()!r}")
                try:
                    client = socket.create_connection(("127.0.0.1", ports[0]), timeout=1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
            client.settimeout(5)
            client.sendall(b"\x05")
            with socket.create_connection(("127.0.0.1", ports[1]), timeout=2):
                pass
            process.wait(timeout=5)
            stderr = process.stderr.read()
            if process.returncode == 0 or b"proxy-start-fault-injected" not in stderr or b"accept failed" not in stderr:
                raise RuntimeError(f"failure not reported: {process.returncode}, {stderr!r}")
            try:
                if client.recv(1):
                    raise RuntimeError("pending session survived failure")
            except ConnectionResetError:
                pass
            for port in ports:
                with socket.socket() as check:
                    check.settimeout(1)
                    if check.connect_ex(("127.0.0.1", port)) == 0:
                        raise RuntimeError("listener survived process shutdown")
        finally:
            if client:
                client.close()
            if process.poll() is None:
                process.kill()
                process.wait()
print("multi-inbound accept failure stopped all listeners and sessions")
