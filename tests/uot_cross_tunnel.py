#!/usr/bin/env python3
"""A reply on one UoT stream cannot use another stream's authorization."""
import base64
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus = pathlib.Path(sys.argv[1]).resolve()
fixture = nexus.with_name("nexus-uot-fault-server")

def exact(sock, size):
    result = b""
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data: raise RuntimeError("unexpected EOF")
        result += data
    return result

for order in ((1, 2), (2, 1)):
    with tempfile.TemporaryDirectory(prefix="nexus-uot-cross-") as directory:
        root = pathlib.Path(directory)
        (root / "key").write_text(base64.b64encode(bytes(range(16))).decode())
        (root / "key").chmod(0o600)
        (root / "second.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
        listeners, peers, pipes = [], [], []
        proxy = None
        try:
            for _ in range(2):
                listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
                listeners.append(listener)
                read_fd, write_fd = os.pipe(); pipes.append(write_fd)
                peers.append(subprocess.Popen([fixture, str(listener.fileno()), "valid", str(read_fd)],
                                              pass_fds=(listener.fileno(), read_fd)))
                os.close(read_fd)
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0)); listen_port = reserved.getsockname()[1]
            (root / "config.kdl").write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={listen_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "first" type="shadowsocks" {{ server host="127.0.0.1" port={listeners[0].getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
outbound "second" type="shadowsocks" {{ server host="127.0.0.1" port={listeners[1].getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ rule-set "second" path="second.kdl" format="kdl"; rule kind="rule-set" value="second" outbound="second"; default-outbound "first"; }}
''')
            proxy = subprocess.Popen([nexus, "run", "--config", root / "config.kdl"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 5
            while True:
                if proxy.poll() is not None: raise RuntimeError(f"proxy exited: {proxy.stderr.read()!r}")
                try: control = socket.create_connection(("127.0.0.1", listen_port), timeout=.2); break
                except OSError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(.02)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                control.settimeout(5); client.settimeout(5); client.bind(("127.0.0.1", 0))
                control.sendall(b"\x05\x01\x00")
                if exact(control, 2) != b"\x05\x00": raise RuntimeError("authentication failed")
                control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                reply = exact(control, 10)
                if reply[:4] != b"\x05\x00\x00\x01": raise RuntimeError("association failed")
                relay = (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], "big"))
                for target in order:
                    header = b"\x00\x00\x00\x01\x7f\x00\x00" + bytes([target]) + b"\x00\x35"
                    client.sendto(header + b"probe", relay)
                    received = client.recvfrom(65535)[0]
                    if received != header + b"good": raise RuntimeError(f"cross-tunnel forged reply: {received!r}")
                client.settimeout(.25)
                try: raise RuntimeError(f"unexpected extra reply: {client.recvfrom(65535)!r}")
                except socket.timeout: pass
                for fd in pipes: os.write(fd, b"x")
                for peer in peers:
                    if peer.wait(timeout=5): raise RuntimeError(f"peer exit {peer.returncode}")
            proxy.terminate(); _, stderr = proxy.communicate(timeout=5)
            if proxy.returncode: raise RuntimeError(f"proxy shutdown: {stderr!r}")
            proxy = None
        finally:
            for fd in pipes: os.close(fd)
            for peer in peers:
                if peer.poll() is None: peer.kill(); peer.wait()
            if proxy and proxy.poll() is None: proxy.terminate(); proxy.communicate(timeout=5)
            for listener in listeners: listener.close()
print("UoT cross-outbound forged replies rejected in both authorization orders")
