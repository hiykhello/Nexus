"""Check DNS TTL rule inheritance and override through the real CLI."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

binary = Path(sys.argv[1]).resolve()

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upstream.bind(("127.0.0.1", 0))
upstream.settimeout(5)
listen, proxy = free_port(), free_port()
while proxy == listen:
    proxy = free_port()
config = f'''schema-version 1
role "client"
dns {{
  listen host="127.0.0.1" port={listen}
  server "a" type="udp" host="127.0.0.1" port={upstream.getsockname()[1]}
  rule action="route-options" rewrite-ttl=7
  rule domain="route.test" action="route" server="a" rewrite-ttl=0
  rule domain="evaluate.test" action="evaluate" server="a" rewrite-ttl=3
  rule domain="evaluate.test" action="respond" match-response=#true response-record-ttl-min=3 response-record-ttl-max=3
  rule domain="after.test" action="evaluate" server="a" rewrite-ttl=3
  rule domain="after.test" action="route-options" rewrite-ttl=9
  rule domain="after.test" action="respond" match-response=#true response-record-ttl-min=3 response-record-ttl-max=3
  rule domain="synthetic.test" action="predefined" {{ record section="answer" name="@" type=1 address="192.0.2.1" ttl=60; }}
}}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
'''
failures = []
def answer():
    try:
        for _ in range(3):
            request, peer = upstream.recvfrom(65535)
            # Queries in this fixture have a single uncompressed question.
            end = 12
            while request[end]:
                end += request[end] + 1
            end += 5
            response = bytearray(request[:end])
            response[2:4] = b"\x81\x80"
            response[6:8] = b"\x00\x01"
            response[10:12] = b"\x00\x01" if len(request) > end else b"\x00\x00"
            response.extend(bytes.fromhex("c00c000100010000003c0004c0000201"))
            if len(request) > end:
                response.extend(bytes.fromhex("00002904d0000080000000"))
            upstream.sendto(response, peer)
    except Exception as error:
        failures.append(error)

def query(name, edns=False):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    question = labels + b"\x00\x01\x00\x01"
    header = bytes.fromhex("123401000001000000000001" if edns else "123401000001000000000000")
    opt = bytes.fromhex("00002904d0000080000000") if edns else b""
    return header + question + opt, len(header + question)

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "config.kdl"
    path.write_text(config)
    process = subprocess.Popen([str(binary), "run", "--config", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    worker = threading.Thread(target=answer)
    worker.start()
    try:
        for _ in range(80):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", listen), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("DNS listener failed to start")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(4)
            for name, expected, edns in (("route.test", 0, True), ("evaluate.test", 3, False), ("after.test", 9, False), ("synthetic.test", 7, False)):
                request, offset = query(name, edns)
                client.sendto(request, ("127.0.0.1", listen))
                response, _ = client.recvfrom(4096)
                assert response[:2] == request[:2] and response[3] & 15 == 0, response.hex()
                assert struct.unpack_from("!I", response, offset + 6)[0] == expected, response.hex()
                if edns:
                    assert response[-11:] == bytes.fromhex("00002904d0000080000000"), response.hex()
    finally:
        process.terminate()
        _, err = process.communicate(timeout=8)
        worker.join(timeout=6)
        upstream.close()
        if process.returncode:
            raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
    assert not worker.is_alive() and not failures, failures
print("DNS TTL route override, evaluated and synthetic responses passed")
