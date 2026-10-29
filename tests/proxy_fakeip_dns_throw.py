"""Inject a DNS receive exception while a real Fake-IP dial owns a pin."""
import os
import pathlib
import socket
import subprocess
import sys
import time

binary = pathlib.Path(sys.argv[1]).resolve()

def exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)

for workers in (1, 2):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.bind(("127.0.0.1", 0))
        dns.settimeout(5)
        env = dict(os.environ, NEXUS_TEST_FAKEIP_DNS_THROW="1")
        proc = subprocess.Popen([str(binary), str(dns.getsockname()[1]), str(workers)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env)
        try:
            port = int(proc.stdout.readline())
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.settimeout(5)
                client.sendall(b"\x05\x01\x00")
                if exact(client, 2) != b"\x05\x00": raise RuntimeError("greeting failed")
                client.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01\x00\x50")
                query, peer = dns.recvfrom(512)
                if query[12:].lower() != b"\x07example\x04test\x00\x00\x01\x00\x01":
                    raise RuntimeError("unexpected DNS request")
                time.sleep(1.2)
                proc.stdin.write("probe\n"); proc.stdin.flush()
                if proc.stdout.readline().strip() != "full": raise RuntimeError("pending dial did not retain pin")
                dns.sendto(query, peer)
                try:
                    if client.recv(1): raise RuntimeError("unexpected reply after DNS exception")
                except ConnectionResetError:
                    pass
                deadline = time.monotonic() + 5
                while True:
                    proc.stdin.write("probe\n"); proc.stdin.flush()
                    status = proc.stdout.readline().strip()
                    if status == "free": break
                    if status != "full" or time.monotonic() >= deadline:
                        raise RuntimeError(f"pin not released after failure: {status}")
                    time.sleep(.02)
                proc.stdin.write("order\n"); proc.stdin.flush()
                if proc.stdout.readline().strip() != "1 0":
                    raise RuntimeError("session released its pin before the dial watcher drained")
            proc.stdin.write("stop\n"); proc.stdin.flush()
            if proc.wait(timeout=5): raise RuntimeError(proc.stderr.read())
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait()
print("FakeIP dial DNS exception drains watcher and releases pin on one and two workers")
