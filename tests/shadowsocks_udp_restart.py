"""Exercise listener replacement while retaining one replay owner."""
import pathlib
import socket
import subprocess
import sys

listener = pathlib.Path(sys.argv[1]).resolve()
client = pathlib.Path(sys.argv[2]).resolve()
for size in (16, 32):
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("127.0.0.1", 0))
    dns.settimeout(2)
    server = subprocess.Popen([listener, str(size), str(dns.getsockname()[1]), "restart"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peer = None
    try:
        port = int(server.stdout.readline())
        peer = subprocess.Popen([client, str(port), str(size), "restart"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if peer.stdout.readline().strip() != "ready":
            raise RuntimeError(f"client did not start: {peer.stderr.read()}")
        queries = [dns.recvfrom(512)]
        if any(query[12:20] != b"\x01a\x04test\x00" for query, _ in queries):
            raise RuntimeError("unexpected DNS query")
        replacement = int(server.stdout.readline())
        # Complete the canceled lookup only after the new listener starts.
        for query, source in queries:
            response = bytearray(query)
            response[2:4] = b"\x81\x80"
            if int.from_bytes(query[-4:-2], "big") == 1:
                response[7] = 1
                response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
            dns.sendto(response, source)
        output, errors = peer.communicate(f"{replacement}\n", timeout=3)
        if peer.returncode:
            raise RuntimeError(f"client failed: {peer.returncode}, {output}, {errors}")
        dns.settimeout(0.2)
        try:
            dns.recvfrom(512)
            raise RuntimeError("replayed request triggered DNS")
        except TimeoutError:
            pass
        if server.wait(timeout=5):
            raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
    finally:
        dns.close()
        for process in (peer, server):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
print("SS-2022 UDP listener replacement for both AES methods passed")
