"""Exercise ECS, DNSSEC flags and client-view restoration through the CLI."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upstream.bind(("127.0.0.1", 0))
upstream.settimeout(.2)
listen, proxy = port(), port()
while proxy == listen:
    proxy = port()
observed = []
errors = []
stop = threading.Event()


def serve():
    try:
        while not stop.is_set():
            try:
                request, peer = upstream.recvfrom(65535)
            except TimeoutError:
                continue
            observed.append(request)
            end = 12
            while request[end]:
                end += request[end] + 1
            end += 5
            if request[13:18] == b"retry" and bytes.fromhex("00080007") in request[end:]:
                response = bytearray(request[:end])
                response[2:4] = b"\x81\x85"
                response[10:12] = b"\0\0"
                upstream.sendto(response, peer)
                continue
            response = bytearray(request[:end])
            response[2:4] = b"\x81\x80"
            response[3] |= request[3] & 0x10
            if request[13:18] == b"flags" and request[3] & 0x10:
                response[3] |= 0x20
            response[7] = 1
            response.extend(bytes.fromhex("c00c000100010000003c0004c0000201"))
            response.extend(request[end:])
            upstream.sendto(response, peer)
    except Exception as error:
        errors.append(error)


thread = threading.Thread(target=serve)
thread.start()
with tempfile.TemporaryDirectory(prefix="nexus-ecs-rule-") as directory:
    config = Path(directory) / "config.kdl"
    race = " race=#true" if sys.argv[2:] == ["race"] else ""
    config.write_text(f'''schema-version 1
role "client"
dns {{
  listen host="127.0.0.1" port={listen}
  server "a" type="udp" host="127.0.0.1" port={upstream.getsockname()[1]}
  rule domain="set.test" action="route" server="a" client-subnet="198.51.100.129/24"
  rule domain="remove.test" action="route" server="a" remove-client-subnet=#true
  rule domain="eval.test" action="evaluate" server="a" client-subnet="198.51.100.0/24"
  rule domain="eval.test" action="respond" match-response=#true
  rule domain="named.test" action="evaluate" server="a" tag="first" client-subnet="198.51.100.0/24"
  rule domain="named.test" action="evaluate" server="a" tag="second" client-subnet="203.0.113.0/24"
  rule domain="named.test" action="respond" match-response="first"
  rule domain="inherit.test" action="route-options" client-subnet="198.51.100.0/24"
  rule domain="inherit.test" action="evaluate" server="a" client-subnet="203.0.113.0/24"
  rule domain="inherit.test" action="route" server="a" match-response=#true
  rule domain="removed.test" action="route-options" client-subnet="198.51.100.0/24"
  rule domain="removed.test" action="route" server="a" remove-client-subnet=#true
  rule domain="retry.test" action="route" server="a" client-subnet="198.51.100.0/24"
  rule domain="flags.test" query-class="IN" query-type="A" action="evaluate" server="a" tag="flags"
  rule domain="flags.test" query-checking-disabled=#true match-response="flags" response-authenticated-data=#false action="reject"{race}
  rule domain="flags.test" query-checking-disabled=#false match-response="flags" response-authenticated-data=#true action="reject"{race}
  rule domain="flags.test" query-checking-disabled=#true match-response="flags" response-authenticated-data=#true action="respond"{race}
  rule domain="flags.test" query-checking-disabled=#false match-response="flags" response-authenticated-data=#false action="respond"{race}
  rule domain="flags.test" action="reject"
  rule domain="ad-gate.test" query-authenticated-data=#true action="route" server="a"
  rule domain="ad-gate.test" query-authenticated-data=#false action="reject"
}}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    process = subprocess.Popen([str(Path(sys.argv[1]).resolve()), "run", "--config", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
            raise RuntimeError("listener did not start")
        client_ecs = bytes.fromhex("0008000700011800c00002")
        upstream_ecs = bytes.fromhex("0008000700011800c63364")
        restored_ecs = bytes.fromhex("0008000700011818c00002")
        def ask(name, ident, edns, extra=False, cd=False, do=True, ecs=True, ad=False, rcode=0):
            question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0\0\1\0\1"
            flags = 0x0100 | (0x10 if cd or extra else 0) | (0x20 if ad else 0)
            request = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, int(edns)) + question
            if edns:
                options = (client_ecs if ecs else b"") + (bytes.fromhex("fde80004c0ff1234") if extra else b"")
                request += struct.pack("!BHHIH", 0, 41, 1232, 0x8000 if do else 0, len(options)) + options
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(request, ("127.0.0.1", listen))
                response, _ = sock.recvfrom(4096)
            assert response[:2] == request[:2] and response[3] & 15 == rcode, response.hex()
            return response
        response = ask("set.test", 1, True)
        assert upstream_ecs in observed[-1] and restored_ecs in response and upstream_ecs not in response
        response = ask("set.test", 2, False)
        assert upstream_ecs in observed[-1] and response[10:12] == b"\0\0" and upstream_ecs not in response
        response = ask("remove.test", 3, True)
        assert client_ecs not in observed[-1] and restored_ecs in response
        response = ask("eval.test", 4, True)
        assert upstream_ecs in observed[-1] and restored_ecs in response and upstream_ecs not in response
        count = len(observed)
        response = ask("named.test", 11, True)
        assert len(observed) == count + 2 and upstream_ecs in observed[-2] and bytes.fromhex("0008000700011800cb0071") in observed[-1]
        assert restored_ecs in response and upstream_ecs not in response and bytes.fromhex("0008000700011800cb0071") not in response
        count = len(observed)
        response = ask("inherit.test", 5, True)
        assert len(observed) == count + 2 and bytes.fromhex("0008000700011800cb0071") in observed[-2] and upstream_ecs in observed[-1]
        assert restored_ecs in response and upstream_ecs not in response
        response = ask("removed.test", 6, True)
        assert client_ecs not in observed[-1] and upstream_ecs not in observed[-1] and restored_ecs in response
        count = len(observed)
        response = ask("retry.test", 7, True)
        assert len(observed) == count + 2 and upstream_ecs in observed[-2] and bytes.fromhex("00080007") not in observed[-1]
        assert restored_ecs in response and upstream_ecs not in response
        response = ask("retry.test", 8, True)
        assert len(observed) == count + 2 and restored_ecs in response
        count = len(observed)
        for ident in (9, 10):
            response = ask("set.test", ident, True, extra=True)
            assert response[3] & 0x10 and bytes.fromhex("fde80004c0ff1234") in response and restored_ecs in response
            assert bytes.fromhex("fde80004c0ff1234") in observed[-1] and upstream_ecs in observed[-1]
            assert b"\x00\x00\x80\x00" in response
        assert len(observed) == count + 2
        count = len(observed)
        for ident, cd, do in ((12, False, False), (13, True, False), (14, False, True),
                              (15, False, False), (16, True, False), (17, False, True)):
            response = ask("flags.test", ident, True, cd=cd, do=do, ecs=False)
            assert bool(response[3] & 0x20) == cd and bool(response[3] & 0x10) == cd
        for ident in (18, 19):
            response = ask("flags.test", ident, True, do=False, ecs=False, ad=True)
            assert not response[3] & 0x20
        assert len(observed) == count + 4 and observed[-1][3] & 0x20, len(observed) - count
        count = len(observed)
        for ident in (20, 22):
            ask("ad-gate.test", ident, False, rcode=5)
            response = ask("ad-gate.test", ident + 1, False, ad=True)
            assert not response[3] & 0x20, response.hex()
        assert len(observed) == count + 1 and observed[-1][3] & 0x20
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=5)
        stop.set()
        thread.join(timeout=3)
        upstream.close()
        if process.returncode:
            raise RuntimeError(stderr.decode())
assert not errors and not thread.is_alive(), errors
print(f"DNS ECS, CD and AD policy with cache isolation passed ({'race' if race else 'serial'})")
