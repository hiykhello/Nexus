"""Exercise ECS rule routing on proxy TCP and Shadowsocks UDP."""
import base64
import concurrent.futures
import contextlib
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import Echo, datagram_request, free_port, nexus_process, question, ss_client, stream_request

binary = pathlib.Path(sys.argv[1]).resolve()
local = "--local" in sys.argv
if local and "--inside" not in sys.argv:
    subprocess.run(["unshare", "-Urnm", sys.executable, __file__, str(binary), "--local", "--inside"], check=True)
    sys.exit(0)
if local:
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.2", 53) if local else ("127.0.0.1", 0))
sock.settimeout(.2)
seen, errors, stop = [], [], threading.Event()


def serve():
    try:
        while not stop.is_set():
            try:
                packet, peer = sock.recvfrom(65535)
            except TimeoutError:
                continue
            name, kind, end = question(packet)
            seen.append((name, kind, packet[end:]))
            if name.startswith("hold."):
                continue
            if name.startswith(("parallel.", "parallel-eval.")):
                time.sleep(.12)
            if name in ("bad.test", "formerr.test"):
                if name == "bad.test":
                    options = bytearray(packet[end:]);options[-1] ^= 1
                    answer = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 1) + packet[12:end] + options
                else:
                    answer = packet[:2] + struct.pack("!HHHHH", 0x8181, 1, 0, 0, 0) + packet[12:end]
                sock.sendto(answer, peer)
                continue
            if name == "negative.search.test":
                authority = b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(16) + struct.pack("!I", 60)
                answer = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 1, int(len(packet)>end)) + packet[12:end] + authority + packet[end:]
                sock.sendto(answer, peer)
                continue
            address = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, "127.0.0.1" if kind == 1 else "::1")
            answer = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, int(len(packet)>end)) + packet[12:end]
            if name == "alias.test":
                target = b"\x06target\x04test\0"
                answer += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target + packet[end:]
            else:
                answer += b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(address)) + address + packet[end:]
            sock.sendto(answer, peer)
    except Exception as error:
        errors.append(error)


worker = threading.Thread(target=serve)
worker.start()
try:
    with tempfile.TemporaryDirectory(prefix="nexus-ecs-proxy-") as directory, Echo() as origin:
        root = pathlib.Path(directory)
        key = bytes(range(16))
        key_file = root / "key"
        key_file.write_text(base64.b64encode(key).decode() + "\n")
        key_file.chmod(0o600)
        if local:
            resolv, hosts = root / "resolv", root / "hosts"
            resolv.write_text("nameserver 127.0.0.2\nsearch search.test\noptions timeout:3 attempts:1\n")
            hosts.write_text("")
            for source, target in ((resolv, "/etc/resolv.conf"), (hosts, "/etc/hosts")):
                subprocess.run(["mount", "--bind", str(source), target], check=True)
        front, ss_port = free_port(), free_port()
        config = root / "config.kdl"
        server = 'server "a" type="local"' if local else f'server "a" type="udp" host="127.0.0.1" port={sock.getsockname()[1]}'
        config.write_text(f'''schema-version 1
role "server"
inbounds {{
 mixed "in" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_file}"; }}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{
 {server}
 rule domain="one.test" action="route-options" client-subnet="198.51.100.1/24"
 rule domain="two.test" action="evaluate" server="a" client-subnet="203.0.113.1/24"
 rule domain="two.test" action="respond" match-response=#true
 rule domain="split.test" inbound="ss" action="route" server="a" client-subnet="198.51.100.0/24"
 rule domain="split.test" inbound="in" action="route" server="a" client-subnet="203.0.113.0/24"
 rule domain="split-eval.test" inbound="ss" action="evaluate" server="a" client-subnet="198.51.100.0/24"
 rule domain="split-eval.test" inbound="in" action="evaluate" server="a" client-subnet="203.0.113.0/24"
 rule domain="split-eval.test" action="respond" match-response=#true
 rule domain="short" action="route-options" client-subnet="198.51.100.0/24"
 rule domain="negative" action="route-options" client-subnet="198.51.100.0/24"
 rule domain="hold.test" action="route-options" client-subnet="198.51.100.0/24"
 rule domain="alias.test" action="evaluate" server="a" client-subnet="203.0.113.0/24"
 rule domain="alias.test" action="respond" match-response=#true
 rule domain="bad.test" action="route" server="a" client-subnet="203.0.113.0/24"
 rule domain="formerr.test" action="route" server="a" client-subnet="203.0.113.0/24"
 rule domain="parallel.test" action="route" server="a" client-subnet="198.51.100.0/24"
 rule domain="parallel-eval.test" action="evaluate" server="a" client-subnet="198.51.100.0/24"
 rule domain="parallel-eval.test" action="respond" match-response=#true
 rule domain="host.test" action="evaluate" server="a" client-subnet="198.51.100.0/24"
 rule domain="host.test" action="respond" match-response=#true
 final "a"
}}
''')
        with nexus_process(binary, config, 2) as process, contextlib.ExitStack() as stack:
            client, relay = stack.enter_context(ss_client(root, ss_port, key))
            for name in ("one.test", "two.test"):
                datagram_request(client, relay, origin.port, name)
                stream_request(front, origin.port, name)
                datagram_request(client, relay, origin.port, name)
            for name in ("split.test", "split-eval.test"):
                datagram_request(client, relay, origin.port, name)
                stream_request(front, origin.port, name)
                datagram_request(client, relay, origin.port, name)
                stream_request(front, origin.port, name)
            datagram_request(client, relay, origin.port, "alias.test")
            stream_request(front, origin.port, "alias.test")
            for name in ("bad.test", "formerr.test"):
                stream_request(front, origin.port, name, success=False)
                stream_request(front, origin.port, name, success=False)
            for name in ("parallel.test", "parallel-eval.test"):
                barrier = threading.Barrier(8)
                def parallel_request(_):
                    barrier.wait(timeout=5)
                    stream_request(front, origin.port, name)
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    list(pool.map(parallel_request, range(8)))
            if local:
                hosts.write_text("127.0.0.1 host.test\n::1 host.test\n")
                time.sleep(1.2)
                before = len(seen)
                datagram_request(client, relay, origin.port, "host.test")
                stream_request(front, origin.port, "host.test")
                assert len(seen) == before, seen
                datagram_request(client, relay, origin.port, "short")
                stream_request(front, origin.port, "short")
                datagram_request(client, relay, origin.port, "negative")
                stream_request(front, origin.port, "negative")
                canceled = []
                def held_request():
                    try:
                        stream_request(front, origin.port, "hold.test", success=False)
                    except (OSError, RuntimeError) as error:
                        canceled.append(error)
                pending = threading.Thread(target=held_request)
                pending.start()
                deadline = time.monotonic() + 3
                while not any(name.startswith("hold.") for name, _, _ in seen):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("pending ECS query not observed")
                    time.sleep(.01)
                process.terminate()
                pending.join(timeout=4)
                assert not pending.is_alive() and canceled, "active query did not cancel"
        for name, prefix in (("one.test", bytes.fromhex("0008000700011800c63364")),
                             ("two.test", bytes.fromhex("0008000700011800cb0071"))):
            packets = [options for host, _, options in seen if host == name]
            assert packets and all(prefix in options for options in packets), (name, seen)
        for name in ("split.test", "split-eval.test"):
            packets = [(kind, options) for host, kind, options in seen if host == name]
            for prefix in (bytes.fromhex("0008000700011800c63364"), bytes.fromhex("0008000700011800cb0071")):
                assert sorted(kind for kind, options in packets if prefix in options) == [1, 28], (name, seen)
        for name in ("alias.test", "target.test"):
            packets = [(kind, options) for host, kind, options in seen if host == name]
            assert sorted(kind for kind, _ in packets) == [1, 1, 28, 28] and all(bytes.fromhex("0008000700011800cb0071") in options for _, options in packets), (name, seen)
        for name in ("bad.test", "formerr.test"):
            packets = [(kind, options) for host, kind, options in seen if host == name]
            assert len(packets) == 2 and all(bytes.fromhex("0008000700011800cb0071") in options for _, options in packets), (name, seen)
        for name in ("parallel.test", "parallel-eval.test"):
            packets = [(kind, options) for host, kind, options in seen if host == name]
            assert sorted(kind for kind, _ in packets) == [1, 28] and all(bytes.fromhex("0008000700011800c63364") in options for _, options in packets), seen
        if local:
            packets = [(kind, options) for name, kind, options in seen if name == "short.search.test"]
            assert sorted(kind for kind, _ in packets) == [1, 28] and all(bytes.fromhex("0008000700011800c63364") in options for _, options in packets), seen
            for name in ("negative.search.test", "negative"):
                packets = [(kind, options) for host, kind, options in seen if host == name]
                assert sorted(kind for kind, _ in packets) == [1, 28] and all(bytes.fromhex("0008000700011800c63364") in options for _, options in packets), seen
finally:
    stop.set()
    worker.join(timeout=3)
    sock.close()
assert not errors and not worker.is_alive(), errors
print("DNS ECS proxy TCP and Shadowsocks UDP route/evaluate passed")
