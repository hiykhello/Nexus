"""Per-question routes through TCP, HTTP, SOCKS UDP and optional SS UDP."""
import argparse
import base64
import collections
import concurrent.futures
import contextlib
import pathlib
import struct
import subprocess
import tempfile
import threading
import time
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, stream_request, udp_client, datagram_request, ss_client, question

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--ss", action="store_true")
args = parser.parse_args()
binary = args.binary.resolve()


class BoundedPeer(DnsPeer):
    def reply(self, packet, transport):
        wire = super().reply(packet, transport)
        if transport != "udp" or wire is None or len(wire) <= 512:
            return wire
        _, _, end = question(packet)
        return packet[:2] + struct.pack("!5H", 0x8380, 1, 0, 0, 0) + packet[12:end]


def run(workers, prefer_v6, disabled, named):
    with tempfile.TemporaryDirectory(prefix="nexus-dns-question-") as directory, \
         BoundedPeer() as first, DnsPeer(ipv6=not named) as second, DnsPeer() as bootstrap, Echo() as origin:
        root, front, ss_port = pathlib.Path(directory), free_port(), free_port()
        key = bytes(range(16))
        key_file = root / "key"
        key_file.write_text(base64.b64encode(key).decode() + "\n")
        key_file.chmod(0o600)
        second_host = "upstream.test" if named else "::1"
        dependency = 'domain-resolver="bootstrap"' if named else ""
        optional_ss = f'shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_file}"; }}' if args.ss else ""
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{
 mixed "mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 {optional_ss}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
dns {{
 server "first" type="udp" host="127.0.0.1" port={first.port};
 server "second" type="tcp" host="{second_host}" port={second.port} {dependency};
 server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap.port};
 rule domain="ordered.rules.test" server="first";
 rule domain-keyword="KEYWORD-" query-type=1 server="first";
 rule domain-keyword="KEYWORD-" query-type=28 server="second";
 rule domain-wildcard="*.single.test" query-type=1 server="first";
 rule domain-wildcard="*.single.test" query-type=28 server="second";
 rule domain-suffix="rules.test" query-type="A" server="first";
 rule domain-suffix="rules.test" query-type=28 server="second";
 rule query-type="AAAA" server="second";
 final "bootstrap";
 strategy "{'prefer_ipv6' if prefer_v6 else 'prefer_ipv4'}";
 disable-cache {'#true' if disabled else '#false'};
}}
''')
        with nexus_process(binary, config, 2 if args.ss else 1) as process, contextlib.ExitStack() as stack:
            clients = [stack.enter_context(udp_client(front))]
            if args.ss:
                clients.append(stack.enter_context(ss_client(root, ss_port, key)))
            name = "cache.rules.test"
            stream_request(front, origin.port, name)
            stream_request(front, origin.port, name.upper(), http=True)
            for client, relay in clients:
                datagram_request(client, relay, origin.port, name)
            expected = 2 + len(clients) if disabled else 1
            if first.count(name, 1) != expected or second.count(name, 28) != expected:
                raise RuntimeError(f"shared cache counts: {first.seen!r}, {second.seen!r}")
            for mode in ("alias", "no-a", "no-b", "limit", "ordered"):
                stream_request(front, origin.port, f"{mode}.rules.test")
                for client, relay in clients:
                    datagram_request(client, relay, origin.port, f"{mode}.rules.test")
            for name in ("MYKEYWORD-OUTSIDE.other", "one.single.test", "single.test", "deep.one.single.test"):
                stream_request(front, origin.port, name)
                for client, relay in clients:
                    datagram_request(client, relay, origin.port, name)
                normalized = name.lower()
                selected = first if name in ("MYKEYWORD-OUTSIDE.other", "one.single.test") else bootstrap
                unselected = bootstrap if selected is first else first
                if not selected.count(normalized, 1) or unselected.count(normalized, 1) or not second.count(normalized, 28):
                    raise RuntimeError(f"DNS domain pattern route was ignored: {name}")
            for mode in ("mismatch", "conflict", "nx", "servfail", "many"):
                stream_request(front, origin.port, f"{mode}.rules.test", success=False)
                for client, relay in clients:
                    datagram_request(client, relay, origin.port, f"{mode}.rules.test", success=False)
                stream_request(front, origin.port, f"recover-{mode}.rules.test")
            stream_request(front, origin.port, "fallback.other")
            if bootstrap.count("fallback.other", 1) != 1 or second.count("fallback.other", 28) != 1:
                raise RuntimeError("query-type-only or final fallback was ignored")
            if not disabled:
                barrier = threading.Barrier(12)
                def concurrent_request(_):
                    barrier.wait(timeout=5)
                    stream_request(front, origin.port, "coalesce.rules.test")
                with concurrent.futures.ThreadPoolExecutor(12) as pool:
                    list(pool.map(concurrent_request, range(12)))
                if first.count("coalesce.rules.test", 1) != 1 or second.count("coalesce.rules.test", 28) != 1:
                    raise RuntimeError("routed questions did not coalesce")
            for name, kind, transport in first.seen:
                if kind != 1 and name != "ordered.rules.test":
                    raise RuntimeError(f"AAAA leaked into the A route: {(name, kind, transport)}")
            for name, kind, transport in second.seen:
                if kind != 28 or transport != "tcp":
                    raise RuntimeError(f"incorrect second-route question: {(name, kind, transport)}")
            if named:
                seen = collections.Counter(kind for name, kind, _ in bootstrap.seen if name == "upstream.test")
                if not seen[1] or seen[1] != seen[28]:
                    raise RuntimeError(f"bootstrap inherited a business-family restriction: {seen!r}")
            client = connect(front)
            stack.callback(client.close)
            client.sendall(b"\x05\x01\x00")
            if exact(client, 2) != b"\x05\x00":
                raise RuntimeError("pending greeting")
            raw = b"pending.rules.test"
            client.sendall(b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", origin.port))
            deadline = time.monotonic() + 3
            while not second.count("pending.rules.test", 28):
                if time.monotonic() >= deadline:
                    raise RuntimeError("routed pending question did not start")
                time.sleep(.01)
            started = time.monotonic()
            process.terminate()
            process.wait(timeout=3)
            if time.monotonic() - started > 1.5:
                raise RuntimeError("routed question did not cancel promptly")
    print(f"question rules passed: workers={workers} v6={prefer_v6} no-cache={disabled} bootstrap={named}", flush=True)


if args.ss:
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
for workers in (1, 2):
    for v6 in (False, True):
        for disabled in (False, True):
            for named in (False, True):
                run(workers, v6, disabled, named)
print("DNS question routes, cache/coalescing, canonical/negative limits and cancellation passed")
