"""Continued DNS cache options apply to each question and preserve local search."""
import argparse
import base64
import concurrent.futures
import contextlib
import pathlib
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, stream_request, udp_client, datagram_request, ss_client

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--ss", action="store_true")
parser.add_argument("--local", action="store_true")
parser.add_argument("--inside", action="store_true")
args = parser.parse_args()
binary = args.binary.resolve()
if args.local and not args.inside:
    subprocess.run(["unshare", "-Urnm", sys.executable, __file__, binary, "--local", "--inside"] +
                   (["--ss"] if args.ss else []), check=True)
    sys.exit(0)
if args.local:
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    local_files = tempfile.TemporaryDirectory(prefix="nexus-cache-options-local-")
    local_path = pathlib.Path(local_files.name)
    (local_path / "resolv").write_text("nameserver 127.0.0.2\nsearch rules.test other.test\noptions timeout:2 attempts:1\n")
    (local_path / "hosts").write_text("127.0.0.1 localhost\n")
    for source, target in ((local_path / "resolv", "/etc/resolv.conf"), (local_path / "hosts", "/etc/hosts")):
        subprocess.run(["mount", "--bind", source, target], check=True)
if args.ss:
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")


def run(workers, disabled, v6):
    with tempfile.TemporaryDirectory(prefix="nexus-dns-cache-options-") as directory:
        root, front, ss_port = pathlib.Path(directory), free_port(), free_port()
        key = bytes(range(16))
        key_file = root / "key"
        key_file.write_text(base64.b64encode(key).decode()+"\n")
        key_file.chmod(0o600)
        ss = f'shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_file}"; }}' if args.ss else ""
        peer = DnsPeer(host="127.0.0.2", port=53) if args.local else DnsPeer()
        with peer, Echo() as origin:
            # The first local candidate has only AAAA. Splitting A and AAAA
            # into separate searches would incorrectly take A from other.test.
            peer.no_data = {("choice.rules.test", 1)}
            rules = R'''
 rule domain="enabled.rules.test" action="route-options" disable-cache=#false;
 rule domain="disabled.rules.test" action="route-options" disable-cache=#true;
 rule domain="family.rules.test" query-type=1 action="route-options" disable-cache=#true;
 rule domain="family.rules.test" query-type=28 action="route-options" disable-cache=#false;
 rule domain="choice" query-type=1 action="route-options" disable-cache=#true;
 rule domain="choice" query-type=28 action="route-options" disable-cache=#false;
 rule domain="coalesce.rules.test" action="route-options" disable-cache=#false;
 rule domain="independent.rules.test" action="route-options" disable-cache=#true;
 rule domain="pending.rules.test" action="route-options" disable-cache=#true;
 rule domain="early.rules.test" action="route" server="first";
 rule domain="early.rules.test" action="route-options" disable-cache=#true;
 rule domain="override.rules.test" action="route-options" disable-cache=#true;
 rule domain="override.rules.test" action="route-options" disable-cache=#false;
 rule domain="terminal.rules.test" action="route-options" disable-cache=#true;
 rule domain="terminal.rules.test" action="route" server="first" disable-cache=#false;
 rule domain="negative.rules.test" query-type=1 action="route-options" disable-cache=#true;
 rule domain="negative.rules.test" query-type=28 action="route-options" disable-cache=#false;
'''
            peer.no_data.add(("negative.rules.test", 1))
            server = 'server "first" type="local";' if args.local else f'server "first" type="udp" host="127.0.0.1" port={peer.port};'
            if not args.local:
                server += f'\n server "named" type="udp" host="upstream.test" port={peer.port} domain-resolver="first";'
                rules += '''
 rule domain="prime.rules.test" action="route" server="named" disable-cache=#true;
 rule domain="upstream.test" query-type=1 action="route-options" disable-cache=#true;
 rule domain="upstream.test" query-type=28 action="route-options" disable-cache=#false;
'''
            config = root / "server.kdl"
            config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{
 mixed "in" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 {ss}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
 {server}
 {rules}
 final "first";
 strategy "{'prefer_ipv6' if v6 else 'prefer_ipv4'}";
 disable-cache {'#true' if disabled else '#false'};
}}
''')
            with nexus_process(binary, config, 2 if args.ss else 1) as process, contextlib.ExitStack() as stack:
                clients = [stack.enter_context(udp_client(front))]
                if args.ss:
                    clients.append(stack.enter_context(ss_client(root, ss_port, key)))
                requests = 2 + len(clients)
                if not args.local:
                    stream_request(front, origin.port, "prime.rules.test")
                    stream_request(front, origin.port, "upstream.test")
                    stream_request(front, origin.port, "upstream.test")
                    for client, relay in clients:
                        datagram_request(client, relay, origin.port, "upstream.test")
                    expected = (1 + requests, 2 if disabled else 1)
                    if tuple(peer.count("upstream.test", kind) for kind in (1, 28)) != expected:
                        raise RuntimeError(f"business cache policy leaked into bootstrap: {peer.seen!r}")
                    for client, relay in clients:
                        datagram_request(client, relay, origin.port, "prime.rules.test")
                    expected = (expected[0] + (len(clients) if disabled else 0),
                                expected[1] + (len(clients) if disabled else 0))
                    if tuple(peer.count("upstream.test", kind) for kind in (1, 28)) != expected or \
                       tuple(peer.count("prime.rules.test", kind) for kind in (1, 28)) != (1 + len(clients),) * 2:
                        raise RuntimeError(f"bootstrap stopped using global cache policy: {peer.seen!r}")
                for name, counts in (("enabled.rules.test", (1, 1)), ("disabled.rules.test", (requests, requests)),
                    ("family.rules.test", (requests, 1)), ("early.rules.test", (requests, requests) if disabled else (1, 1)),
                    ("override.rules.test", (1, 1)), ("terminal.rules.test", (1, 1)), ("negative.rules.test", (requests, 1))):
                    stream_request(front, origin.port, name)
                    stream_request(front, origin.port, name.upper(), http=True)
                    for client, relay in clients:
                        datagram_request(client, relay, origin.port, name)
                    actual = tuple(peer.count(name, kind) for kind in (1, 28))
                    if actual != counts:
                        raise RuntimeError(f"{name}: queries={actual}, expected={counts}, seen={peer.seen!r}")
                if args.local:
                    stream_request(front, origin.port, "choice")
                    stream_request(front, origin.port, "choice")
                    for client, relay in clients:
                        datagram_request(client, relay, origin.port, "choice")
                    if tuple(peer.count("choice.rules.test", kind) for kind in (1, 28)) != (requests, 1) or \
                       any(name == "choice.other.test" for name, _, _ in peer.seen):
                        raise RuntimeError(f"per-question cache options split the local search: {peer.seen!r}")
                for name, expected in (("coalesce.rules.test", 1), ("independent.rules.test", 12)):
                    peer.delays.update({(name, 1): .025, (name, 28): .025})
                    barrier = threading.Barrier(12)
                    def exchange(_):
                        barrier.wait(timeout=5)
                        stream_request(front, origin.port, name)
                    with concurrent.futures.ThreadPoolExecutor(12) as pool:
                        list(pool.map(exchange, range(12)))
                    if tuple(peer.count(name, kind) for kind in (1, 28)) != (expected, expected):
                        raise RuntimeError(f"cache option did not control coalescing for {name}: {peer.seen!r}")
                pending = stack.enter_context(connect(front))
                pending.sendall(b"\x05\x01\x00")
                if exact(pending, 2) != b"\x05\x00":
                    raise RuntimeError("pending greeting failed")
                raw = b"pending.rules.test"
                target = bytes([len(raw)]) + raw + struct.pack("!H", origin.port)
                pending.sendall(b"\x05\x01\x00\x03" + target)
                for client, relay in clients:
                    client.sendto(b"\x00\x00\x00\x03" + target + b"pending", relay)
                deadline = time.monotonic() + 3
                while peer.count("pending.rules.test", 28) != 1 + len(clients):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("no-cache pending questions were coalesced or not sent")
                    time.sleep(.01)
                started = time.monotonic()
                process.terminate()
                process.wait(timeout=3)
                if time.monotonic() - started > 1.5 or pending.recv(1):
                    raise RuntimeError("continued no-cache questions did not cancel and drain")
            print(f"DNS cache options passed: workers={workers} global-disabled={disabled} v6={v6} local={args.local}", flush=True)


for workers in (1, 2):
    for disabled in (False, True):
        for v6 in (False, True):
            run(workers, disabled, v6)
print("DNS continued cache options preserve order, per-type positive/negative caches, coalescing and local search")
