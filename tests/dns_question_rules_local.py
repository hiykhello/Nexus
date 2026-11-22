"""Local/remote question routes retain search, hosts and one snapshot."""
import argparse
import base64
import contextlib
import concurrent.futures
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, stream_request, udp_client, datagram_request, ss_client

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--inside", action="store_true")
parser.add_argument("--ss", action="store_true")
args = parser.parse_args()
binary = args.binary.resolve()
if args.ss:
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
if not args.inside:
    subprocess.run(["unshare", "-Urnm", sys.executable, __file__, binary, "--inside"] + (["--ss"] if args.ss else []), check=True)
    sys.exit(0)
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
subprocess.run(["mount", "--make-rprivate", "/"], check=True)


def wait_for(peer, name, kind):
    deadline = time.monotonic() + 3
    while not peer.count(name, kind):
        if time.monotonic() >= deadline:
            raise RuntimeError(f"missing question {(name, kind)}: {peer.seen!r}")
        time.sleep(.01)


with tempfile.TemporaryDirectory(prefix="nexus-dns-question-local-") as directory:
    root = pathlib.Path(directory)
    (root / "resolv").write_text("nameserver 127.0.0.2\nsearch rules.test other.test\noptions timeout:3 attempts:1\n")
    key = bytes(range(16))
    key_file = root / "key"
    key_file.write_text(base64.b64encode(key).decode()+"\n")
    key_file.chmod(0o600)
    hosts = root / "hosts"
    hosts.write_text("127.0.0.1 host.rules.test\n::1 host.rules.test snapshot.rules.test fresh.rules.test\n")
    for source, target in ((root / "resolv", "/etc/resolv.conf"), (hosts, "/etc/hosts")):
        subprocess.run(["mount", "--bind", source, target], check=True)
    with DnsPeer(host="127.0.0.2", port=53) as local, DnsPeer() as remote, Echo() as origin:
        for workers in (1, 2):
            for local_a in (True, False):
                front, ss_port = free_port(), free_port()
                optional_ss = f'shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_file}"; }}' if args.ss else ""
                local_type, remote_type = (1, 28) if local_a else (28, 1)
                local.seen.clear()
                remote.seen.clear()
                local.no_data = {("fallback.rules.test", local_type), ("diverge.rules.test", local_type)}
                remote.aliases = {"search": "search.rules.test", "fallback": "fallback.other.test", "diverge": "diverge.rules.test"}
                hosts.write_text("127.0.0.1 host.rules.test\n::1 host.rules.test snapshot.rules.test fresh.rules.test\n" +
                                 ("::1 only-remote.rules.test\n" if local_a else "127.0.0.1 only-remote.rules.test\n"))
                config = root / "server.kdl"
                config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{
 mixed "in" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 {optional_ss}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
 server "local" type="local";
 server "remote" type="udp" host="127.0.0.1" port={remote.port};
 server "named" type="udp" host="upstream.test" port={remote.port} domain-resolver="local";
 rule domain="no-a" server="local";
 rule domain="fresh.rules.test" server="local";
 rule domain-suffix="bootstrap.test" query-type=28 server="named";
 rule query-type={local_type} server="local";
 rule query-type={remote_type} server="remote";
 strategy "prefer_ipv4";
}}
''')
                gate = threading.Event()
                try:
                    with nexus_process(binary, config, 2 if args.ss else 1) as process, contextlib.ExitStack() as stack:
                        clients = [stack.enter_context(udp_client(front))]
                        if args.ss:
                            clients.append(stack.enter_context(ss_client(root, ss_port, key)))
                        for name in ("host.rules.test", "only-remote.rules.test"):
                            before = len(local.seen)
                            stream_request(front, origin.port, name)
                            for client, relay in clients:
                                datagram_request(client, relay, origin.port, name)
                            if len(local.seen) != before:
                                raise RuntimeError("hosts leaked a query to the local nameserver")
                        for name in ("search", "fallback"):
                            stream_request(front, origin.port, name)
                            for client, relay in clients:
                                datagram_request(client, relay, origin.port, name)
                        for name in ("different", "diverge"):
                            before = (len(origin.accepted), len(origin.received))
                            stream_request(front, origin.port, name, success=False)
                            for client, relay in clients:
                                datagram_request(client, relay, origin.port, name, success=False)
                            if (len(origin.accepted), len(origin.received)) != before:
                                raise RuntimeError("inconsistent search answers reached a target")
                        stream_request(front, origin.port, "no-a")
                        for client, relay in clients:
                            datagram_request(client, relay, origin.port, "no-a")
                        if local.count("no-a.rules.test", 1) != 1 or local.count("no-a.rules.test", 28) != 1 or \
                           local.count("no-a.other.test", 1) or local.count("no-a.other.test", 28):
                            raise RuntimeError("same-server dual search changed its first successful candidate")
                        if not local_a:
                            operations = [lambda name: stream_request(front, origin.port, name)]
                            for client, relay in clients:
                                operations.append(lambda name, c=client, r=relay: datagram_request(c, r, origin.port, name))
                            for bootstrap in (False, True):
                                for index, operation in enumerate(operations):
                                    name = f"snapshot-{index}.{'bootstrap' if bootstrap else 'rules'}.test"
                                    hosts.write_text(f"::1 {name} fresh.rules.test\n127.0.0.1 upstream.test\n")
                                    time.sleep(1.3)
                                    remote.no_data = {(name, 1)}
                                    gate = threading.Event()
                                    remote.gates[(name, 1)] = gate
                                    with concurrent.futures.ThreadPoolExecutor(1) as pool:
                                        future = pool.submit(operation, name)
                                        try:
                                            wait_for(remote, name, 1)
                                            hosts.write_text(f"::2 {name} fresh.rules.test\n127.0.0.2 upstream.test\n")
                                            time.sleep(1.5)
                                            stream_request(front, origin.port, "fresh.rules.test", success=False)
                                        finally:
                                            gate.set()
                                        future.result(timeout=3)
                                    remote.gates.clear()
                                    remote.no_data.clear()
                        for index, (client, relay) in enumerate(clients):
                            name = f"cancel-udp{index}"
                            local.drop.add((name+".rules.test", local_type))
                            raw = name.encode()
                            client.sendto(b"\x00\x00\x00\x03"+bytes([len(raw)])+raw+struct.pack("!H", origin.port)+b"pending", relay)
                            wait_for(local, name+".rules.test", local_type)
                        local.drop.add(("cancel.rules.test", local_type))
                        with connect(front) as client:
                            client.sendall(b"\x05\x01\x00")
                            if exact(client, 2) != b"\x05\x00":
                                raise RuntimeError("pending greeting failed")
                            raw = b"cancel"
                            client.sendall(b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", origin.port))
                            wait_for(local, "cancel.rules.test", local_type)
                            started = time.monotonic()
                            process.terminate()
                            process.wait(timeout=3)
                            if time.monotonic() - started > 1.5:
                                raise RuntimeError("local question did not cancel promptly")
                finally:
                    gate.set()
                    remote.gates.clear()
                    remote.no_data.clear()
                    local.drop.clear()
                print(f"local question routes passed: workers={workers} local_A={local_a}", flush=True)
print("Local question routes retain hosts, search candidates, canonical checks, snapshots and cancellation")
