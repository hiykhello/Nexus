"""Ordered DNS route/reject actions run before cache or upstream I/O."""
import argparse
import base64
import contextlib
import pathlib
import socket
import struct
import subprocess
import tempfile
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, stream_request, udp_client, datagram_request, ss_client

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--ss", action="store_true")
args = parser.parse_args()
binary = args.binary.resolve()


def run(workers, strategy, disabled):
    with tempfile.TemporaryDirectory(prefix="nexus-dns-actions-") as directory, DnsPeer() as first, \
         DnsPeer(ipv6=True, port=first.port) as first_v6, DnsPeer() as fallback, Echo() as origin:
        root, front, ss_port = pathlib.Path(directory), free_port(), free_port()
        key = bytes(range(16))
        key_file = root / "key"
        key_file.write_text(base64.b64encode(key).decode()+"\n")
        key_file.chmod(0o600)
        ss = f'shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_file}"; }}' if args.ss else ""
        first_type = 28 if strategy in ("prefer_ipv6", "ipv6_only") else 1
        opposite = 1 if first_type == 28 else 28
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
 server "first" type="udp" host="127.0.0.1" port={first.port};
 server "fallback" type="udp" host="127.0.0.1" port={fallback.port};
 server "prewarm" type="tcp" host="cached.rules.test" port={first.port} domain-resolver="first";
 rule domain="warmer.rules.test" action="route" server="prewarm";
 rule domain="allow.blocked.test" action="route" server="first";
 rule domain="cached.rules.test" action="reject";
 rule domain-suffix="blocked.test" action="reject";
 rule domain="blocked-family.rules.test" query-type={first_type} action="reject";
 rule domain="opposite.rules.test" query-type={opposite} action="reject";
 rule action="route" server="first";
 final "fallback";
 strategy "{strategy}";
 disable-cache {'#true' if disabled else '#false'};
}}
''')
        with nexus_process(binary, config, 2 if args.ss else 1), contextlib.ExitStack() as stack:
            clients = [stack.enter_context(udp_client(front))]
            if args.ss:
                clients.append(stack.enter_context(ss_client(root, ss_port, key)))
            # An explicit bootstrap is allowed to fill the ordinary upstream
            # view even though the same business name is rejected by policy.
            stream_request(front, origin.port, "warmer.rules.test")
            if not first.count("cached.rules.test", first_type):
                raise RuntimeError("rejected name was not prewarmed through explicit bootstrap")
            for client, relay in clients:
                datagram_request(client, relay, origin.port, "warmer.rules.test")
            stream_request(front, origin.port, "allow.blocked.test", http=True)
            for client, relay in clients:
                datagram_request(client, relay, origin.port, "allow.blocked.test")
            before = [len(peer.seen) for peer in (first, first_v6, fallback)]
            target_before = (len(origin.accepted), len(origin.received))
            for name in ("cached.rules.test", "deny.blocked.test", "blocked-family.rules.test"):
                stream_request(front, origin.port, name, success=False, code=2)
                stream_request(front, origin.port, name, success=False, http=True, code=403)
                for client, relay in clients:
                    datagram_request(client, relay, origin.port, name, success=False)
            if [len(peer.seen) for peer in (first, first_v6, fallback)] != before or \
               (len(origin.accepted), len(origin.received)) != target_before:
                raise RuntimeError("DNS rejection queried an upstream or reached a target")
            if strategy.endswith("_only"):
                stream_request(front, origin.port, "opposite.rules.test")
                for client, relay in clients:
                    datagram_request(client, relay, origin.port, "opposite.rules.test")
            else:
                before = [len(peer.seen) for peer in (first, first_v6, fallback)]
                stream_request(front, origin.port, "opposite.rules.test", success=False, code=2)
                if [len(peer.seen) for peer in (first, first_v6, fallback)] != before:
                    raise RuntimeError("a rejected later family sent an earlier question")
            # Rejected datagrams must release each pending dispatcher token.
            raw = b"deny.blocked.test"
            packet = b"\x00\x00\x00\x03"+bytes([len(raw)])+raw+struct.pack("!H", origin.port)+b"denied"
            for client, relay in clients:
                for _ in range(80):
                    client.sendto(packet, relay)
                datagram_request(client, relay, origin.port, "healthy.rules.test")
            stream_request(front, origin.port, "healthy.rules.test")
            # An upstream REFUSED stays a DNS failure, distinct from a local
            # policy denial, and cannot become a cached rejection.
            for _ in range(2):
                stream_request(front, origin.port, "refused.rules.test", success=False, code=4)
            if first.count("refused.rules.test", first_type) != 2 or fallback.seen:
                raise RuntimeError("REFUSED was cached, retried through final, or the explicit catch-all route was ignored")
            if strategy.endswith("_only"):
                allowed = {first_type}
                if {kind for _, kind, _ in first.seen + first_v6.seen} != allowed:
                    raise RuntimeError("DNS rejection changed the configured address families")
        print(f"DNS actions passed: workers={workers} strategy={strategy} no-cache={disabled}", flush=True)


def reject_all():
    with tempfile.TemporaryDirectory(prefix="nexus-dns-reject-all-") as directory, DnsPeer() as peer, Echo() as origin:
        root, front = pathlib.Path(directory), free_port()
        config = root / "server.kdl"
        config.write_text(f'''schema-version 1
role "server"
inbound "in" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
 server "first" type="udp" host="127.0.0.1" port={peer.port};
 rule action="reject";
}}
''')
        with nexus_process(binary, config), udp_client(front) as (client, relay):
            stream_request(front, origin.port, "denied.test", success=False, code=2)
            stream_request(front, origin.port, "denied.test", success=False, http=True, code=403)
            datagram_request(client, relay, origin.port, "denied.test", success=False)
            # Literal targets do not issue DNS questions and remain usable.
            with connect(front) as literal:
                literal.sendall(b"\x05\x01\x00")
                if exact(literal, 2) != b"\x05\x00":
                    raise RuntimeError("literal greeting failed")
                literal.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+struct.pack("!H", origin.port))
                if exact(literal, 10)[1]:
                    raise RuntimeError("unconditional DNS rejection blocked a literal target")
                literal.sendall(b"literal")
                if exact(literal, 7) != b"literal":
                    raise RuntimeError("literal target response mismatch")
            if peer.seen:
                raise RuntimeError("unconditional rejection sent a DNS question")
    print("unconditional DNS rejection passed", flush=True)


if args.ss:
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
for workers in (1, 2):
    for strategy in ("prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"):
        for disabled in (False, True):
            run(workers, strategy, disabled)
reject_all()
print("DNS route/reject ordering, cache precedence, bootstrap, error distinctions and pending-token recovery passed")
