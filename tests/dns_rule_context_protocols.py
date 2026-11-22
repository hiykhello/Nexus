#!/usr/bin/env python3
"""Real authenticated protocol clients exercise DNS business context."""
import argparse
import base64
import pathlib
import socket
import struct
import subprocess
import tempfile

from dns_rule_support import (DnsPeer, Echo, connect, datagram_request, exact, free_port,
                              nexus_process, proxy_client, stream_request, udp_client)

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--protocol", choices=("all", "ss", "vless", "trojan"), default="all")
parser.add_argument("--trojan", action="store_true", help="include Trojan in the combined graph")
args = parser.parse_args()
binary = args.binary.resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")


def denied_stream(front, origin, name):
    with connect(front) as client:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("client greeting")
        raw = name.encode()
        client.sendall(b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", origin))
        reply = exact(client, 4)
        if reply[3] not in (1, 4):
            raise RuntimeError("invalid client reply")
        exact(client, 6 if reply[3] == 1 else 18)
        if reply[1] == 0:
            try:
                client.sendall(b"must-be-rejected")
                if client.recv(1):
                    raise RuntimeError("rejected stream returned application data")
            except (ConnectionResetError, BrokenPipeError):
                pass


def run(workers):
    with tempfile.TemporaryDirectory(prefix="nexus-dns-protocol-context-") as directory, \
         DnsPeer() as first, DnsPeer() as second, Echo() as origin:
        root = pathlib.Path(directory)
        ids = ["00010203-0405-0607-0809-0a0b0c0d0e0f", "10111213-1415-1617-1819-1a1b1c1d1e1f"]
        key = base64.b64encode(bytes(range(16))).decode()
        (root / "key").write_text(key + "\n")
        (root / "key").chmod(0o600)
        inbounds, clients = [], []
        if args.protocol in ("all", "ss"):
            front = free_port()
            inbounds.append(f'shadowsocks "ss" {{ listen host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root / "key"}"; }}')
            for uot in (False, True):
                outbound = {"type": "shadowsocks", "server": "127.0.0.1", "server_port": front,
                            "method": "2022-blake3-aes-128-gcm", "password": key}
                if uot:
                    outbound["udp_over_tcp"] = {"enabled": True, "version": 2}
                clients.append((f"ss-{'uot' if uot else 'udp'}", "ss", None, outbound))
        if args.protocol != "ss" or args.trojan:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "tls-key"),
                            "-out", str(root / "cert"), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (root / "tls-key").chmod(0o600)
            for index, identity in enumerate(ids):
                (root / f"uuid{index}").write_text(identity + "\n")
                (root / f"uuid{index}").chmod(0o600)
            for vision in ((False, True) if args.protocol in ("all", "vless") else ()):
                front = free_port()
                tag = "vision" if vision else "vless"
                flow = 'flow "xtls-rprx-vision";' if vision else ""
                inbounds.append(f'''vless "{tag}" {{ listen host="127.0.0.1" port={front}; {flow}
 authentication {{ user "alice" uuid-file="{root / 'uuid0'}"; user "bob" uuid-file="{root / 'uuid1'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'tls-key'}"; }}
}}''')
                for index, user in ((1, "bob"), (0, "alice")):
                    outbound = {"type": "vless", "server": "127.0.0.1", "server_port": front, "uuid": ids[index],
                                "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(root / "cert")}}
                    if vision:
                        outbound["flow"] = "xtls-rprx-vision"
                    clients.append((f"{tag}-{user}", tag, user, outbound))
            if args.trojan or args.protocol == "trojan":
                front = free_port()
                for user in ("alice", "bob"):
                    (root / user).write_text(f"secret-{user}\n")
                    (root / user).chmod(0o600)
                inbounds.append(f'''trojan "trojan" {{ listen host="127.0.0.1" port={front};
 authentication {{ user "alice" password-file="{root / 'alice'}"; user "bob" password-file="{root / 'bob'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'tls-key'}"; }}
}}''')
                for user in ("bob", "alice"):
                    outbound = {"type": "trojan", "server": "127.0.0.1", "server_port": front, "password": f"secret-{user}",
                                "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(root / "cert")}}
                    clients.append((f"trojan-{user}", "trojan", user, outbound))
        config = root / "server.kdl"
        config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{ {chr(10).join(inbounds)} }}
outbound "direct" type="direct"
dns {{
 server "first" type="udp" host="127.0.0.1" port={first.port}
 server "second" type="tcp" host="127.0.0.1" port={second.port}
 rule domain="identity.test" auth-user="alice" action="reject"
 rule domain="network.test" network="udp" action="reject"
 rule domain="source.test" network="udp" source-ip-cidr="127.0.0.1/32" source-port-range="1-65535" action="reject"
 rule domain="listener.test" inbound="vision" action="reject"
 rule domain="listener.test" inbound="trojan" action="reject"
 rule domain="split.test" auth-user="bob" network="udp" query-type=28 server="second"
 rule domain="split.test" inbound="ss" network="udp" query-type=28 server="second"
 final "first"
}}
routing {{ default-outbound "direct"; }}
''')
        with nexus_process(binary, config, len(inbounds)):
            for label, tag, user, outbound in clients:
                peer_root = root / label
                peer_root.mkdir()
                with proxy_client(peer_root, outbound) as socks:
                    for name, denied in (("identity.test", user == "alice"), ("network.test", False),
                                         ("source.test", False), ("listener.test", tag in ("vision", "trojan"))):
                        before = (len(first.seen), len(second.seen))
                        if denied:
                            denied_stream(socks, origin.port, name)
                        else:
                            stream_request(socks, origin.port, name)
                        if denied and before != (len(first.seen), len(second.seen)):
                            raise RuntimeError(f"{label} rejected TCP triggered DNS: {name}")
                    for name, denied in (("identity.test", user == "alice"), ("network.test", True),
                                         ("source.test", True), ("listener.test", tag in ("vision", "trojan")), ("split.test", False)):
                        before = (len(first.seen), len(second.seen))
                        # sing-vmess treats a rejected session's End as EOF;
                        # each probe uses a fresh SOCKS association.
                        with udp_client(socks) as (client, relay):
                            datagram_request(client, relay, origin.port, name, not denied)
                        if denied and before != (len(first.seen), len(second.seen)):
                            raise RuntimeError(f"{label} rejected UDP triggered DNS: {name}")
                    print(f"DNS TCP/UDP context passed: {label} workers={workers}")
            if not second.count("split.test", 28) or second.count("split.test", 1):
                raise RuntimeError("protocol context did not combine with qtype")


for worker_count in (1, 2):
    run(worker_count)
