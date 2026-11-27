#!/usr/bin/env python3
"""Check required ECH through production QUIC outbounds and independent peers."""
import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import tempfile

from dns_rule_support import DnsPeer, exact, free_port, nexus_process, question, udp_client
from masque_ip_outbound import packet, roundtrip
from tuic_singbox import launch_singbox, socks5_tcp_echo, start_tcp_echo, stop_proc
from udp_bind_port_network import certificate


UUID = "b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f"


def generate(root, stem, public_name="public.example"):
    pem = subprocess.check_output(["sing-box", "generate", "ech-keypair", public_name])
    parts = re.findall(rb"-----BEGIN (ECH [A-Z]+)-----\s+([A-Za-z0-9+/=\s]+)-----END \1-----", pem)
    values = {label: base64.b64decode(data) for label, data in parts}
    config, keys = root / (stem + ".bin"), root / (stem + ".pem")
    config.write_bytes(values[b"ECH CONFIGS"])
    keys.write_bytes(pem[pem.index(b"-----BEGIN ECH KEYS-----"):])
    keys.chmod(0o600)
    return config, keys


class EchDnsPeer(DnsPeer):
    def __init__(self, kind, config_list):
        super().__init__()
        self.kind, self.config_list = kind, config_list

    def reply(self, query, transport):
        name, kind, end = question(query)
        self.seen.append((name, kind, transport))
        answer = b""
        if name == "localhost" and kind == self.kind and self.config_list:
            param = struct.pack("!HH", 5, len(self.config_list)) + self.config_list
            data = b"\x00\x01\x00\x00\x01\x00\x03\x02h3" + param
            answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 10, len(data)) + data
        return query[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0) + query[12:end] + answer


def make_config(root, protocol, upstream, ech, dns=None):
    front = free_port()
    cfg = root / "nexus.kdl"
    options = {
        "hysteria2": f'authentication {{ password-file "{root / "password"}"; }}\n quic {{ lazy-tcp-response #true; }}',
        "tuic": f'authentication {{ uuid-file "{root / "uuid"}"; password-file "{root / "password"}"; }}',
        "masque": f'mode "connect-ip"; authority "localhost"; authentication {{ bearer-file "{root / "bearer"}"; }}',
    }[protocol]
    nameserver = f'dns {{ server "control" type="udp" host="127.0.0.1" port={dns}; final "control"; }}' if dns else ""
    cfg.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="{protocol}" {{
    server host="127.0.0.1" port={upstream}
    {options}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; {ech}; }}
    connect-timeout-ms 1800
}}
routing {{ final "edge"; }}
{nameserver}
''')
    return cfg, front


@contextlib.contextmanager
def go_peer(root, fixture, keys, retry=False):
    env = dict(os.environ, NEXUS_TEST_ECH_KEYS=str(keys), NEXUS_TEST_ECH_RETRY="1" if retry else "0")
    with subprocess.Popen([fixture, root / "cert", root / "key"], env=env, stdout=subprocess.PIPE) as peer:
        try:
            if not select.select([peer.stdout], [], [], 5)[0]:
                raise RuntimeError("ECH Go peer startup deadline")
            yield int(peer.stdout.readline().rsplit(b":", 1)[1])
        finally:
            stop_proc(peer)


def open_socks(front):
    client = socket.create_connection(("127.0.0.1", front), timeout=4)
    try:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting rejected")
        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
        return client
    except BaseException:
        client.close()
        raise


def check_blocked(front, protocol):
    if protocol == "masque":
        with udp_client(front) as (client, relay):
            client.settimeout(.7)
            client.sendto(packet("198.51.100.42", b"must-not-pass"), relay)
            try:
                client.recv(2048)
            except TimeoutError:
                return
        raise RuntimeError("CONNECT-IP unexpectedly transferred traffic")
    with open_socks(front) as client:
        if exact(client, 10)[1] == 0:
            raise RuntimeError(f"{protocol} accepted a connection without ECH")


def tuic_server(root, keys, port):
    config = root / "tuic.json"
    config.write_text(json.dumps({
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "tuic", "listen": "127.0.0.1", "listen_port": port,
            "users": [{"uuid": UUID, "password": "test-password"}],
            "tls": {
                "enabled": True, "alpn": ["h3"], "certificate_path": str(root / "cert"),
                "key_path": str(root / "key"), "ech": {"enabled": True, "key_path": str(keys)},
            },
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }))
    return launch_singbox(config)


def run(binary, hy2_peer, masque_peer):
    with tempfile.TemporaryDirectory(prefix="nexus-ech-") as folder:
        root = Path(folder)
        certificate(root)
        for name, value in {"uuid": UUID, "password": "test-password", "bearer": "approved"}.items():
            path = root / name
            path.write_text(value + "\n")
            path.chmod(0o600)
        config, keys = generate(root, "ech")
        wrong, _ = generate(root, "wrong")
        static = f'ech-config-file "{config}"'

        for retry in (False, True):
            with go_peer(root, hy2_peer, keys, retry=retry) as port:
                tls = static + ('; fingerprint "chrome"' if retry else "")
                cfg, front = make_config(root, "hysteria2", port, tls)
                with nexus_process(str(binary), str(cfg)), open_socks(front) as client:
                    if exact(client, 10)[1] != 0:
                        raise RuntimeError(f"Hysteria 2 static ECH failed (HRR={retry})")
                    client.sendall(b"ech-hy2")
                    if exact(client, 7) != b"ech-hy2":
                        raise RuntimeError("Hysteria 2 ECH echo mismatch")
        with go_peer(root, hy2_peer, keys) as port:
            cfg, front = make_config(root, "hysteria2", port, f'ech-config-file "{wrong}"')
            with nexus_process(str(binary), str(cfg)):
                check_blocked(front, "hysteria2")
        print("Hysteria 2 static ECH, HelloRetryRequest and rejection passed", flush=True)

        with go_peer(root, masque_peer, keys) as port, EchDnsPeer(65, config.read_bytes()) as dns:
            cfg, front = make_config(root, "masque", port, "ech-dns #true", dns.port)
            with nexus_process(str(binary), str(cfg)):
                roundtrip(front, b"ech-masque", timeout=4)
            if ("localhost", 65, "udp") not in dns.seen:
                raise RuntimeError("MASQUE did not fetch HTTPS ECH")
        print("MASQUE CONNECT-IP HTTPS ECH passed", flush=True)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        tcp, target, stop = start_tcp_echo()
        peer = None
        try:
            peer = tuic_server(root, keys, port)
            with EchDnsPeer(64, config.read_bytes()) as dns:
                cfg, front = make_config(root, "tuic", port, "ech-dns #true", dns.port)
                with nexus_process(str(binary), str(cfg)):
                    socks5_tcp_echo(front, "127.0.0.1", target, b"ech-tuic")
                if ("localhost", 64, "udp") not in dns.seen:
                    raise RuntimeError("TUIC did not use the SVCB ECH fallback")
        finally:
            stop_proc(peer)
            stop.set()
            tcp.close()
        print("TUIC SVCB ECH passed", flush=True)

        for protocol in ("hysteria2", "masque", "tuic"):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as monitor, EchDnsPeer(65, None) as dns:
                monitor.bind(("127.0.0.1", 0))
                cfg, front = make_config(root, protocol, monitor.getsockname()[1], "ech-dns #true", dns.port)
                with nexus_process(str(binary), str(cfg)):
                    check_blocked(front, protocol)
                if ("localhost", 65, "udp") not in dns.seen or select.select([monitor], [], [], .1)[0]:
                    raise RuntimeError(f"{protocol}: missing ECH query or leaked a QUIC Initial")
        print("Missing ECH DNS data stopped all three protocols before QUIC Initial")
        same_name, _ = generate(root, "same-name", "localhost")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as monitor:
            monitor.bind(("127.0.0.1", 0))
            cfg, front = make_config(root, "hysteria2", monitor.getsockname()[1], f'ech-config-file "{same_name}"')
            with nexus_process(str(binary), str(cfg)):
                check_blocked(front, "hysteria2")
            if select.select([monitor], [], [], .1)[0]:
                raise RuntimeError("ECH public_name matched the origin and allowed an Initial")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("hy2_peer", type=Path)
    parser.add_argument("masque_peer", type=Path)
    args = parser.parse_args()
    run(*(p.resolve(strict=True) for p in (args.binary, args.hy2_peer, args.masque_peer)))
