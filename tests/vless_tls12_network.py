#!/usr/bin/env python3
"""Verify ordinary VLESS carriers against a TLS 1.2-only independent peer."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from dns_rule_support import Echo, exact, free_port, nexus_process
from httpupgrade_tls_network import UUID, certificates
from shadowtls_singbox import REVISION, launch_singbox, stop_proc
from tcp_proxy_outbounds_network import open_socks


def write_config(path, root, front, remote, transport, name="localhost", extra=""):
    path.write_text(f'''schema-version 1
role "client"
inbound "entry" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
    server host="127.0.0.1" port={remote}
    authentication {{ uuid-file "{root / 'uuid'}"; }}
    tls {{ server-name "{name}"; ca-file "{root / 'cert'}"; fingerprint "tls12"; verify #true; }}
    {transport}
    {extra}
}}
routing {{ final "edge"; }}
''')


def verify(binary, root):
    certificates(root)
    uuid = root / "uuid"
    uuid.write_text(UUID + "\n")
    uuid.chmod(0o600)

    configuration = root / "nexus.kdl"
    peer_config = root / "peer.json"
    path = "/nexus-tls12"
    cases = (
        ("tcp", None, "", []),
        ("httpupgrade", {"type": "httpupgrade", "path": path},
         f'transport "httpupgrade" {{ path "{path}"; }}', ["http/1.1"]),
        ("websocket", {"type": "ws", "path": path},
         f'transport "websocket" {{ path "{path}"; }}', ["http/1.1"]),
        ("grpc", {"type": "grpc", "service_name": "nexus.Service"},
         'transport "grpc" { service-name "nexus.Service"; response-policy "sing-box-lite"; }', ["h2"]),
    )
    for label, go_transport, nexus_transport, alpn in cases:
        front, remote = free_port(), free_port()
        inbound = {"type": "vless", "listen": "127.0.0.1", "listen_port": remote,
                   "users": [{"uuid": UUID}], "tls": {"enabled": True, "certificate_path": str(root / "cert"),
                   "key_path": str(root / "key"), "min_version": "1.2", "max_version": "1.2", "alpn": alpn}}
        if go_transport:
            inbound["transport"] = go_transport
        peer_config.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": [inbound],
                                          "outbounds": [{"type": "direct"}]}))
        peer = launch_singbox(peer_config, remote)
        try:
            write_config(configuration, root, front, remote, nexus_transport,
                         extra="tcp-fast-open #true" if label == "tcp" else "")
            with nexus_process(binary, configuration), Echo() as origin:
                for host in ("127.0.0.1", "::1"):
                    with open_socks(front, host, origin.port) as client:
                        payload = ("TLS 1.2 / " + label + " / " + host).encode()
                        client.sendall(payload)
                        assert exact(client, len(payload)) == payload
            if label == "tcp":
                write_config(configuration, root, front, remote, nexus_transport, name="wrong.example")
                with nexus_process(binary, configuration), open_socks(front, "127.0.0.1", 53, accepted=False):
                    pass
        finally:
            stop_proc(peer)
        print(f"VLESS TLS 1.2 {label}: authenticated IPv4 and IPv6 targets")

    write_config(configuration, root, free_port(), free_port(), "", extra='flow "xtls-rprx-vision"')
    rejected = subprocess.run([binary, "run", "--config", configuration], capture_output=True, text=True, timeout=5)
    assert rejected.returncode and "VLESS TLS 1.2 requires ordinary TLS" in rejected.stderr, rejected


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    version = subprocess.check_output(["sing-box", "version"], text=True)
    assert f"Revision: {REVISION}" in version, version
    with tempfile.TemporaryDirectory(prefix="nexus-vless-tls12-") as directory:
        verify(binary, Path(directory))
