"""Ordered Trojan must charge the sniffed prefix before forwarding it."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from detour_network import running, socks
from dns_rule_support import free_port, nexus_process
from hy2_outbound_singbox import REVISION
from principal_limits_network import usage
from udp_bind_port_network import certificate


def check(binary, root):
    certificate(root)
    secret = root / "secret"
    secret.write_text("quota-peer\n")
    secret.chmod(0o600)
    front, client = free_port(), free_port()
    control = root / "control"
    config = root / "nexus.kdl"
    config.write_text(f'''schema-version 1
role "server"
control socket="{control}"
inbound "edge" type="trojan" {{
 listen host="127.0.0.1" port={front}
 authentication {{ user "alice" password-file="{secret}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 user-limits {{ user "alice" byte-quota=12; }}
}}
outbound "direct" type="direct" {{ tcp-fast-open #true; }}
routing {{
 tcp-program unknown="skip" sniff-timeout-ms=1000 {{
   rule action="sniff"
   rule action="route" outbound="direct"
 }}
 final "direct"
}}
''')
    peer = root / "sing-box.json"
    peer.write_text(json.dumps({
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": client}],
        "outbounds": [{"type": "trojan", "server": "127.0.0.1", "server_port": front,
                       "password": "quota-peer", "tls": {"enabled": True, "server_name": "localhost",
                                                          "certificate_path": str(root / "cert")}}],
    }))
    with nexus_process(binary, config), running(["sing-box", "run", "-c", peer], client, root / "peer.log"):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(5)
            target = listener.getsockname()
            with socks(client, 1, target)[0] as wire:
                payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
                wire.sendall(payload)
                with listener.accept()[0] as accepted:
                    accepted.settimeout(5)
                    observed = bytearray()
                    while chunk := accepted.recv(4096):
                        observed.extend(chunk)
                    assert observed == payload[:12], observed
                usage(binary, control, 0, "alice", upload=12, download=0, byte_limit_denials=1)


if __name__ == "__main__":
    assert f"Revision: {REVISION}" in subprocess.check_output(["sing-box", "version"], text=True)
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-trojan-byte-quota-") as folder:
        check(binary, Path(folder))
    print("Ordered Trojan charged the sniffed TLS payload before forwarding")
