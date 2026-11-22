#!/usr/bin/env python3
"""Exercise the production SS-2022 TCP and native UDP listener with sing-box."""
import base64
import socket
import sys
import tempfile
from pathlib import Path

from detour_network import exact, reserve, running, socks
from dns_rule_support import Echo, proxy_client, udp_client
from wireguard_singbox import start_tcp_echo


def verify(binary, root):
    for size in (16, 32):
        key = root / "key"
        password = base64.b64encode(bytes(range(size))).decode()
        key.write_text(password + "\n")
        key.chmod(0o600)
        port = reserve()
        method = f"2022-blake3-aes-{size * 8}-gcm"
        config = root / "server.kdl"
        config.write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{
  listen host="127.0.0.1" port={port}
  method "{method}"
  key-file "{key}"
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        outbound = {"type": "shadowsocks", "server": "127.0.0.1", "server_port": port,
                    "method": method, "password": password}
        with running([binary, "run", "--config", config], port, root / "ss.log"), proxy_client(root, outbound) as front:
            server, origin, stop = start_tcp_echo("127.0.0.1", socket.AF_INET)
            try:
                with udp_client(front) as (datagram, relay), Echo() as echo:
                    packet = b"\0\0\0\x01\x7f\0\0\x01" + echo.port.to_bytes(2, "big") + b"wave11-udp"
                    datagram.settimeout(4)
                    datagram.sendto(packet, relay)
                    assert datagram.recvfrom(65535)[0] == packet
                with socks(front, 1, ("127.0.0.1", origin))[0] as conn:
                    conn.sendall(b"wave11-tcp")
                    assert exact(conn, 10) == b"wave11-tcp"
            finally:
                stop.set()
                server.close()
        print(f"SS-2022 AES-{size * 8} production TCP and native UDP with sing-box")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="nexus-94d-ss-") as name:
        verify(Path(sys.argv[1]).resolve(strict=True), Path(name))
