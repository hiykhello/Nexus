#!/usr/bin/env python3
"""Check TCP and UDP route publication on Hysteria 2 and TUIC ingress."""
from proxy_listener_reload_network import reload as reload_listeners
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile

from detour_network import exact, socks
from dns_rule_support import connect, nexus_process, proxy_client, udp_client
from tun_inbound_e2e import start_tcp_echo, start_udp_echo
from tuic_singbox import REVISION
from udp_bind_port_network import certificate


def peer_config(root, protocol, port):
    password = "test-password"
    passfile = root / "password"
    passfile.write_text(password + "\n")
    passfile.chmod(0o600)
    auth = f'user "peer" password-file="{passfile}"'
    outbound = {"type": protocol, "server": "127.0.0.1", "server_port": port, "password": password,
                "tls": {"enabled": True, "server_name": "localhost", "alpn": ["h3"],
                        "certificate_path": str(root / "cert")}}
    if protocol == "tuic":
        uid = "b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f"
        uuid = root / "uuid"
        uuid.write_text(uid + "\n")
        uuid.chmod(0o600)
        auth += f' uuid-file="{uuid}"'
        outbound.update(uuid=uid, congestion_control="cubic", udp_relay_mode="native")
    path = root / "proxy.kdl"
    path.write_text(f'''schema-version 1
role "server"
inbound "edge" type="{protocol}" {{
    listen host="127.0.0.1" port={port}
    authentication {{ {auth}; }}
    tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}}
outbound "direct" type="direct"
outbound "block" type="block"
routing {{
    rule-set "policy" path="route.kdl" format="kdl"
    rules {{ - kind="rule-set" value="policy" outbound="block"; }}
    default-outbound "direct"
}}
''')
    return path, outbound


def rules(root, cidr):
    path = root / "route.kdl"
    update = path.with_suffix(".candidate")
    update.write_text(f'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="{cidr}"\n')
    update.replace(path)


def transfer(stream, data):
    stream.sendall(data)
    assert exact(stream, len(data)) == data


def check(binary, root, protocol):
    with socket.socket(type=socket.SOCK_DGRAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    path, outbound = peer_config(root, protocol, port)
    tcp, tcp_port, tcp_stop = start_tcp_echo("127.0.0.1")
    udp, udp_port, udp_stop = start_udp_echo("127.0.0.1")
    prefix = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_port.to_bytes(2, "big")
    rules(root, "192.0.2.0/24")
    try:
        with nexus_process(binary, path) as host, proxy_client(root, outbound) as front:
            with connect(front):
                pass
            with socks(front, 1, ("127.0.0.1", tcp_port))[0] as stream, udp_client(front) as (old_udp, relay):
                transfer(stream, b"before")
                block = bytes(range(256)) * 32
                for _ in range(10):
                    transfer(stream, block)
                old_udp.sendto(prefix+b"before", relay)
                assert old_udp.recvfrom(4096)[0] == prefix+b"before"
                rules(root, "127.0.0.1/32")
                assert reload_listeners(host) is None
                transfer(stream, b"old")
                old_udp.sendto(prefix+b"old", relay)
                assert old_udp.recvfrom(4096)[0] == prefix+b"old"
                with udp_client(front) as (current_udp, current_relay):
                    current_udp.sendto(prefix+b"blocked", current_relay)
                    assert not select.select([current_udp], [], [], .35)[0]
                with socket.create_connection(("127.0.0.1", front), timeout=3) as fresh:
                    fresh.sendall(b"\x05\x01\x00")
                    assert exact(fresh, 2) == b"\x05\x00"
                    fresh.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + tcp_port.to_bytes(2, "big"))
                    result = exact(fresh, 2)
                    if result[1] == 0:
                        family = exact(fresh, 2)[1]
                        exact(fresh, 6 if family == 1 else 18)
                        fresh.sendall(b"blocked")
                        try:
                            assert fresh.recv(32) == b""
                        except ConnectionResetError:
                            pass
    finally:
        tcp_stop.set()
        udp_stop.set()
        tcp.close()
        udp.close()


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    assert f"Revision: {REVISION}" in subprocess.check_output(["sing-box", "version"], text=True)
    with tempfile.TemporaryDirectory(prefix="nexus-quic-reload-") as directory:
        root = Path(directory)
        certificate(root)
        for protocol in ("hysteria2", "tuic"):
            check(binary, root, protocol)
            print(f"{protocol}: old TCP and UDP flows retained policy, new flows used the refreshed rules")
