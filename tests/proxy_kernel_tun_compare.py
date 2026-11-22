#!/usr/bin/env python3
"""Compare IPv4 TUN forwarding through external Linux route ownership."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from tailscale_endpoint_network import eventually, ip, line, process
from detour_network import exact

ORIGIN = "192.0.2.2"
ORIGIN_PROXY = "192.0.2.1"
SOURCE = "198.18.1.2"
SOURCE_PROXY = "198.18.1.1"
FRAME = b"routed-tun-payload"
TABLE = "420"
MTU = 1420


def configure(root, label):
    if label == "vp_core":
        path = root / "proxy.yaml"
        path.write_text(f"""mode: rule
log-level: error
tun:
  enable: true
  address: 10.88.0.1
  netmask: 255.255.255.0
  mtu: {MTU}
  auto-route: false
  strict: true
rules: ['MATCH,DIRECT']
""")
        return ["run", "-c", str(path), "-d", str(root)]
    if label == "sing_box":
        path = root / "proxy.json"
        path.write_text(json.dumps({
            "log": {"level": "error"},
            "inbounds": [{"type": "tun", "tag": "tun", "interface_name": "bench-tun",
                          "address": ["10.88.0.1/24"], "mtu": MTU, "dns_mode": "disabled",
                          "auto_route": False, "stack": "system"}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }))
        return ["run", "-c", str(path)]
    path = root / "proxy.kdl"
    path.write_text(f'''schema-version 1
role "client"
inbound "tun" type="tun" {{
    interface-name "bench-tun"
    inet4-address "10.88.0.1/24"
    mtu {MTU}
    auto-route #false
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
    return ["run", "--config", str(path)]


def links():
    return {item["ifname"]: item for item in json.loads(ip("-j", "link", "show"))}


def create_veth(local, remote, address, target, namespace):
    prefix = ("nsenter", "-t", str(namespace.pid), "-n")
    ip("link", "add", local, "type", "veth", "peer", "name", remote)
    ip("link", "set", remote, "netns", str(namespace.pid))
    ip("link", "set", local, "up")
    ip("address", "add", address + "/24", "dev", local)
    ip("link", "set", "lo", "up", prefix=prefix)
    ip("link", "set", remote, "up", prefix=prefix)
    ip("address", "add", target + "/24", "dev", remote, prefix=prefix)
    return prefix


def run_origin():
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind((ORIGIN, 0))
        udp.bind((ORIGIN, 0))
        tcp.listen()
        tcp.settimeout(8)
        udp.settimeout(8)
        print(tcp.getsockname()[1], udp.getsockname()[1], flush=True)
        client, address = tcp.accept()
        with client:
            client.settimeout(3)
            assert address[0] == ORIGIN_PROXY, address
            assert exact(client, len(FRAME)) == FRAME
            client.sendall(FRAME)
        packet, address = udp.recvfrom(1024)
        assert address[0] == ORIGIN_PROXY and packet == FRAME, address
        udp.sendto(packet, address)


def run_source(tcp_port, udp_port):
    with socket.create_connection((ORIGIN, tcp_port), timeout=5) as tcp:
        tcp.sendall(FRAME)
        assert exact(tcp, len(FRAME)) == FRAME
    with socket.socket(type=socket.SOCK_DGRAM) as udp:
        udp.settimeout(4)
        udp.sendto(FRAME, (ORIGIN, udp_port))
        assert udp.recvfrom(1024) == (FRAME, (ORIGIN, udp_port))


def compare(binaries):
    ip("link", "set", "lo", "up")
    subprocess.run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"], check=True)
    own = os.stat("/proc/self/ns/net").st_ino
    script = Path(__file__).resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-tun-parity-") as folder, \
            process(["unshare", "-n", "sleep", "90"]) as source, \
            process(["unshare", "-n", "sleep", "90"]) as origin:
        for ns in (source, origin):
            eventually(lambda: os.stat(f"/proc/{ns.pid}/ns/net").st_ino != own)
        origin_prefix = create_veth("p-out", "o-in", ORIGIN_PROXY, ORIGIN, origin)
        source_prefix = create_veth("p-in", "c-out", SOURCE_PROXY, SOURCE, source)
        ip("route", "add", ORIGIN + "/32", "via", SOURCE_PROXY, prefix=source_prefix)
        ip("rule", "add", "priority", "14020", "iif", "p-in", "lookup", TABLE)
        base = links()
        for label, binary in binaries.items():
            folder_path = Path(folder) / label
            folder_path.mkdir()
            with process([binary, *configure(folder_path, label)]) as proxy:
                def ready():
                    if proxy.poll() is not None:
                        raise RuntimeError(f"{label} stopped before creating its TUN device")
                    found = links()
                    added = [item for name, item in found.items() if name not in base]
                    return added and "UP" in added[0]["flags"]

                eventually(ready)
                device = next(name for name in links() if name not in base)
                assert links()[device]["mtu"] == MTU
                ip("route", "add", "table", TABLE, ORIGIN + "/32", "dev", device)
                try:
                    with process([*origin_prefix, sys.executable, script, "--origin"]) as echo:
                        ports = line(echo).decode().split()
                        start = time.monotonic()
                        subprocess.run([*source_prefix, sys.executable, script, "--source", *ports],
                                       check=True, timeout=10)
                        elapsed = round((time.monotonic() - start) * 1000, 3)
                        assert echo.wait(3) == 0
                finally:
                    ip("route", "del", "table", TABLE, ORIGIN + "/32", "dev", device)
            eventually(lambda: device not in links())
            print(json.dumps({"Implementation": label, "transport": ["IPv4 TCP", "IPv4 UDP"],
                              "mtu": MTU, "elapsed_ms_with_client_startup": elapsed, "device_removed": True}),
                  flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "--origin":
        run_origin()
    elif sys.argv[1] == "--source":
        run_source(*map(int, sys.argv[2:]))
    else:
        assert len(sys.argv) == 5, "run inside unshare -Urn with vp_core sing-box nexus-epoll nexus-uring"
        compare(dict(zip(("vp_core", "sing_box", "nexus_epoll", "nexus_uring"),
                         (str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:]))))
