#!/usr/bin/env python3
"""Run DoH3 over a WireGuard detour and a 1290-byte inner veth path."""
from contextlib import contextmanager
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile

from detour_network import reserve, running
from dns_encrypted_network import config_text, query
from wireguard_singbox import free_udp_port, wg_keypair


def run(*args):
    return subprocess.check_output(args, text=True).strip()


@contextmanager
def child(*args):
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                _, errors = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, errors = proc.communicate()
            if proc.returncode not in (0, -15):
                print(errors, file=sys.stderr)


def line(process):
    assert select.select([process.stdout], [], [], 8)[0], "peer startup or request timed out"
    report = process.stdout.readline().strip()
    assert report, "peer unexpectedly closed its output"
    return report


def test(binary, peer, root):
    run("ip", "link", "set", "lo", "up")
    with child("unshare", "-n", "sh", "-c", "printf 'ready\\n'; exec sleep 90") as ns:
        assert line(ns) == "ready"
        prefix = ("nsenter", "-t", str(ns.pid), "-n", "--")
        run("ip", "link", "add", "doh94a", "type", "veth", "peer", "name", "doh94b")
        run("ip", "link", "set", "doh94b", "netns", str(ns.pid))
        for commands, name, address in (((), "doh94a", "198.18.94.1"), (prefix, "doh94b", "198.18.94.2")):
            run(*commands, "ip", "addr", "add", f"{address}/30", "dev", name)
            run(*commands, "ip", "link", "set", name, "mtu", os.environ.get("NEXUS_94D_TEST_MTU", "1290"), "up")
        run(*prefix, "ip", "link", "set", "lo", "up")
        run(*prefix, "ip", "route", "add", "10.94.0.2/32", "via", "198.18.94.1")
        run("sysctl", "-qw", "net.ipv4.ip_forward=1")

        def key(name, value):
            path = root / name
            path.write_text(value + "\n")
            path.chmod(0o600)
            return path

        local_private, local_public = wg_keypair()
        peer_private, peer_public = wg_keypair()
        endpoint = root / "wireguard.kdl"
        wg_port, local_port = free_udp_port(), free_udp_port()
        endpoint.write_text(f'''schema-version 1
role "server"
endpoint "wireguard" type="wireguard" {{
  private-key-file "{key('peer.key', peer_private)}"
  listen host="127.0.0.1" port={wg_port}
  device name="wg94" mtu=1420
  local-address "10.94.0.1/32"
  route-include "10.94.0.2/32"
  peer "client" {{
    public-key-file "{key('local.pub', local_public)}"
    endpoint host="127.0.0.1" port={local_port}
    allowed-ip "10.94.0.2/32"
  }}
}}
''')
        cert, priv = root / "dns.pem", root / "dns.key"
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-days", "1", "-subj", "/CN=dns.test", "-addext", "subjectAltName=DNS:dns.test",
            "-out", cert, "-keyout", priv)
        with child(*prefix, "env", "NEXUS_TEST_QUIC_1200=1", f"QLOGDIR={root / 'qlog'}", peer, "-protocol", "h3", "-address", "198.18.94.2:0", "-cert", cert, "-key", priv) as server, \
                child(binary, "endpoint", "run", "--config", endpoint) as wireguard:
            port = int(line(server).rsplit(":", 1)[1])
            print(line(wireguard), flush=True)
            front, dns = reserve(), free_udp_port()
            config = root / "proxy.kdl"
            direct_config = config_text("h3", front, dns, "198.18.94.2", port, cert, free_udp_port())
            direct_config = direct_config.replace('bind-interface="lo"', 'detour="wg"')
            wg = f'''outbound "wg" type="wireguard" {{
  server host="127.0.0.1" port={wg_port}
  private-key-file "{key('local.key', local_private)}"
  peer-public-key-file "{key('peer.pub', peer_public)}"
  udp-bind-port {local_port}
  local-address "10.94.0.2/32"
  mtu 1420
}}
'''
            config.write_text(direct_config.replace("dns {", wg+"dns {", 1))
            with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as capture:
                capture.bind(("doh94a", 0))
                capture.setblocking(False)
                try:
                    with running([binary, "run", "--config", config], front, root / "proxy.log"):
                        query(dns, "mtu1290.test")
                        assert "HTTP/3" in line(server)
                        query(dns, "again1290.test", identifier=23)
                        assert "HTTP/3" in line(server)
                except Exception:
                    print((root / "proxy.log").read_text())
                    print(run("ip", "-s", "link"))
                    print(run("ip", "route"))
                    for trace in (root / "qlog").glob("*.sqlog"):
                        for event in trace.read_text().splitlines():
                            if "connection_closed" in event or "connection_state_updated" in event:
                                print(event)
                    while True:
                        try:
                            packet = capture.recv(4096)
                        except BlockingIOError:
                            break
                        if len(packet)>20:
                            print("veth IPv4", socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20]), len(packet))
                    raise
                observed = []
                while True:
                    try:
                        packet = capture.recv(4096)
                    except BlockingIOError:
                        break
                    if len(packet) >= 28 and packet[12:20] == socket.inet_aton("10.94.0.2")+socket.inet_aton("198.18.94.2"):
                        length, flags = struct.unpack_from("!HH", packet, 2)[0], struct.unpack_from("!H", packet, 6)[0]
                        assert length <= int(os.environ.get("NEXUS_94D_TEST_MTU", "1290")) and flags & 0x3fff == 0, (length, flags)
                        observed.append(length)
                assert observed and max(observed) >= 1228, observed
                print(f"WireGuard DoH3 over veth MTU 1290: 2 answers, unfragmented inner IPv4 sizes {observed}")


if __name__ == "__main__":
    if not os.environ.get("NEXUS_94D_NETNS"):
        os.environ["NEXUS_94D_NETNS"] = str(os.stat("/proc/self/ns/net").st_ino)
        os.execvp("unshare", ["unshare", "-Urn", sys.executable, "-B", __file__, *sys.argv[1:]])
    assert str(os.stat("/proc/self/ns/net").st_ino) != os.environ["NEXUS_94D_NETNS"]
    with tempfile.TemporaryDirectory(prefix="nexus-94d-wg-") as folder:
        test(*(Path(value).resolve(strict=True) for value in sys.argv[1:3]), Path(folder))
