#!/usr/bin/env python3
"""Wave 25 Track C E2E: routed TUN live hot-reload (inline routing + DNS) & strict-route loopback coexistence."""
import http.client
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from dns_rule_support import exact, free_port, wire_name
from proxy_listener_reload_network import reload as reload_signal
from tailscale_endpoint_network import eventually, ip, line, process
from tun_inbound_e2e import start_tcp_echo, start_udp_echo


class FixedDnsServer:
    """Minimal UDP DNS A-record server returning one fixed IPv4 address."""

    def __init__(self, answer_ip: str, host: str = "127.0.0.1"):
        self.answer_ip = answer_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.queries = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        rdata = socket.inet_aton(self.answer_ip)
        while not self.stop_event.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if len(data) < 12:
                continue
            self.queries += 1
            pos = 12
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            qend = pos + 5
            if qend > len(data):
                continue
            qtype = struct.unpack("!H", data[pos + 1:pos + 3])[0]
            question = data[12:qend]
            if qtype == 1:
                hdr = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180, 1, 1, 0, 0)
                ans = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + rdata
                self.sock.sendto(hdr + question + ans, peer)
            else:
                soa = b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(16) + struct.pack("!I", 60)
                hdr = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180, 1, 0, 1, 0)
                self.sock.sendto(hdr + question + soa, peer)

    def close(self):
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)


def dns_query_a(host: str, port: int, domain: str) -> str:
    qid = 0x4242
    req = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + wire_name(domain) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4)
        s.sendto(req, (host, port))
        resp, _ = s.recvfrom(4096)
    assert len(resp) >= 16 and struct.unpack("!H", resp[:2])[0] == qid, resp.hex()
    assert struct.unpack("!H", resp[6:8])[0] >= 1, f"no A answer in {resp.hex()}"
    return socket.inet_ntoa(resp[-4:])


def http_post_reload(port: int) -> bool:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", "/v1/reload")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        assert resp.status == 202, (resp.status, body)
    finally:
        conn.close()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            c.request("GET", "/v1/events")
            r = c.getresponse()
            ev = r.read().decode("utf-8", errors="replace")
        finally:
            c.close()
        if "reload-succeeded" in ev:
            return True
        if "reload-failed" in ev:
            return False
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for HTTP reload completion event")


def socks5_connect_domain(proxy_port: int, domain: str, target_port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    s.settimeout(5)
    s.sendall(b"\x05\x01\x00")
    assert exact(s, 2) == b"\x05\x00"
    enc = domain.encode("ascii")
    s.sendall(bytes([5, 1, 0, 3, len(enc)]) + enc + struct.pack("!H", target_port))
    hdr = exact(s, 4)
    assert hdr[:2] == b"\x05\x00", hdr
    if hdr[3] == 1:
        exact(s, 6)
    elif hdr[3] == 4:
        exact(s, 18)
    else:
        n = exact(s, 1)[0]
        exact(s, n + 2)
    return s


def socks5_connect_ipv4(proxy_port: int, ip_str: str, target_port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    s.settimeout(5)
    s.sendall(b"\x05\x01\x00")
    assert exact(s, 2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip_str) + struct.pack("!H", target_port))
    hdr = exact(s, 10)
    assert hdr[:2] == b"\x05\x00", hdr
    return s


def http_connect_echo(proxy_port: int, ip_str: str, target_port: int, payload: bytes) -> None:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as s:
        s.settimeout(5)
        req = f"CONNECT {ip_str}:{target_port} HTTP/1.1\r\nHost: {ip_str}:{target_port}\r\n\r\n".encode()
        s.sendall(req)
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(1024)
            assert chunk, "HTTP CONNECT closed before headers"
            buf.extend(chunk)
        assert buf.startswith(b"HTTP/1.1 200"), bytes(buf)
        s.sendall(payload)
        assert exact(s, len(payload)) == payload


def ifindex(dev: str) -> int:
    return socket.if_nametoindex(dev)


def test_inline_routing_hot_reload(binary: str, root: Path) -> None:
    address = "198.51.100.10"
    dest = address + "/32"
    ip("addr", "add", dest, "dev", "lo")
    ip("route", "add", "local", dest, "dev", "lo", "table", "100", "src", "127.0.0.1")
    ip("rule", "del", "priority", "0")
    ip("rule", "add", "priority", "1", "fwmark", "43", "lookup", "100")
    ip("rule", "add", "priority", "2", "to", dest, "table", "main")
    ip("rule", "add", "priority", "3", "lookup", "local")

    config = root / "inline-reload.kdl"

    def write_cfg(rule_line: str) -> None:
        config.write_text(f'''schema-version 1
role "client"
inbounds {{
  inbound "tun-in" type="tun" {{
    interface-name "nx-reload"
    inet4-address "10.91.0.1/30"
    socket-mark 43
    endpoint-independent-nat #false
  }}
}}
outbound "direct" type="direct"
outbound "block" type="block"
routing {{
  rules udp=#true {{
    {rule_line}
    - final "direct"
  }}
}}
''')

    write_cfg('- ip-cidr "203.0.113.0/24" to="block"')
    with subprocess.Popen(["stdbuf", "-oL", binary, "run", "--config", str(config)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as proxy:
        servers = []
        try:
            assert select.select([proxy.stdout], [], [], 6)[0] and b"TUN listening" in proxy.stdout.readline()
            idx0 = ifindex("nx-reload")
            ip("route", "add", dest, "dev", "nx-reload", "src", "10.91.0.1")
            tcp, tcp_port, tcp_stop = start_tcp_echo(address)
            udp, udp_port, udp_stop = start_udp_echo(address)
            servers.extend(((tcp, tcp_stop), (udp, udp_stop)))
            target = (address, udp_port)
            with socket.create_connection((address, tcp_port), timeout=4) as stream, \
                 socket.socket(type=socket.SOCK_DGRAM) as prev_udp, socket.socket(type=socket.SOCK_DGRAM) as fresh_udp:
                prev_udp.settimeout(3)
                prev_udp.sendto(b"before", target)
                assert prev_udp.recvfrom(4096) == (b"before", target)
                stream.sendall(b"before")
                assert exact(stream, 6) == b"before"

                write_cfg(f'- ip-cidr "{dest}" to="block"')
                assert reload_signal(proxy) is None
                assert ifindex("nx-reload") == idx0, "TUN device was recreated on inline route reload"

                prev_udp.sendto(b"preserved", target)
                assert prev_udp.recvfrom(4096) == (b"preserved", target)
                stream.sendall(b"preserved")
                assert exact(stream, 9) == b"preserved"

                fresh_udp.sendto(b"blocked", target)
                assert not select.select([fresh_udp], [], [], 0.35)[0]
                try:
                    with socket.create_connection((address, tcp_port), timeout=2) as fresh_tcp:
                        fresh_tcp.sendall(b"blocked")
                        assert fresh_tcp.recv(32) == b""
                except (ConnectionRefusedError, ConnectionResetError):
                    pass

                write_cfg(f'- ip-cidr "{dest}" to="direct"')
                assert reload_signal(proxy) is None
                assert ifindex("nx-reload") == idx0, "TUN device was recreated on second inline route reload"
                with socket.create_connection((address, tcp_port), timeout=4) as reopened:
                    reopened.sendall(b"unblocked")
                    assert exact(reopened, 9) == b"unblocked"
        finally:
            proxy.terminate()
            _, errors = proxy.communicate(timeout=5)
            for srv, stop in servers:
                stop.set()
                srv.close()
            assert proxy.returncode == 0, errors
    print("PASS test 1: routed TUN inline routing hot-reload preserved established flows & ifindex")


def test_live_dns_swap(binary: str, root: Path) -> None:
    ip_a, ip_b, dns_vip = "198.51.100.11", "198.51.100.12", "198.51.100.85"
    for addr in (ip_a, ip_b):
        ip("addr", "add", addr + "/32", "dev", "lo")
        ip("route", "add", "local", addr + "/32", "dev", "lo", "table", "101", "src", "127.0.0.1")
    ip("rule", "del", "priority", "0")
    ip("rule", "add", "priority", "1", "fwmark", "44", "lookup", "101")
    ip("rule", "add", "priority", "2", "to", dns_vip + "/32", "table", "main")
    ip("rule", "add", "priority", "3", "lookup", "local")

    dns_a = FixedDnsServer(ip_a)
    dns_b = FixedDnsServer(ip_b)
    common_port = free_port()

    def start_tagged_echo(host: str, tag: bytes):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, common_port))
        srv.listen(8)
        srv.settimeout(0.1)
        stop = threading.Event()

        def run():
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with c:
                    c.sendall(tag)

        threading.Thread(target=run, daemon=True).start()
        return srv, stop

    srv_a, sa = start_tagged_echo(ip_a, b"PEER_A")
    srv_b, sb = start_tagged_echo(ip_b, b"PEER_B")
    ctl_port = free_port()
    dns_listen = free_port()
    mixed_port = free_port()
    config = root / "tun-dns-live.kdl"

    def write_cfg(upstream_port: int) -> None:
        config.write_text(f'''schema-version 1
role "client"
control http-listen="127.0.0.1:{ctl_port}"
inbounds {{
  inbound "mixed-in" type="mixed" {{
    listen host="127.0.0.1" port={mixed_port}
    authentication "none"
  }}
  inbound "tun-in" type="tun" {{
    interface-name "nx-dns-live"
    inet4-address "10.92.0.1/30"
    socket-mark 44
    endpoint-independent-nat #false
  }}
}}
outbound "direct" type="direct"
dns {{
  listen host="127.0.0.1" port={dns_listen}
  server "up" type="udp" host="127.0.0.1" port={upstream_port}
  final "up"
}}
routing {{
  rules udp=#true {{
    - action="hijack-dns" {{ ip-cidr "{dns_vip}/32"; port 53; }}
    - final "direct"
  }}
}}
''')

    write_cfg(dns_a.port)
    with subprocess.Popen(["stdbuf", "-oL", binary, "run", "--config", str(config)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as proxy:
        try:
            seen = set()
            deadline = time.monotonic() + 8
            while len(seen) < 2 and time.monotonic() < deadline:
                assert select.select([proxy.stdout], [], [], 2)[0]
                text = proxy.stdout.readline().decode("utf-8", errors="replace")
                if "Mixed listening" in text:
                    seen.add("mixed")
                if "TUN listening on nx-dns-live" in text:
                    seen.add("tun")
            assert len(seen) == 2, f"startup incomplete: {seen}"
            idx0 = ifindex("nx-dns-live")
            ip("route", "add", dns_vip + "/32", "dev", "nx-dns-live", "src", "10.92.0.1")

            assert dns_query_a(dns_vip, 53, "live.test") == ip_a
            assert dns_query_a("127.0.0.1", dns_listen, "live.test") == ip_a
            with socks5_connect_domain(mixed_port, "live.test", common_port) as s:
                assert exact(s, 6) == b"PEER_A"

            write_cfg(dns_b.port)
            assert http_post_reload(ctl_port), "HTTP reload failed on live DNS server swap"
            assert ifindex("nx-dns-live") == idx0, "TUN device was recreated on live DNS swap"

            assert dns_query_a(dns_vip, 53, "live.test") == ip_b
            assert dns_query_a("127.0.0.1", dns_listen, "live.test") == ip_b
            with socks5_connect_domain(mixed_port, "live.test", common_port) as s:
                assert exact(s, 6) == b"PEER_B"
        finally:
            proxy.terminate()
            _, errors = proxy.communicate(timeout=5)
            sa.set(); srv_a.close()
            sb.set(); srv_b.close()
            dns_a.close(); dns_b.close()
            assert proxy.returncode == 0, errors
    print("PASS test 2: routed TUN live DNS server swap succeeded without TUN teardown")


def test_strict_route_loopback_coexistence(binary: str, root: Path) -> None:
    def validate_kdl(name: str, text: str) -> subprocess.CompletedProcess:
        p = root / name
        p.write_text(text)
        return subprocess.run([binary, "check", "--config", str(p)], capture_output=True, text=True)

    good = validate_kdl("strict-good.kdl", '''schema-version 1
role "client"
inbounds {
  inbound "mixed-in" type="mixed" { listen host="127.0.0.1" port=17890; authentication "none"; }
  inbound "socks-v6" type="socks5" { listen host="::1" port=17891; authentication "none"; }
  inbound "tun-in" type="tun" { interface-name "nx-v"; inet4-address "198.51.100.1/32"; auto-route #true; strict-route #true; }
}
outbound "direct" type="direct"
routing { final "direct"; }
''')
    assert good.returncode == 0, good.stderr

    bad_any = validate_kdl("strict-bad-any.kdl", '''schema-version 1
role "client"
inbounds {
  inbound "mixed-in" type="mixed" { listen host="0.0.0.0" port=17890; authentication "none"; }
  inbound "tun-in" type="tun" { interface-name "nx-v"; inet4-address "198.51.100.1/32"; auto-route #true; strict-route #true; }
}
outbound "direct" type="direct"
routing { final "direct"; }
''')
    assert bad_any.returncode != 0 and "loopback mixed, socks5 or http" in bad_any.stderr, bad_any.stderr

    bad_two_tun = validate_kdl("strict-bad-two-tun.kdl", '''schema-version 1
role "client"
inbounds {
  inbound "tun-a" type="tun" { interface-name "nx-a"; inet4-address "198.51.100.1/32"; auto-route #true; strict-route #true; }
  inbound "tun-b" type="tun" { interface-name "nx-b"; inet4-address "198.51.100.2/32"; }
}
outbound "direct" type="direct"
routing { final "direct"; }
''')
    assert bad_two_tun.returncode != 0 and "loopback mixed, socks5 or http" in bad_two_tun.stderr, bad_two_tun.stderr

    with process(["unshare", "-n", "sleep", "60"]) as peer_ns:
        prefix = ("nsenter", "-t", str(peer_ns.pid), "-n")
        eventually(lambda: os.stat(f"/proc/{peer_ns.pid}/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino)
        ip("link", "add", "nxphys", "type", "veth", "peer", "name", "nxpeer")
        ip("link", "set", "nxpeer", "netns", str(peer_ns.pid))
        ip("link", "set", "nxphys", "up")
        ip("link", "set", "lo", "up", prefix=prefix)
        ip("link", "set", "nxpeer", "up", prefix=prefix)
        ip("address", "add", "192.0.2.1/24", "dev", "nxphys")
        ip("address", "add", "192.0.2.2/24", "dev", "nxpeer", prefix=prefix)

        mixed_port = free_port()
        ctl_port = free_port()
        cfg = root / "strict-coexist.kdl"
        base_cfg = f'''schema-version 1
role "client"
control http-listen="127.0.0.1:{ctl_port}"
inbounds {{
  inbound "mixed-in" type="mixed" {{
    listen host="127.0.0.1" port={mixed_port}
    authentication "none"
  }}
  inbound "tun-in" type="tun" {{
    interface-name "nx-strict-mix"
    inet4-address "198.51.100.1/32"
    auto-route #true
    strict-route #true
  }}
}}
outbound "direct" type="direct"
dns {{
  server "up" type="udp" host="192.0.2.2" port=53
  final "up"
}}
'''
        cfg.write_text(base_cfg + 'routing { final "direct"; }\n')
        echo_script = Path(__file__).with_name("tailscale_endpoint_network.py")
        with process([*prefix, sys.executable, str(echo_script), "--echo"], stdin=subprocess.PIPE) as target:
            assert line(target) == b"ready\n"
            with process(["stdbuf", "-oL", binary, "run", "--config", str(cfg)], bufsize=0) as nexus:
                seen = set()
                for _ in range(4):
                    out = line(nexus).decode("utf-8", errors="replace")
                    if "Mixed listening on 127.0.0.1:" in out:
                        seen.add("mixed")
                    if "TUN listening on nx-strict-mix" in out:
                        seen.add("tun")
                    if len(seen) == 2:
                        break
                assert len(seen) == 2, f"coexisting strict-route startup failed: {seen}"
                # 1. TUN strict-route direct capture
                with socket.create_connection(("192.0.2.2", 18080), timeout=5) as s:
                    s.settimeout(5)
                    s.sendall(b"via-tun")
                    assert exact(s, 7) == b"via-tun"
                # 2. Loopback SOCKS5 & HTTP CONNECT coexistence (loop-free via fwmark)
                with socks5_connect_ipv4(mixed_port, "192.0.2.2", 18080) as s:
                    s.sendall(b"via-socks5")
                    assert exact(s, 10) == b"via-socks5"
                http_connect_echo(mixed_port, "192.0.2.2", 18080, b"via-http-connect")
                # 3. Changing strict-route DNS hijack via reload must fail cleanly without tearing down TUN
                cfg.write_text(base_cfg + 'routing { rules udp=#true { - port 53 action="hijack-dns"; - final "direct"; }; }\n')
                assert not http_post_reload(ctl_port), "strict-route DNS hijack change must be rejected on hot reload"
    print("PASS test 3: Linux strict-route + loopback mixed coexistence & hijack guard verified")


def run_subtest(binary: str, case: str) -> None:
    ip("link", "set", "lo", "up")
    with tempfile.TemporaryDirectory(prefix=f"nexus-w25-{case}-") as tmp:
        root = Path(tmp)
        if case == "inline":
            test_inline_routing_hot_reload(binary, root)
        elif case == "dns":
            test_live_dns_swap(binary, root)
        elif case == "strict":
            test_strict_route_loopback_coexistence(binary, root)
        else:
            raise ValueError(case)


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    if len(sys.argv) == 2:
        for case in ("inline", "dns", "strict"):
            subprocess.run(["unshare", "-Urn", "--", sys.executable, __file__, binary, case], check=True)
        print("WAVE 25 TUN HOT-RELOAD & STRICT-ROUTE COEXISTENCE E2E PASSED")
    else:
        run_subtest(binary, sys.argv[2])
