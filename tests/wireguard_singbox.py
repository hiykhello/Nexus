#!/usr/bin/env python3
"""E2E interop test: Nexus wireguard outbound <-> /usr/bin/sing-box wireguard endpoint."""
import base64
import json
import os
import pty
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from detour_network import exact
from dns_rule_support import nexus_process
from wireguard_provider_network import ReservedRelay

SINGBOX = "/usr/bin/sing-box"


def free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wg_keypair():
    out = subprocess.check_output([SINGBOX, "generate", "wg-keypair"], text=True)
    priv = pub = ""
    for line in out.splitlines():
        if line.startswith("PrivateKey:"):
            priv = line.split(":", 1)[1].strip()
        elif line.startswith("PublicKey:"):
            pub = line.split(":", 1)[1].strip()
    return priv, pub


def start_tcp_echo(host, family):
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(16)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            def handle(c):
                with c:
                    c.settimeout(5)
                    while True:
                        d = c.recv(65536)
                        if not d:
                            break
                        c.sendall(d)

            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def start_udp_echo(host, family):
    srv = socket.socket(family, socket.SOCK_DGRAM)
    srv.bind((host, 0))
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                data, peer = srv.recvfrom(65535)
                srv.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def socks5_tcp_echo(socks_port, dst_ip, dst_port, payload):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=6) as s:
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        if ":" in dst_ip:
            addr = b"\x04" + socket.inet_pton(socket.AF_INET6, dst_ip)
        else:
            addr = b"\x01" + socket.inet_pton(socket.AF_INET, dst_ip)
        s.sendall(b"\x05\x01\x00" + addr + struct.pack("!H", dst_port))
        hdr = s.recv(4)
        assert len(hdr) == 4 and hdr[1] == 0, f"SOCKS5 connect failed: {hdr!r}"
        alen = 4 if hdr[3] == 1 else 16
        s.recv(alen + 2)
        s.sendall(payload)
        got = bytearray()
        while len(got) < len(payload):
            c = s.recv(len(payload) - len(got))
            if not c:
                raise RuntimeError("EOF in SOCKS5 WireGuard TCP")
            got.extend(c)
        assert bytes(got) == payload


def socks5_udp_echo(socks_port, dst_ip, dst_port, payload):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=6) as ctrl:
        ctrl.sendall(b"\x05\x01\x00")
        assert ctrl.recv(2) == b"\x05\x00"
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = ctrl.recv(10)
        assert len(resp) >= 10 and resp[1] == 0
        uport = struct.unpack("!H", resp[8:10])[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            if ":" in dst_ip:
                hdr = b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, dst_ip) + struct.pack("!H", dst_port)
            else:
                hdr = b"\x00\x00\x00\x01" + socket.inet_pton(socket.AF_INET, dst_ip) + struct.pack("!H", dst_port)
            udp.sendto(hdr + payload, ("127.0.0.1", uport))
            rx, _ = udp.recvfrom(65535)
            assert rx.endswith(payload), f"SOCKS5 WireGuard UDP mismatch: {rx!r}"


def launch_and_wait(cmd, ready_substr):
    master, slave = pty.openpty()
    proc = subprocess.Popen(cmd, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    buf = b""
    t0 = time.monotonic()
    while time.monotonic() - t0 < 10:
        import select
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if ready_substr.encode() in buf:
                os.close(master)
                return proc, buf.decode(errors="replace").splitlines()
        elif proc.poll() is not None:
            break
    os.close(master)
    proc.terminate()
    raise RuntimeError(f"failed start {cmd}: " + buf.decode(errors="replace"))


def check_bound_port_conflict(socks_port, destination_port):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as client:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting rejected")
        client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("10.9.0.99") + struct.pack("!H", destination_port))
        reply = exact(client, 10)
        if reply[1] == 0:
            raise RuntimeError("WireGuard ignored the occupied UDP source port")


def main():
    nexus_bin = sys.argv[1] if len(sys.argv) > 1 else "/tmp/nexus-full-test"
    if not os.path.exists(SINGBOX):
        print("skipping: /usr/bin/sing-box not found")
        return

    c_priv, c_pub = wg_keypair()
    s_priv, s_pub = wg_keypair()
    psk = base64.b64encode(os.urandom(32)).decode()

    tcp4, tcp4_p, tcp4_stop = start_tcp_echo("127.0.0.1", socket.AF_INET)
    udp4, udp4_p, udp4_stop = start_udp_echo("127.0.0.1", socket.AF_INET)
    tcp6, tcp6_p, tcp6_stop = start_tcp_echo("::1", socket.AF_INET6)
    udp6, udp6_p, udp6_stop = start_udp_echo("::1", socket.AF_INET6)

    with tempfile.TemporaryDirectory(prefix="nexus-wg-e2e-") as td:
        root = Path(td)
        (root / "c.key").write_text(c_priv + "\n")
        (root / "s.pub").write_text(s_pub + "\n")
        (root / "psk").write_text(psk + "\n")
        for f in ("c.key", "s.pub", "psk"):
            os.chmod(root / f, 0o600)

        wg_port = free_udp_port()
        socks_port = free_tcp_port()
        bind_port = free_udp_port()

        sb_cfg = {
            "log": {"level": "info"},
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg-ep",
                "listen_port": wg_port,
                "private_key": s_priv,
                "address": ["10.9.0.1/24", "fd09::1/64"],
                "peers": [{
                    "public_key": c_pub,
                    "pre_shared_key": psk,
                    "allowed_ips": ["10.9.0.2/32", "fd09::2/128"],
                }],
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        (root / "sb.json").write_text(json.dumps(sb_cfg))

        nx_cfg = f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{
    listen host="127.0.0.1" port={socks_port}
    authentication "none"
}}
outbound "direct" type="direct" {{
    inet4-bind-address "127.0.0.1"
    udp-bind-port {bind_port}
}}
outbound "wg" type="wireguard" {{
    server host="127.0.0.1" port={wg_port}
    detour "direct"
    private-key-file "{root / 'c.key'}"
    peer-public-key-file "{root / 's.pub'}"
    preshared-key-file "{root / 'psk'}"
    local-address "10.9.0.2/32"
    local-address "fd09::2/128"
    mtu 1420
}}
routing {{ final "wg"; }}
'''
        (root / "nx.kdl").write_text(nx_cfg)
        key = root / "ss.key"
        key.write_text(base64.b64encode(os.urandom(16)).decode() + "\n")
        key.chmod(0o600)
        hop_port = free_tcp_port()
        layered_port = free_tcp_port()
        warp_front = free_tcp_port()
        hop_config = root / "hop.kdl"
        hop_config.write_text(f'''schema-version 1
role "server"
inbound "hop" type="shadowsocks" {{
    listen host="127.0.0.1" port={hop_port}
    method "2022-blake3-aes-128-gcm"
    key-file "{key}"
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        layered = root / "layered.kdl"
        lower = f'''outbound "hop" type="shadowsocks" {{
    server host="127.0.0.1" port={hop_port}
    method "2022-blake3-aes-128-gcm"
    key-file "{key}"
    udp-over-tcp "v2"
}}
'''
        layered.write_text(nx_cfg.replace(f'port={socks_port}', f'port={layered_port}', 1)
                           .replace('\noutbound "wg"', '\n' + lower + 'outbound "wg"')
                           .replace('detour "direct"', 'detour "hop"'))

        def exchange(front):
            # The sing-box endpoint maps targets in its tunnel prefixes to
            # the local echo services.
            socks5_tcp_echo(front, "10.9.0.99", tcp4_p, b"wg-v4-tcp-" * 128)
            socks5_udp_echo(front, "10.9.0.99", udp4_p, b"wg-v4-udp-ok")
            socks5_tcp_echo(front, "fd09::99", tcp6_p, b"wg-v6-tcp-" * 128)
            socks5_udp_echo(front, "fd09::99", udp6_p, b"wg-v6-udp-ok")

        p_sb, _ = launch_and_wait([SINGBOX, "run", "-c", str(root / "sb.json")], "sing-box started")
        try:
            p_nx, _ = launch_and_wait([nexus_bin, "run", "--config", str(root / "nx.kdl")], "SOCKS5 listening on")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blocker:
                    blocker.bind(("127.0.0.1", bind_port))
                    check_bound_port_conflict(socks_port, tcp4_p)
                exchange(socks_port)
            finally:
                p_nx.terminate()
                p_nx.wait(timeout=5)
                if p_nx.returncode:
                    raise RuntimeError(f"Nexus exited with status {p_nx.returncode}")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as released:
                released.bind(("127.0.0.1", bind_port))
            print("WireGuard direct detour passed IPv4/IPv6 TCP+UDP, bind conflict, retry and port release")
            with nexus_process(nexus_bin, str(hop_config)), nexus_process(nexus_bin, str(layered)):
                exchange(layered_port)
            print("WireGuard through Shadowsocks UDP-over-TCP passed IPv4/IPv6 TCP+UDP and shutdown")
            relay = ReservedRelay(socket.AF_INET, "127.0.0.1", wg_port, bind_port, inject_faults=False)
            try:
                warp = root / "warp.kdl"
                warp.write_text(nx_cfg.replace(f'port={socks_port}', f'port={warp_front}', 1)
                                .replace(f'port={wg_port}', f'port={relay.port}', 1)
                                .replace('    mtu 1420', '    reserved 17 34 51\n    mtu 1420'))
                with nexus_process(nexus_bin, str(warp)):
                    exchange(warp_front)
            finally:
                relay.close()
            for direction, packet_type in (("nexus-to-go", 1), ("go-to-nexus", 2), ("nexus-to-go", 4), ("go-to-nexus", 4)):
                if relay.errors or not relay.counts[f"{direction}-type{packet_type}"]:
                    raise RuntimeError(f"WARP packet evidence missing: {relay.errors!r}, {relay.counts!r}")
            print("WireGuard WARP reserved bytes verified on handshake and dual-stack business traffic")
        finally:
            p_sb.terminate()
            p_sb.wait(timeout=5)

    for s in (tcp4_stop, udp4_stop, tcp6_stop, udp6_stop):
        s.set()
    for s in (tcp4, udp4, tcp6, udp6):
        s.close()


if __name__ == "__main__":
    main()
