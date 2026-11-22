#!/usr/bin/env python3
"""Production HTTPUpgrade KDL/CLI with real TLS, VLESS TCP/XUDP and fixed Go peers."""
import argparse
import contextlib
import json
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from anytls_network import Origin
from anytls_proxy_network import targets_closed
from detour_network import running
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, proxy_client, udp_client
from httpupgrade_network import origin as deferred_origin
from httpupgrade_tls_network import PATH, PAYLOAD, RESPONSE, UUID, certificates, client_context, header, server_context
from grpc_tls_network import untouched_target

HOST, TARGET = "cover.example", "/nexus%2Dupgrade?ignored=1"
ALICE = "10111213-1415-1617-1819-1a1b1c1d1e1f"


def transport(host=HOST, path=PATH):
    return {"type": "httpupgrade", "host": host, "path": path, "headers": {"X-Test": "from-go"}}


def transport_kdl(host=HOST, path=TARGET, response=False):
    authority = f"host {json.dumps(host)};" if host is not None else ""
    return f'''transport "httpupgrade" {{ {authority} path {json.dumps(path)}; header "X-Test" "from-{'server' if response else 'nexus'}"; }}'''


def outbound(root, remote, host=HOST, path=TARGET, name="localhost", ca="cert"):
    return f'''server host="127.0.0.1" port={remote}
 authentication {{ uuid-file "{root / 'uuid'}"; }}
 tls {{ server-name "{name}"; ca-file "{root / ca}"; verify #true; }}
 {transport_kdl(host, path)}'''


def client_config(root, front, remote, workers, dns, lower=None, **options):
    detour = 'detour "lower";' if lower else ""
    fast_open = 'tcp-fast-open #true;' if os.getenv('NEXUS_TEST_FAST_OPEN') and not lower else ''
    lower_config = f'''outbound "lower" type="trojan" {{ server host="127.0.0.1" port={lower};
 authentication {{ password-file "{root / 'password'}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}''' if lower else ""
    path = root / "client.kdl"
    path.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{ {outbound(root, remote, **options)}
 {fast_open}
 {detour}
}}
{lower_config}
dns {{ server "remote" type="udp" host="127.0.0.1" port={dns.port}; }}
routing {{ default-outbound "edge"; }}
''')
    return path


def server_config(root, front, workers, dns, host=HOST):
    path = root / "server.kdl"
    path.write_text(f'''schema-version 1
role "server"
workers {workers}
inbound "upgrade-in" type="vless" {{ listen host="127.0.0.1" port={front};
 authentication {{ user "bob" uuid-file="{root / 'uuid'}"; user "alice" uuid-file="{root / 'alice'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 {transport_kdl(host, PATH, response=True)}
}}
outbound "direct" type="direct"
dns {{
 server "remote" type="udp" host="127.0.0.1" port={dns.port}
 rule domain="identity.test" auth-user="alice" action="reject"
 rule domain="source.test" source-ip-cidr="127.0.0.1/32" source-port-range="1-65535" action="reject"
 rule domain="listener.test" inbound="upgrade-in" action="reject"
 rule domain="network.test" network="udp" action="reject"
 final "remote"
}}
routing {{ default-outbound "direct"; }}
''')
    return path


def address(host, port):
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        wire = bytes([4 if family == socket.AF_INET6 else 1]) + socket.inet_pton(family, host)
    except OSError:
        wire = b"\x03" + bytes([len(host.encode())]) + host.encode()
    return wire + struct.pack("!H", port)


def begin(front, target, host="127.0.0.1", accepted=True):
    client = connect(front)
    try:
        client.sendall(b"\x05\x01\x00")
        if exact(client, 2) != b"\x05\x00":
            raise RuntimeError("HTTPUpgrade CLI SOCKS greeting")
        client.sendall(b"\x05\x01\x00" + address(host, target))
        reply = exact(client, 4)
        if reply[3] not in (1, 4) or (reply[1] == 0) != accepted:
            raise RuntimeError(f"HTTPUpgrade CLI SOCKS connect: {reply!r}, expected={accepted}")
        exact(client, 6 if reply[3] == 1 else 18)
        return client
    except Exception:
        client.close()
        raise


def traffic(front, label, empty):
    with deferred_origin() as target, begin(front, target) as client:
        client.sendall(PAYLOAD)
        client.shutdown(socket.SHUT_WR)
        if exact(client, len(PAYLOAD)) != PAYLOAD or client.recv(1):
            raise RuntimeError(f"{label}: 512KiB delayed echo or half-close mismatch")
    with Echo() as target:
        for host in ("127.0.0.1", "::1", "origin.test"):
            with begin(front, target.port, host) as client:
                client.sendall(b"upgrade-cli-address")
                if exact(client, 19) != b"upgrade-cli-address" or client.recv(1):
                    raise RuntimeError(f"{label}: TCP domain/dual-stack mismatch: {host}")
        # Keep the stronger mixed-family single association for a Nexus pair.
        # The fixed Go direct UDP owner selects its family on the first target.
        groups = (("127.0.0.1", "::1", "origin.test"),) if empty else (("127.0.0.1",), ("::1",), ("origin.test",))
        for hosts in groups:
            with udp_client(front) as (client, relay):
                for host in hosts:
                    for payload in ((b"one", b"", bytes(range(256)) * 32) if empty else (b"one", bytes(range(256)) * 32)):
                        client.sendto(b"\x00\x00\x00" + address(host, target.port) + payload, relay)
                        try:
                            received = client.recvfrom(65535)[0]
                        except TimeoutError as error:
                            raise RuntimeError(f"{label}: XUDP timeout: host={host}, size={len(payload)}, origin={list(map(len, target.received))}") from error
                        family = received[3] if len(received) >= 4 else 0
                        end = 10 if family == 1 else 22 if family == 4 else 7 + received[4] if family == 3 and len(received) >= 5 else 0
                        valid_source = False
                        if end and len(received) >= end:
                            if family == 3:
                                valid_source = host == "origin.test" and received[5:end - 2] == host.encode()
                            else:
                                source = socket.inet_ntop(socket.AF_INET if family == 1 else socket.AF_INET6, received[4:end - 2])
                                valid_source = source in ("127.0.0.1", "::1") if host == "origin.test" else source == host
                        if not valid_source or int.from_bytes(received[end - 2:end], "big") != target.port or received[end:] != payload:
                            raise RuntimeError(f"{label}: XUDP address/payload mismatch: {host}, size={len(payload)}, response={received[:40]!r}")
    print(f"HTTPUpgrade CLI {label}: 512KiB/half-close, TCP+XUDP domain/v4/v6 passed; "
          f"empty={'preserved by Nexus pair' if empty else 'omitted for pinned Go XUDP limitation'}", flush=True)


@contextlib.contextmanager
def sing_server(root, front, lower, dns):
    tls = {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key"), "alpn": ["http/1.1"]}
    config = {"log": {"level": "warn"}, "inbounds": [
        {"type": "vless", "listen": "127.0.0.1", "listen_port": front, "users": [{"uuid": UUID}], "tls": tls, "transport": transport()},
        {"type": "trojan", "listen": "127.0.0.1", "listen_port": lower, "users": [{"password": "upgrade-lower"}], "tls": tls}],
        "dns": {"servers": [{"type": "udp", "tag": "local", "server": "127.0.0.1", "server_port": dns.port}], "final": "local"},
        "route": {"default_domain_resolver": {"server": "local", "strategy": "ipv4_only"}}, "outbounds": [{"type": "direct"}]}
    path = root / "go-server.json"
    path.write_text(json.dumps(config))
    subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
    with running(["sing-box", "run", "-c", path], front, root / "go-server.log"):
        yield


def go_outbound(root, remote):
    # Go's configured Path is URL.Path; its '?' is escaped into the path.
    # Nexus' configured client path is the literal on-wire origin-form target.
    return {"type": "vless", "server": "127.0.0.1", "server_port": remote, "uuid": UUID, "transport": transport(),
            "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(root / "cert"), "alpn": ["http/1.1"]}}


def request(host=HOST, path=TARGET, extra=b""):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n".encode() + extra + b"\r\n"


def vless(host, port, user=UUID):
    target = address(host, port)
    kind = {1: 1, 3: 2, 4: 3}[target[0]]
    return b"\x00" + bytes.fromhex(user.replace("-", "")) + b"\x00\x01" + target[-2:] + bytes([kind]) + target[1:-2]


def raw_rejections(root, remote, dns):
    cases = (("host", request(host="wrong.example")), ("path", request(path="/wrong")),
             ("duplicate", request(extra=b"Connection: Upgrade\r\n")),
             ("framing", request(extra=b"Content-Length: 1\r\n")))
    with untouched_target() as target:
        before = len(dns.seen)
        for label, wire in cases:
            with connect(remote) as raw, client_context(root, ["http/1.1"]).wrap_socket(raw, server_hostname="localhost") as peer:
                peer.sendall(wire + vless("127.0.0.1", target) + b"must-not-forward")
                try:
                    if peer.recv(1):
                        raise RuntimeError(f"HTTPUpgrade CLI accepted invalid {label}")
                except (ConnectionResetError, ssl.SSLError):
                    pass
            if before != len(dns.seen):
                raise RuntimeError(f"HTTPUpgrade CLI invalid {label} reached DNS")
        for protocols in ([], ["h2"]):
            with connect(remote) as raw:
                try:
                    with client_context(root, protocols).wrap_socket(raw, server_hostname="localhost"):
                        raise RuntimeError("HTTPUpgrade CLI accepted absent http/1.1 ALPN")
                except ssl.SSLError:
                    pass
    print("HTTPUpgrade CLI host/path/header/framing and required-h1 rejection stayed before target", flush=True)


def dns_context(root, remote, dns):
    with Echo() as target:
        for name, user, allowed in (("identity.test", UUID, True), ("identity.test", ALICE, False),
                                    ("source.test", UUID, False), ("listener.test", UUID, False), ("network.test", UUID, True)):
            before = len(dns.seen)
            destination = contextlib.nullcontext(target.port) if allowed else untouched_target()
            with destination as port, connect(remote) as raw, client_context(root, ["http/1.1"]).wrap_socket(raw, server_hostname="localhost") as peer:
                peer.sendall(request() + vless(name, port, user) + b"identity-check")
                response = header(peer)
                if not response.startswith(b"HTTP/1.1 101 ") or b"x-test: from-server\r\n" not in response.lower():
                    raise RuntimeError("HTTPUpgrade CLI response extra-header missing")
                if allowed:
                    if exact(peer, 2) != b"\x00\x00" or exact(peer, 14) != b"identity-check":
                        raise RuntimeError("HTTPUpgrade CLI authenticated DNS context lost payload")
                else:
                    try:
                        if peer.recv(1):
                            raise RuntimeError("HTTPUpgrade CLI rejected DNS context returned VLESS/application bytes")
                    except (ConnectionResetError, ssl.SSLError):
                        pass
            if not allowed and before != len(dns.seen):
                raise RuntimeError(f"HTTPUpgrade CLI DNS rejection lost identity/source/inbound: {name}")
    print("HTTPUpgrade CLI DNS authenticated user, physical source and inbound conditions passed", flush=True)


def active_stop(front, process):
    with Origin(expected=1) as target, begin(front, target.port) as client:
        client.sendall(b"active-upgrade")
        if exact(client, 14) != b"active-upgrade":
            raise RuntimeError("HTTPUpgrade CLI stop did not establish actual target data")
        process.terminate()
        if process.wait(timeout=5):
            raise RuntimeError("HTTPUpgrade CLI active stop failed")
        targets_closed(target, 1)
        try:
            if client.recv(1):
                raise RuntimeError("HTTPUpgrade CLI stopped owner left business stream open")
        except ConnectionResetError:
            pass


def client_headers(binary, root, workers, dns):
    seen, errors = [], []
    with socket.socket() as listener, untouched_target() as target:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)

        def serve():
            try:
                with listener.accept()[0] as raw, server_context(root, ["http/1.1"]).wrap_socket(raw, server_side=True) as peer:
                    peer.settimeout(5)
                    wire = header(peer)
                    if not wire.startswith(f"GET {TARGET} HTTP/1.1\r\n".encode()) or wire.lower().count(b"\r\nx-test: from-nexus\r\n") != 1:
                        raise RuntimeError(f"HTTPUpgrade CLI on-wire target or configured header missing: {wire!r}")
                    peer.sendall(RESPONSE[:-2] + b"Content-Length: 1\r\n\r\n")
                    seen.append(peer.recv(4096))
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        front = free_port()
        with nexus_process(binary, client_config(root, front, listener.getsockname()[1], workers, dns)):
            with begin(front, target, accepted=False):
                pass
        worker.join(6)
        if worker.is_alive() or errors or seen != [b""]:
            raise RuntimeError(f"HTTPUpgrade CLI framing rejection sent VLESS/target bytes: {seen}, {errors}")
    print("HTTPUpgrade CLI configured client header/path emitted and bad response rejected before VLESS", flush=True)


def run(binary, root, workers, dns):
    remote = free_port()
    with nexus_process(binary, server_config(root, remote, workers, dns)) as server:
        front = free_port()
        with nexus_process(binary, client_config(root, front, remote, workers, dns)) as client:
            traffic(front, f"Nexus pair workers={workers}", empty=True)
            active_stop(front, client)
        with proxy_client(root, go_outbound(root, remote)) as front:
            traffic(front, f"pinned Go client -> Nexus workers={workers}", empty=False)
            raw_rejections(root, remote, dns)
            dns_context(root, remote, dns)
            active_stop(front, server)
    remote, lower = free_port(), free_port()
    with sing_server(root, remote, lower, dns):
        for layered in (False, True):
            front = free_port()
            with nexus_process(binary, client_config(root, front, remote, workers, dns, lower if layered else None)):
                traffic(front, f"Nexus -> pinned Go server workers={workers}, Trojan detour={layered}", empty=False)
        with untouched_target() as target:
            for options in ({"name": "wrong.example"}, {"ca": "untrusted-cert"}, {"host": "wrong.example"}, {"path": "/wrong"}):
                front = free_port()
                with nexus_process(binary, client_config(root, front, remote, workers, dns, **options)):
                    with begin(front, target, accepted=False):
                        pass
    client_headers(binary, root, workers, dns)
    remote, front = free_port(), free_port()
    with nexus_process(binary, server_config(root, remote, workers, dns, host=None)), \
         nexus_process(binary, client_config(root, front, remote, workers, dns, host=None)):
        traffic(front, f"Nexus default client authority / unrestricted server Host workers={workers}", empty=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path, nargs="?")
    parser.add_argument("--self-test", action="store_true", help="verify only the independent Go peers and shared network harness")
    args = parser.parse_args()
    if not args.self_test and args.binary is None:
        parser.error("binary is required unless --self-test is selected")
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected fixed HTTPUpgrade peer")
    with tempfile.TemporaryDirectory(prefix="nexus-httpupgrade-cli-") as directory, DnsPeer() as dns:
        root = pathlib.Path(directory)
        certificates(root)
        for name, value in (("uuid", UUID), ("alice", ALICE), ("password", "upgrade-lower")):
            (root / name).write_text(value + "\n")
            (root / name).chmod(0o600)
        if args.self_test:
            remote, lower = free_port(), free_port()
            with sing_server(root, remote, lower, dns), proxy_client(root, go_outbound(root, remote)) as front:
                traffic(front, "independent Go -> Go harness only", empty=False)
            print("HTTPUpgrade CLI harness self-test passed; no Nexus program was executed", flush=True)
        else:
            for workers in (1, 2):
                run(args.binary.resolve(), root, workers, dns)


if __name__ == "__main__":
    main()
