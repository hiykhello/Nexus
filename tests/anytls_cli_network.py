#!/usr/bin/env python3
"""Production AnyTLS KDL/CLI, multiplexed inbound, DNS identity and UoT v2."""
import argparse
import contextlib
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import time

from anytls_network import Origin
from anytls_proxy_network import CountedRelay, payload, targets_closed
from anytls_test_peer import Peer, address, datagram
from detour_network import running
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, proxy_client, udp_client


def wait_for(predicate, label, timeout=5):
    limit = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= limit:
            raise RuntimeError(label)
        time.sleep(.005)


def begin(front, target, host="127.0.0.1"):
    client = connect(front)
    client.sendall(b"\x05\x01\x00")
    if exact(client, 2) != b"\x05\x00":
        raise RuntimeError("AnyTLS CLI SOCKS greeting")
    client.sendall(b"\x05\x01\x00" + address(host, target))
    response = exact(client, 4)
    if response[1] or response[3] not in (1, 4):
        raise RuntimeError(f"AnyTLS CLI SOCKS reply: {response!r}")
    exact(client, 6 if response[3] == 1 else 18)
    return client


def connection(root, port):
    return f'''server host="127.0.0.1" port={port}
authentication {{ password-file "{root / 'bob'}"; }}
tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}'''


def client_config(root, front, remote, workers, lower=None, max_sessions=1):
    lower_config = f'''outbound "lower" type="trojan" {{ {connection(root, lower)} }}''' if lower else ""
    direct_fast = os.getenv('NEXUS_TEST_TFO_DIRECT') and not lower
    detour = 'detour "lower";' if lower else 'detour "direct";' if direct_fast else ""
    fast_open = 'tcp-fast-open #true;' if os.getenv('NEXUS_TEST_FAST_OPEN') and not lower else ''
    direct = 'outbound "direct" type="direct" { tcp-fast-open #true; }' if direct_fast else 'outbound "direct" type="direct"'
    path = root / "client.kdl"
    path.write_text(f'''schema-version 1
role "server"
workers {workers}
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
{direct}
outbound "edge" type="anytls" {{ {connection(root, remote)}
 pool {{ max-sessions {max_sessions}; min-idle 1; idle-timeout-ms 30000; check-interval-ms 30000; }}
 {fast_open}
 {detour}
}}
{lower_config}
routing {{ default-outbound "edge"; }}
''')
    return path


def server_config(root, front, workers, dns, ipv6=False):
    host, prefix = ("::1", "::1/128") if ipv6 else ("127.0.0.1", "127.0.0.1/32")
    path = root / "server.kdl"
    path.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{ anytls "ain" {{ listen host="{host}" port={front};
 authentication {{ user "alice" password-file="{root / 'alice'}"; user "bob" password-file="{root / 'bob'}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
}} }}
outbound "direct" type="direct"
dns {{
 server "dns" type="udp" host="127.0.0.1" port={dns.port}
 rule domain="identity.test" auth-user="alice" action="reject"
 rule domain="network.test" network="udp" action="reject"
 rule domain="source.test" source-ip-cidr="{prefix}" source-port-range="1-65535" action="reject"
 rule domain="listener.test" inbound="ain" action="reject"
 final "dns"
}}
routing {{ default-outbound "direct"; }}
''')
    return path


def socks_packets(front):
    with Echo() as origin, udp_client(front) as (client, relay):
        for host in ("127.0.0.1", "::1"):
            header = b"\x00\x00\x00" + address(host, origin.port)
            for data in (b"AnyTLS CLI UoT", b"", bytes(range(256)) * 32):
                client.sendto(header + data, relay)
                try:
                    received = client.recvfrom(65535)[0]
                except TimeoutError as error:
                    raise RuntimeError(f"AnyTLS CLI UoT timeout: host={host}, size={len(data)}, origin={list(map(len, origin.received))}") from error
                if received != header + data:
                    raise RuntimeError("AnyTLS CLI UoT v2 address/empty/payload mismatch")


def pool_references(binary, root):
    remote, front = free_port(), free_port()
    control = root / "control.sock"
    with DnsPeer() as dns, Origin(expected=1) as origin:
        with nexus_process(binary, server_config(root, remote, 1, dns)), CountedRelay(remote) as relay:
            config = client_config(root, front, relay.port, 1, max_sessions=2)
            source = config.read_text().replace("workers 1", f'workers 1\ncontrol socket="{control}"')
            source = source.replace("idle-timeout-ms 30000; check-interval-ms 30000;",
                                    "idle-timeout-ms 200; check-interval-ms 50;")
            source = source.replace('routing { default-outbound "edge"; }', '''
outbound "selected" type="selector" { member "direct"; member "edge"; selected "direct"; }
routing { default-outbound "selected"; }''')
            config.write_text(source)

            def select(member):
                subprocess.run([binary, "control", control, "select", "selected", member],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            with nexus_process(binary, config):
                time.sleep(.35)
                assert relay.accepted == 0, relay.accepted
                select("edge")
                relay.wait(1, 0)
                with begin(front, origin.port) as client:
                    relay.wait(2, 0)
                    select("direct")
                    relay.wait(2, 1)
                    data = b"old AnyTLS flow survives its outbound being unselected"
                    client.sendall(data)
                    assert exact(client, len(data)) == data
                    client.shutdown(socket.SHUT_WR)
                    assert client.recv(1) == b""
                relay.wait(2, 2)
                time.sleep(.35)
                assert relay.accepted == 2, relay.accepted
                select("edge")
                relay.wait(3, 2)
            relay.wait(3, 3)
    print("AnyTLS prewarm followed selector publications, reaped idle sockets and retained the old active flow")


def cli_client(binary, root, remote, workers, lower=None):
    with CountedRelay(remote) as relay:
        front = free_port()
        path = client_config(root, front, relay.port, workers, lower)
        with nexus_process(binary, path), Origin() as origin:
            relay.wait(workers, 0)
            if origin.peers:
                raise RuntimeError("AnyTLS CLI prewarm reached business target")
            for index in range(3):
                with begin(front, origin.port) as client:
                    payload(client)
                targets_closed(origin, index + 1)
                relay.wait(workers, 0)
        relay.wait(workers, workers)
        front = free_port()
        path = client_config(root, front, relay.port, workers, lower, max_sessions=2)
        with nexus_process(binary, path):
            relay.wait(2 * workers, workers)
            socks_packets(front)
            # The shared SOCKS UDP path keeps independent v4/v6 slots active;
            # its second family leases one additional TLS connection.
            relay.wait(2 * workers + 1, workers)
        relay.wait(2 * workers + 1, 2 * workers + 1)


@contextlib.contextmanager
def sing_server(root, front, lower):
    tls = {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}
    path = root / "sing-server.json"
    path.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": [
        {"type": "anytls", "listen": "127.0.0.1", "listen_port": front, "users": [{"name": "bob", "password": "anytls-network-secret"}], "tls": tls},
        {"type": "trojan", "listen": "127.0.0.1", "listen_port": lower, "users": [{"password": "anytls-network-secret"}], "tls": tls}],
        "outbounds": [{"type": "direct"}]}))
    with running(["sing-box", "run", "-c", path], front, root / "sing-server.log"):
        yield


def sing_client(root, remote):
    outbound = {"type": "anytls", "server": "127.0.0.1", "server_port": remote, "password": "anytls-network-secret",
                "min_idle_session": 1, "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(root / "cert")}}
    with proxy_client(root, outbound) as front, Origin() as origin:
        for index in range(3):
            with begin(front, origin.port, "identity.test") as client:
                payload(client)
            targets_closed(origin, index + 1)
        socks_packets(front)


def raw_streams(root, front, dns, host="127.0.0.1"):
    with Origin() as origin, Peer(root, front, host=host) as peer:
        data = bytes(range(256)) * 256
        streams = [peer.open("127.0.0.1", origin.port, data, fragmented=True) for _ in range(3)]
        for stream in streams:
            peer.ack(stream)
            if peer.read(stream, len(data)) != data:
                raise RuntimeError("simultaneous AnyTLS inbound data mismatch")
        for stream in streams:
            peer.finish(stream)
        targets_closed(origin, 3)
        for name in ("source.test", "listener.test"):
            before = len(dns.seen), len(origin.peers)
            denied = peer.open(name, origin.port, b"must-not-forward")
            peer.ack(denied, accepted=False)
            if before != (len(dns.seen), len(origin.peers)):
                raise RuntimeError(f"AnyTLS inherited DNS metadata missing: {name}")
        allowed = peer.open("identity.test", origin.port, b"bob-allowed")
        peer.ack(allowed)
        if peer.read(allowed, 11) != b"bob-allowed":
            raise RuntimeError("AnyTLS authenticated Bob identity did not route")
        peer.finish(allowed)
        targets_closed(origin, 4)
        dns.drop.update({("slow.test", 1), ("slow.test", 28)})
        pending = peer.open("slow.test", origin.port)
        wait_for(lambda: any(name == "slow.test" for name, *_ in dns.seen), "AnyTLS child never entered DNS")
        peer.finish(pending)
        later = peer.open("127.0.0.1", origin.port, b"after-cancel")
        peer.ack(later)
        if peer.read(later, 12) != b"after-cancel":
            raise RuntimeError("logical FIN during DNS canceled the parent")
        peer.finish(later)
        targets_closed(origin, 5)
        with Echo() as udp:
            initial = b"\x00" + address("0.0.0.0", 0)
            for reserved_port in (0, 443):
                stream = peer.open("sp.v2.udp-over-tcp.arpa", reserved_port, initial)
                peer.ack(stream)
                for name, data in (("identity.test", b"uot-domain"), ("127.0.0.1", b""), ("::1", bytes(range(256)) * 32)):
                    peer.send(stream, datagram(name, udp.port, data), fragmented=True)
                    tag, _, port, received = peer.read_datagram(stream)
                    if tag not in (0, 1) or port != udp.port or received != data:
                        raise RuntimeError("AnyTLS raw UoT v2 payload or destination mismatch")
                batch = (b"first", b"", b"third" * 1200, b"last")
                wire = b"".join(datagram("127.0.0.1", udp.port, data) for data in batch)
                seen = len(udp.received)
                peer.send(stream, wire, fragmented=True)
                replies = [peer.read_datagram(stream) for _ in batch]
                if any(tag != 0 or addr != socket.inet_aton("127.0.0.1") or port != udp.port
                       for tag, addr, port, _ in replies):
                    raise RuntimeError("AnyTLS raw UoT v2 batch reply source mismatch")
                if sorted(reply[3] for reply in replies) != sorted(batch) or sorted(udp.received[seen:]) != sorted(batch):
                    raise RuntimeError("AnyTLS UoT v2 batch lost datagram boundaries")
                before = len(udp.received), len(dns.seen)
                peer.send(stream, datagram("network.test", udp.port, b"blocked"))
                peer.socket.settimeout(.2)
                try:
                    peer.read_datagram(stream)
                except TimeoutError:
                    pass
                else:
                    raise RuntimeError("AnyTLS UDP DNS network condition did not reject")
                peer.socket.settimeout(5)
                if before != (len(udp.received), len(dns.seen)):
                    raise RuntimeError("rejected AnyTLS UDP reached DNS or origin")
                peer.send(stream, datagram("127.0.0.1", udp.port, b"recovered"))
                if peer.read_datagram(stream)[3] != b"recovered":
                    raise RuntimeError("AnyTLS UDP rejection prevented recovery")
                peer.finish(stream)
    with Origin(expected=0) as origin, Peer(root, front, "anytls-alice", host) as peer:
        before = len(dns.seen)
        stream = peer.open("identity.test", origin.port, b"alice-denied")
        peer.ack(stream, accepted=False)
        if len(dns.seen) != before or origin.peers:
            raise RuntimeError("AnyTLS Alice authentication context was lost")
    with Origin() as origin, Peer(root, front, host=host, version=1) as peer:
        denied = peer.open("listener.test", origin.port)
        while denied not in peer.ended:
            peer.next()
        allowed = peer.open("127.0.0.1", origin.port, b"v1-recovery")
        if peer.read(allowed, 11) != b"v1-recovery":
            raise RuntimeError("AnyTLS v1 rejection FIN or recovery failed")
        peer.finish(allowed)
        targets_closed(origin, 1)
    try:
        with Peer(root, front, "wrong-password", host) as peer:
            if peer.socket.recv(1):
                raise RuntimeError("AnyTLS accepted an incorrect password")
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        pass


def active_stop(root, front, process):
    with Origin() as origin, Peer(root, front) as peer:
        stream = peer.open("127.0.0.1", origin.port, b"active-stop")
        peer.ack(stream)
        if peer.read(stream, 11) != b"active-stop":
            raise RuntimeError("active stop did not establish a real logical stream")
        process.terminate()
        process.wait(timeout=5)
        targets_closed(origin, 1)
        try:
            closed = not peer.socket.recv(1)
        except (ssl.SSLError, ConnectionResetError):
            closed = True
        if not closed:
            raise RuntimeError("AnyTLS parent stop left child TLS usable")


def quota(root, front):
    # Creating 63 TLS-framed streams can exceed the ordinary echo's 5s idle
    # timeout. Keep every origin alive until the quota assertion is observed.
    with Origin(idle_timeout=30) as origin, Peer(root, front) as peer:
        # The process-wide 64-session allowance includes one physical owner
        # and its live business children, across all workers.
        streams = []
        for _ in range(63):
            stream = peer.open("127.0.0.1", origin.port, b"quota-live")
            peer.ack(stream)
            if peer.read(stream, 10) != b"quota-live":
                raise RuntimeError("AnyTLS quota transfer mismatch")
            streams.append(stream)
        before = len(origin.peers)
        denied = peer.open("127.0.0.1", origin.port, b"must-not-dial")
        peer.ack(denied, accepted=False)
        if len(origin.peers) != before or before != 63 or origin.closed:
            raise RuntimeError("AnyTLS child escaped the shared session quota")
        peer.finish(streams.pop(0))
        targets_closed(origin, 1)
        recovery = peer.open("127.0.0.1", origin.port, b"quota-recovered")
        peer.ack(recovery)
        if peer.read(recovery, 15) != b"quota-recovered":
            raise RuntimeError("AnyTLS quota release did not recover the parent")
        for stream in streams + [recovery]:
            peer.finish(stream)
        targets_closed(origin, 64)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--pool-references", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if not args.pool_references and f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    with tempfile.TemporaryDirectory(prefix="nexus-anytls-cli-") as directory:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name, secret in (("alice", "anytls-alice"), ("bob", "anytls-network-secret")):
            (root / name).write_text(secret + "\n")
            (root / name).chmod(0o600)
        (root / "key").chmod(0o600)
        if args.pool_references:
            pool_references(binary, root)
            return
        for workers in (1, 2):
            with DnsPeer() as dns:
                front = free_port()
                with nexus_process(binary, server_config(root, front, workers, dns)) as process:
                    raw_streams(root, front, dns)
                    quota(root, front)
                    sing_client(root, front)
                    cli_client(binary, root, front, workers)
                    active_stop(root, front, process)
                print(f"AnyTLS CLI Nexus pair/pinned client/raw multiplex/DNS/FIN/UoT/active stop passed: workers={workers}", flush=True)
            remote, lower = free_port(), free_port()
            with sing_server(root, remote, lower):
                for layered in (False, True):
                    cli_client(binary, root, remote, workers, lower if layered else None)
                    print(f"AnyTLS CLI pinned server/prewarm/reuse/UoT passed: workers={workers}, Trojan detour={layered}", flush=True)
        with DnsPeer() as dns:
            front = free_port()
            with nexus_process(binary, server_config(root, front, 2, dns, ipv6=True)):
                raw_streams(root, front, dns, host="::1")
            print("AnyTLS CLI IPv6 physical source and child lifecycle passed", flush=True)


if __name__ == "__main__":
    main()

