#!/usr/bin/env python3
"""DNS rules use authenticated identities and the actual TCP/UDP input context."""
import argparse
import base64
import contextlib
import pathlib
import socket
import struct
import tempfile
import time

from dns_rule_support import DnsPeer, Echo, datagram_request, exact, free_port, nexus_process, ss_client

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--ss", action="store_true")
args = parser.parse_args()
binary = args.binary.resolve()


@contextlib.contextmanager
def client(front, user=None, source="127.0.0.1", port=0, host="127.0.0.1", http=False):
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as sock:
        sock.bind((source, port))
        sock.settimeout(3)
        sock.connect((host, front))
        if not http:
            method = 2 if user else 0
            sock.sendall(bytes((5, 1, method)))
            if exact(sock, 2) != bytes((5, method)):
                raise RuntimeError("SOCKS greeting")
            if user:
                raw = user.encode()
                sock.sendall(bytes((1, len(raw))) + raw + b"\x06secret")
                if exact(sock, 2) != b"\x01\x00":
                    raise RuntimeError("SOCKS authentication")
        yield sock


def stream(front, origin, name, accepted=True, **options):
    with client(front, **options) as sock:
        if options.get("http"):
            sock.sendall(f"CONNECT {name}:{origin} HTTP/1.1\r\nHost: {name}:{origin}\r\n\r\n".encode())
            response = bytearray()
            while not response.endswith(b"\r\n\r\n"):
                response.extend(exact(sock, 1))
            if not response.startswith(f"HTTP/1.1 {200 if accepted else 403} ".encode()):
                raise RuntimeError(f"HTTP DNS context {name}: {response!r}")
        else:
            raw = name.encode()
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", origin))
            response = exact(sock, 4)
            if response[1] != (0 if accepted else 2) or response[3] not in (1, 4):
                raise RuntimeError(f"SOCKS DNS context {name}: {response!r}")
            exact(sock, 6 if response[3] == 1 else 18)
        if accepted:
            sock.sendall(b"dns-context")
            if exact(sock, 11) != b"dns-context":
                raise RuntimeError("DNS context stream data")


@contextlib.contextmanager
def association(front, user=None):
    with client(front, user) as control:
        # Leave the UDP port unspecified so the data socket supplies it.
        control.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x00")
        reply = exact(control, 10)
        if reply[:4] != b"\x05\x00\x00\x01":
            raise RuntimeError("UDP association")
        yield socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], "big")


def run(workers):
    with tempfile.TemporaryDirectory(prefix="nexus-dns-context-") as directory, \
         DnsPeer() as first, DnsPeer() as second, Echo() as origin, contextlib.ExitStack() as stack:
        root = pathlib.Path(directory)
        password = root / "password"
        password.write_text("secret\n")
        password.chmod(0o600)
        key = bytes(range(16))
        keyfile = root / "key"
        keyfile.write_text(base64.b64encode(key).decode() + "\n")
        keyfile.chmod(0o600)
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.bind(("127.0.0.1", 0))
        udp_port = udp.getsockname()[1]
        tcp = stack.enter_context(socket.socket())
        tcp.bind(("127.0.0.1", 0))
        tcp_port = tcp.getsockname()[1]
        ports = []
        while len(ports) < 7:
            candidate = free_port()
            if candidate not in ports:
                ports.append(candidate)
        ss = "" if not args.ss else f'''
 shadowsocks "blocked-ss" {{ listen host="127.0.0.1" port={ports[5]}; method "2022-blake3-aes-128-gcm"; key-file "{keyfile}"; }}
 shadowsocks "allowed-ss" {{ listen host="127.0.0.1" port={ports[6]}; method "2022-blake3-aes-128-gcm"; key-file "{keyfile}"; }}'''
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{
 mixed "blocked" {{ listen host="127.0.0.1" port={ports[0]}; authentication "none"; }}
 mixed "allowed" {{ listen host="127.0.0.1" port={ports[1]}; authentication "none"; }}
 mixed "v6" {{ listen host="::1" port={ports[2]}; authentication "none"; }}
 socks5 "alice-in" {{ listen host="127.0.0.1" port={ports[3]}; authentication "password" username="alice" password-file="{password}"; }}
 socks5 "bob-in" {{ listen host="127.0.0.1" port={ports[4]}; authentication "password" username="bob" password-file="{password}"; }}
 {ss}
}}
outbound "direct" type="direct"
dns {{
 server "first" type="udp" host="127.0.0.1" port={first.port}
 server "second" type="tcp" host="127.0.0.1" port={second.port}
 server "named" type="udp" host="upstream.test" port={second.port} domain-resolver="first"
 rule domain="network.test" network="udp" action="reject"
 rule domain="source.test" source-ip-cidr="127.0.0.2/32" action="reject"
 rule domain="private.test" source-ip-is-private=#true network="udp" action="reject"
 rule domain="v6-source.test" source-ip-cidr="::1/128" action="reject"
 rule domain="tcp-port.test" source-port={tcp_port} action="reject"
 rule domain="udp-port.test" source-port={udp_port} network="udp" action="reject"
 rule domain="range.test" source-port-range="{udp_port}-{udp_port}" action="reject"
 rule domain="listener.test" inbound="blocked" action="reject"
 rule domain="identity.test" auth-user="alice" action="reject"
 rule domain="and.test" inbound="allowed" auth-user="alice" network="udp" action="reject"
 rule domain="split.test" inbound="allowed" network="udp" query-type="AAAA" server="second"
 rule domain="option.test" inbound="allowed" network="udp" action="route-options" disable-cache=#true
 rule domain="option.test" query-type=1 action="route" server="first" disable-cache=#false
 rule domain="business.test" auth-user="alice" server="named"
 rule domain="upstream.test" auth-user="alice" action="reject"
 rule domain="ss.test" inbound="blocked-ss" action="reject"
 rule domain="ss-unknown.test" auth-user="alice" action="reject"
 final "first"
}}
routing {{ default-outbound "direct"; }}
''')
        with nexus_process(binary, config, 7 if args.ss else 5) as process:
            allowed, blocked = ports[1], ports[0]
            stream(allowed, origin.port, "network.test")
            stream(allowed, origin.port, "source.test")
            stream(allowed, origin.port, "source.test", False, source="127.0.0.2")
            stream(allowed, origin.port, "source.test", False, source="127.0.0.2", http=True)
            stream(ports[2], origin.port, "v6-source.test", False, source="::1", host="::1")
            # This exact port is owned before configuration, and is never the UDP source port.
            tcp.settimeout(3)
            tcp.connect(("127.0.0.1", allowed))
            tcp.sendall(b"\x05\x01\x00")
            if exact(tcp, 2) != b"\x05\x00":
                raise RuntimeError("reserved source port greeting")
            name = b"tcp-port.test"
            tcp.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", origin.port))
            if exact(tcp, 10)[1] != 2:
                raise RuntimeError("TCP source port was not supplied to DNS")
            stream(allowed, origin.port, "listener.test")
            stream(blocked, origin.port, "listener.test", False)
            stream(blocked, origin.port, "listener.test", False, http=True)
            stream(ports[4], origin.port, "identity.test", user="bob")
            stream(ports[3], origin.port, "identity.test", False, user="alice")
            stream(allowed, origin.port, "identity.test")
            stream(ports[3], origin.port, "business.test", user="alice")
            with association(allowed) as relay:
                for name, accepted in (("network.test", False), ("private.test", False),
                                       ("udp-port.test", False), ("range.test", False),
                                       ("and.test", True), ("split.test", True),
                                       ("option.test", True), ("option.test", True)):
                    datagram_request(udp, relay, origin.port, name, accepted)
            for front, user, accepted in ((ports[3], "alice", False), (ports[4], "bob", True), (allowed, None, True)):
                with association(front, user) as relay:
                    datagram_request(udp, relay, origin.port, "identity.test", accepted)
            if args.ss:
                for index, accepted in ((5, False), (6, True)):
                    peer_root = root / f"ss-{index}"
                    peer_root.mkdir()
                    with ss_client(peer_root, ports[index], key) as (ss_udp, relay):
                        datagram_request(ss_udp, relay, origin.port, "ss.test", accepted)
                        datagram_request(ss_udp, relay, origin.port, "ss-unknown.test")
            for name in ("tcp-port.test", "udp-port.test", "range.test", "private.test", "v6-source.test"):
                if first.count(name, 1) or first.count(name, 28) or second.count(name, 1) or second.count(name, 28):
                    raise RuntimeError(f"rejected {name} reached DNS")
            if (first.count("split.test", 1), first.count("split.test", 28), second.count("split.test", 28)) != (1, 0, 1):
                raise RuntimeError("combined context and qtype were not applied independently")
            if (first.count("option.test", 1), first.count("option.test", 28)) != (1, 2):
                raise RuntimeError("context-specific continued cache options")
            if first.count("upstream.test", 1) != 1 or second.count("business.test", 1) != 1:
                raise RuntimeError("business context leaked into explicit bootstrap")
            # Retain the authenticated UDP request and a TCP source while
            # their no-reply questions are canceled by server shutdown.
            with association(ports[4], "bob") as relay, client(allowed) as pending:
                first.drop.add(("cancel-udp.test", 28))
                first.drop.add(("cancel-tcp.test", 28))
                for name in (b"cancel-udp.test", b"cancel-tcp.test"):
                    request = b"\x03" + bytes([len(name)]) + name + struct.pack("!H", origin.port)
                    if name.startswith(b"cancel-udp"):
                        udp.sendto(b"\x00\x00\x00" + request + b"pending", relay)
                    else:
                        pending.sendall(b"\x05\x01\x00" + request)
                deadline = time.monotonic() + 3
                while not all(first.count(name, 28) for name in ("cancel-udp.test", "cancel-tcp.test")):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("context questions were not both pending")
                    time.sleep(.01)
                started = time.monotonic()
                process.terminate()
                process.wait(timeout=3)
                if time.monotonic() - started > 1.5:
                    raise RuntimeError("context questions did not cancel promptly")
        print(f"DNS source, network, inbound, identity, qtype and options passed: workers={workers} ss={args.ss}")


for worker_count in (1, 2):
    run(worker_count)
