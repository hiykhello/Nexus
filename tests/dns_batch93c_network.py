#!/usr/bin/env python3
"""Production DNS views, response compression and local search."""
import contextlib
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading

from dns_rule_support import DnsPeer, Echo, exact, free_port, nexus_process, question, stream_request, wire_name
from tcp_proxy_outbounds_network import open_socks

SUFFIX = "long-label-shared-by-all-cname-records.testing-tailnet.example"


def listener(port):
    return f'inbound "app" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}'


def query(name, kind=1, capacity=None):
    msg = struct.pack("!6H", 0x9152, 0x100, 1, 0, 0, int(capacity is not None))
    msg += wire_name(name) + struct.pack("!HH", kind, 1)
    if capacity is not None:
        msg += struct.pack("!BHHIH", 0, 41, capacity, 0, 0)
    return msg


class HttpPeer(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        request = self.rfile.readline()
        if not request:
            return
        self.server.requests.append(request)
        assert request.startswith(b"CONNECT 127.0.0.1:")
        while self.rfile.readline() not in (b"\r\n", b""):
            pass
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        while chunk := self.request.recv(4096):
            self.request.sendall(chunk)


@contextlib.contextmanager
def http_peer():
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), HttpPeer) as server:
        server.requests = []
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join()


def views(binary, root):
    with http_peer() as peer, DnsPeer() as matched, DnsPeer() as fallback, DnsPeer() as default:
        config = root / "view.kdl"
        front = free_port()
        outbounds = f'''
outbound "direct" type="direct"
outbound "edge" type="http-connect" {{
    server host="HOST" port={peer.server_address[1]}
    domain-resolver "RESOLVER"
}}
routing {{ default-outbound "edge"; }}
'''
        dns = f'''
dns {{
    server "matched" type="udp" host="127.0.0.1" port={matched.port}
    server "fallback" type="udp" host="127.0.0.1" port={fallback.port}
    server "default" type="udp" host="127.0.0.1" port={default.port}
    rule domain="matched.test" server="matched"
    view "dial" final="fallback"
    final "default"
    strategy "ipv4_only"
}}
'''
        base = 'schema-version 1\nrole "client"\nlog { privacy "verbose"; }\n' + listener(front)
        for host, resolver, upstream in (("matched.test", "dial", matched),
                                        ("fallthrough.test", "dial", fallback),
                                        ("evaluated.test", "dial", matched),
                                        ("physical.test", "matched", matched)):
            policy = dns
            if host == "evaluated.test":
                policy = dns.replace('    view "dial"', '''
    rule domain="evaluated.test" action="evaluate" server="matched" tag="candidate"
    rule domain="evaluated.test" match-response="candidate" action="respond"
    view "dial"''')
            config.write_text(base + outbounds.replace("HOST", host).replace("RESOLVER", resolver) + policy)
            before = len(peer.requests)
            with nexus_process(binary, config):
                for _ in range(2):
                    with open_socks(front, "127.0.0.1", 8082) as client:
                        client.sendall(b"view")
                        assert exact(client, 4) == b"view"
            assert len(peer.requests) == before + 2, peer.requests
            assert upstream.count(host, 1) == 1, upstream.seen
        assert not default.seen, default.seen

        bad = dns.replace('rule domain="matched.test" server="matched"', '''
    server "loop" type="tls" host="127.0.0.1" port=853 server-name="resolver.test" ca-file="/tmp/absent.pem" detour="edge"
    rule domain="matched.test" server="loop"
''')
        config.write_text(base + outbounds.replace("HOST", "matched.test").replace("RESOLVER", "dial") + bad)
        result = subprocess.run([binary, "run", "--config", config], capture_output=True, text=True, timeout=3)
        assert result.returncode and "dependency cycle" in result.stderr, result
    print("Dial view selected question/response DNS rules and view final, reused cache, preserved physical tags, rejected startup cycle")


def rr(owner, kind, data):
    return wire_name(owner) + struct.pack("!HHIH", kind, 1, 60, len(data)) + data


class WirePeer(DnsPeer):
    def reply(self, packet, transport):
        name, kind, end = question(packet)
        self.seen.append((name, kind, transport))
        if name == "oversize.test":
            records = [rr(name, 16, b"\xc8" + bytes([65 + i]) * 200) for i in range(4)]
        else:
            names = [f"n{i}.{SUFFIX}" for i in range(11)]
            assert name == names[0]
            records = [rr(src, 5, wire_name(dst)) for src, dst in zip(names, names[1:])]
            address = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                       "192.0.2.8" if kind == 1 else "2001:db8::8")
            records.append(rr(names[-1], kind, address))
        return packet[:2] + struct.pack("!5H", 0x8180, 1, len(records), 0, 0) + packet[12:end] + b"".join(records)


def decode_name(msg, pos, pointers):
    end = None
    labels = []
    while True:
        length = msg[pos]
        if length & 0xc0 == 0xc0:
            target = int.from_bytes(msg[pos:pos+2], "big") & 0x3fff
            assert 12 <= target < pos
            pointers.append(target)
            end = end or pos + 2
            pos = target
        elif length == 0:
            return ".".join(labels), end or pos + 1
        else:
            assert length <= 63
            labels.append(msg[pos+1:pos+1+length].decode("ascii"))
            pos += length + 1


def compression(binary, root):
    front, port = free_port(), free_port()
    config = root / "compression.kdl"
    with WirePeer() as peer:
        config.write_text(f'''schema-version 1
role "client"
{listener(front)}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
    listen host="127.0.0.1" port={port}
    server "wire" type="tcp" host="127.0.0.1" port={peer.port}
    final "wire"
}}
''')
        with nexus_process(binary, config), socket.socket(type=socket.SOCK_DGRAM) as client:
            client.settimeout(4)
            def exchange(name, kind=1, capacity=None):
                client.sendto(query(name, kind, capacity), ("127.0.0.1", port))
                result = client.recv(4096)
                assert result[:2] == b"\x91\x52", result.hex()
                return result

            names = [f"n{i}.{SUFFIX}" for i in range(11)]
            for kind in (1, 28):
                wire = exchange(names[0], kind)
                flags, qd, an, ns, ar = struct.unpack_from("!5H", wire, 2)
                assert len(wire) <= 512 and not flags & 0x200 and (qd, an, ns, ar) == (1, 11, 0, 0)
                pointers = []
                question_name, pos = decode_name(wire, 12, pointers)
                assert question_name == names[0]
                pos += 4
                for i in range(an):
                    owner, pos = decode_name(wire, pos, pointers)
                    record_type, klass, _, length = struct.unpack_from("!HHIH", wire, pos)
                    pos += 10
                    assert owner == names[i] and klass == 1
                    if i < 10:
                        alias, end = decode_name(wire, pos, pointers)
                        assert record_type == 5 and alias == names[i+1] and end == pos + length
                    else:
                        expected = bytes((192, 0, 2, 8)) if kind == 1 else socket.inet_pton(socket.AF_INET6, "2001:db8::8")
                        assert record_type == kind and wire[pos:pos+length] == expected
                    pos += length
                assert pos == len(wire) and len(pointers) >= 20
                print(f"UDP without EDNS QTYPE={kind}: {len(wire)} bytes, 11 decoded answers, TC=0")
            for capacity in (None, 768, 1232):
                wire = exchange("oversize.test", capacity=capacity)
                truncated = capacity != 1232
                _, flags, _, count = struct.unpack_from("!4H", wire)
                assert bool(flags & 0x200) == truncated and count == (0 if truncated else 4), wire.hex()
                assert len(wire) <= (capacity or 512)
            print("Oversize UDP sets TC at 512 and EDNS 768, keeps four records at EDNS 1232")


def local(binary, root):
    config = root / "local.kdl"
    resolv, hosts = root / "resolv", root / "hosts"
    priv = "100.100.100.100"
    resolv.write_text(f"nameserver {priv}\nsearch primary.test private-tailnet.ts.net\noptions ndots:1 timeout:1 attempts:1\n")
    hosts.write_text("")
    for source, target in ((resolv, "/etc/resolv.conf"), (hosts, "/etc/hosts")):
        subprocess.run(["mount", "--bind", source, target], check=True)
    subprocess.run(["ip", "address", "add", f"{priv}/32", "dev", "lo"], check=True)

    class PrivatePeer(DnsPeer):
        def reply(self, packet, transport):
            name, kind, end = question(packet)
            self.seen.append((name, kind, transport))
            if name == "printer.primary.test":
                return packet[:2] + struct.pack("!5H", 0x8183, 1, 0, 0, 0) + packet[12:end]
            assert name in ("printer", "printer.private-tailnet.ts.net", "host.private-tailnet.ts.net"), name
            return (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:end] +
                    bytes.fromhex("c00c000100010000003c00047f000001"))

    with PrivatePeer(host=priv, port=53) as peer, Echo() as echo:
        for mode in ("indexed", "ordered"):
            front = free_port()
            program = '''tcp-program sniff-timeout-ms=60 unknown="skip" {
        rule action="route" outbound="direct" { domain "printer"; }
        rule action="route" outbound="direct" { domain "host.private-tailnet.ts.net"; }
        rule action="reject"
    }''' if mode == "ordered" else ""
            config.write_text(f'''schema-version 1
role "client"
{listener(front)}
outbound "direct" type="direct"
routing {{ {program}
    default-outbound "direct"
}}
dns {{
    server "private" type="local"
    final "private"
    strategy "ipv4_only"
}}
''')
            peer.seen.clear()
            with nexus_process(binary, config):
                for domain in ("printer", "printer.", "host.private-tailnet.ts.net."):
                    stream_request(front, echo.port, domain)
            assert [name for name, _, _ in peer.seen] == [
                "printer.primary.test", "printer.private-tailnet.ts.net", "printer", "host.private-tailnet.ts.net"], peer.seen
    print("Isolated local private DNS stub: ordered search and unqualified/rooted FQDN behavior via indexed and ordered traffic routing")


if __name__ == "__main__":
    binary, mode = str(Path(sys.argv[1]).resolve()), sys.argv[2]
    if mode == "local" and len(sys.argv) == 3:
        raise SystemExit(subprocess.call(["unshare", "-Urnm", sys.executable, __file__, binary, mode, "isolated"]))
    if mode == "local":
        subprocess.run(["mount", "--make-rprivate", "/"], check=True)
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with tempfile.TemporaryDirectory(prefix="nexus-93c-dns-") as work:
        {"views": views, "compression": compression, "local": local}[mode](binary, Path(work))
