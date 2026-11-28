#!/usr/bin/env python3
"""A failed lower node must not be retried for every address at every layer."""
import argparse
import base64
import collections
import pathlib
import socket
import struct
import subprocess
import tempfile
import threading
import time

from detour_network import exact, reserve, running, socks


class Dns:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.negative = threading.Event()
        self.queries = collections.Counter()
        self.errors = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    query, peer = self.socket.recvfrom(4096)
                except TimeoutError:
                    continue
                pos, labels = 12, []
                while query[pos]:
                    size = query[pos]
                    labels.append(query[pos + 1:pos + 1 + size].decode())
                    pos += size + 1
                end = pos + 5
                name = ".".join(labels)
                self.queries[name] += 1
                if query[pos + 1:end] != b"\x00\x01\x00\x01":
                    raise RuntimeError("expected an A query")
                if query[10:12] != b"\x00\x01" or query[end:] != b"\x00\x00\x29\x04\xd0" + bytes(6):
                    raise RuntimeError("expected an EDNS query with a 1232-byte payload")
                if name == "n0.test":
                    soa = b"\x02ns\x04test\x00\x0ahostmaster\x04test\x00" + struct.pack("!5I", 1, 60, 60, 60, 60)
                    reply = query[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x01\x00\x01" + query[12:end]
                    reply += b"\x04test\x00" + struct.pack("!HHIH", 6, 1, 60, len(soa)) + soa
                else:
                    count = 64 if name == "target.test" else 8
                    reply = query[:2] + b"\x81\x80\x00\x01" + count.to_bytes(2, "big") + b"\x00\x00\x00\x01" + query[12:end]
                    for last in range(1, count + 1):
                        reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, last])
                self.socket.sendto(reply + query[end:], peer)
                if name == "n0.test":
                    self.negative.set()
        except Exception as error:
            self.errors.append(error)

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        if self.thread.is_alive() or self.errors:
            raise RuntimeError(f"DNS peer failed: {self.errors}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--protocol", choices=("ss", "vless"), default="ss")
    parser.add_argument("--workers", type=int, choices=(1, 2), default=1)
    parser.add_argument("--domain", action="store_true", help="also use the maximum 64 business destination candidates")
    parser.add_argument("--no-cache", action="store_true", help="expose repeated node attempts without DNS cache hits")
    parser.add_argument("--fallback", action="store_true", help="route the last business address directly after a failed chain")
    args = parser.parse_args()
    if args.fallback and not args.domain:
        parser.error("--fallback requires --domain")
    with tempfile.TemporaryDirectory(prefix="nexus-detour-fanout-") as directory, socket.socket() as origin, socket.socket() as fallback:
        root = pathlib.Path(directory)
        psk = root / "psk"
        psk.write_text(base64.b64encode(bytes(range(16))).decode())
        psk.chmod(0o600)
        if args.protocol == "vless":
            (root / "uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f")
            (root / "uuid").chmod(0o600)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                            "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example", "-days", "1"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(5)
        target = origin.getsockname()[1]
        direct_rules = f'schema-version 2\nkind "predicate"\nrule type="port" value="{target}"\n'
        if args.fallback:
            fallback.bind(("127.0.0.64", 0))
            fallback.listen(1)
            fallback.settimeout(2)
            direct_rules += 'rule type="ip-cidr" value="127.0.0.64/32"\n'
        (root / "direct.kdl").write_text(direct_rules)
        dns = Dns()
        port = reserve()
        text = f'''schema-version 1
role "client"
workers {args.workers}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; edns #true; disable-cache {"#true" if args.no_cache else "#false"}; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
'''
        for index in reversed(range(16)):
            detour = f'detour "n{index - 1}";' if index else ""
            protocol = "shadowsocks" if args.protocol == "ss" else "vless"
            options = f'method "2022-blake3-aes-128-gcm"; key-file "{psk}";' if args.protocol == "ss" else f'authentication {{ uuid-file "{root / "uuid"}"; }}; tls {{ server-name "cover.example"; ca-file "{root / "cert"}"; verify #true; }};'
            text += f'outbound "n{index}" type="{protocol}" {{ server host="n{index}.test" port=443; bootstrap-resolver "boot"; connect-timeout-ms 1200; {detour} {options} }}\n'
        text += 'routing { rulesets {{ "direct" path="direct.kdl" format="kdl"; }}; rules { - rule-set="direct" to="direct"; }; final "n15"; }\n'
        config = root / "config.kdl"
        config.write_text(text)
        errors = []

        def echo():
            try:
                with origin.accept()[0] as conn:
                    conn.settimeout(4)
                    if exact(conn, 4) != b"ping":
                        raise RuntimeError("direct payload mismatch")
                    conn.sendall(b"pong")
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=echo)
        thread.start()
        try:
            with running([args.binary.resolve(), "run", "--config", config], port, root / "nexus.log"):
                with socket.create_connection(("127.0.0.1", port), timeout=4) as blocked:
                    blocked.sendall(b"\x05\x01\x00")
                    if exact(blocked, 2) != b"\x05\x00":
                        raise RuntimeError("failed-chain negotiation failed")
                    started = time.monotonic()
                    target_port = fallback.getsockname()[1] if args.fallback else 9
                    blocked.sendall(b"\x05\x01\x00" + (b"\x03\x0btarget.test" if args.domain else b"\x01\x7f\x00\x00\x01") + target_port.to_bytes(2, "big"))
                    if not dns.negative.wait(2):
                        blocked.settimeout(.2)
                        try:
                            reply = blocked.recv(64)
                        except TimeoutError:
                            reply = b"pending"
                        raise RuntimeError(f"did not reach the lower failure: {dns.queries}; reply={reply!r}; {(root / 'nexus.log').read_text()}")
                    # Give the failure continuation time to run before the
                    # independent connection. This does not cover all ordering.
                    time.sleep(.03)
                    probe_started = time.monotonic()
                    client, _ = socks(port, 1, ("127.0.0.1", target))
                    with client:
                        client.sendall(b"ping")
                        if exact(client, 4) != b"pong":
                            raise RuntimeError("direct probe failed")
                    probe_elapsed = time.monotonic() - probe_started
                    reply = exact(blocked, 10)
                    elapsed = time.monotonic() - started
                    if args.fallback:
                        blocked.sendall(b"resume")
                        with fallback.accept()[0] as peer:
                            peer.settimeout(2)
                            if exact(peer, 6) != b"resume":
                                raise RuntimeError("fallback payload mismatch")
                            peer.sendall(b"ok")
                        if exact(blocked, 2) != b"ok":
                            raise RuntimeError("fallback response mismatch")
                    print(f"chain result: {elapsed:.3f}s, SOCKS={reply[1]}; independent direct: {probe_elapsed:.3f}s; lower DNS queries={dns.queries['n0.test']}")
                    expected = collections.Counter({f"n{i}.test": 1 for i in range(16)})
                    if args.domain:
                        expected["target.test"] = 1
                    if dns.queries != expected:
                        raise RuntimeError(f"expected one attempt per node: {dns.queries}")
                    if (reply[1] != 0 if args.fallback else reply[1] in (0, 6)) or elapsed > .7 or probe_elapsed > .4:
                        raise RuntimeError("lower failure multiplied across upper address candidates")
            thread.join(3)
            if thread.is_alive() or errors:
                raise RuntimeError(f"direct peer failed: {errors}")
        finally:
            dns.close()
            thread.join(5)


if __name__ == "__main__":
    main()
