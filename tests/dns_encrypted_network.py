#!/usr/bin/env python3
"""Test DNS-over-HTTPS and DNS-over-QUIC against an independent Go peer."""

import argparse
import concurrent.futures
import contextlib
import select
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from detour_network import running
from dns_rule_support import DnsPeer, exact, free_port, question, wire_name


@contextlib.contextmanager
def peer(binary, root, protocol, host, *, trace_resumption=False, trace_pool=False,
         delay_handshake=False):
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-noenc", "-days", "1", "-subj", "/CN=dns.test", "-addext", "subjectAltName=DNS:dns.test",
                    "-out", cert, "-keyout", key], check=True, capture_output=True)
    address = f"[{host}]:0" if ":" in host else f"{host}:0"
    trace = (["-trace-quic-early"] if trace_resumption == "early" else
             ["-trace-quic-resumption"] if trace_resumption else [])
    if trace_pool:
        trace.append("-trace-doh-pool")
    if delay_handshake:
        trace.extend(("-delay-doh-handshake", "250ms"))
    with subprocess.Popen([binary, "-protocol", protocol, "-address", address, "-cert", cert, "-key", key, *trace],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as process:
        def line(timeout=3):
            if not select.select([process.stdout], [], [], timeout)[0]:
                raise RuntimeError("encrypted DNS peer did not report expected event")
            text = process.stdout.readline().decode().strip()
            if not text:
                raise RuntimeError(f"peer exited {process.poll()}: {process.stderr.read()!r}")
            return text

        try:
            port = int(line().rsplit(":", 1)[1])
            yield port, cert, line
        except BaseException as failure:
            process.terminate()
            output, errors = process.communicate(timeout=5)
            failure.add_note(f"peer output: {output!r}, stderr: {errors!r}")
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)


def query(port, name, *, kind=1, identifier=0xCFE1, code=0, transport=socket.SOCK_DGRAM, ttl=None, edns=False):
    wire = struct.pack("!6H", identifier, 0x100, 1, 0, 0, int(edns)) + wire_name(name) + struct.pack("!HH", kind, 1)
    if edns:
        wire += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
    with socket.socket(socket.AF_INET, transport) as client:
        client.settimeout(4)
        if transport == socket.SOCK_STREAM:
            client.connect(("127.0.0.1", port))
            client.sendall(struct.pack("!H", len(wire)) + wire)
            response = exact(client, int.from_bytes(exact(client, 2), "big"))
        else:
            client.sendto(wire, ("127.0.0.1", port))
            response = client.recv(2048)
    reply_id, flags, questions, answers = struct.unpack_from("!4H", response)
    assert (reply_id, flags & 0x800F, questions, answers) == (identifier, 0x8000 | code, 1, int(code == 0)), response
    got_name, got_type, end = question(response)
    assert (got_name, got_type) == (name, kind), response
    if not code:
        family, ip = (socket.AF_INET, "127.0.0.1") if kind == 1 else (socket.AF_INET6, "::1")
        assert response.endswith(socket.inet_pton(family, ip)), response
        if ttl is not None:
            assert struct.unpack_from("!I", response, end + 6)[0] == ttl, response


def config_text(protocol, front, port, host, upstream, cert, bootstrap, identity="dns.test"):
    if protocol == "quic":
        carrier = 'type="quic"'
    else:
        transport = "https3" if protocol == "h3" else "https"
        carrier = f'type="{transport}" path="/resolve?profile=edge"'
    resolver = ' domain-resolver="bootstrap"' if host == "resolver.test" else ""
    return f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
dns {{
  listen host="127.0.0.1" port={port}
  server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap}
  server "secure" {carrier} host="{host}" port={upstream}{resolver} server-name="{identity}" ca-file="{cert}" bind-interface="lo"
  rule domain="held.test" action="route" server="secure" timeout-ms=850
  final "secure"
  disable-cache #true
}}
routing {{ default-outbound "direct"; }}
'''


def verify_cold_http2(binary, fixture, host):
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as bootstrap:
        root = Path(directory)
        config = root / "nexus.kdl"
        front, listen = free_port(), free_port()
        with peer(fixture, root, "h2", host, trace_pool=True, delay_handshake=True) as (port, cert, event):
            config.write_text(config_text("h2", front, listen, host, port, cert, bootstrap.port)
                              .replace('domain="held.test"', 'domain="cold-short.test"')
                              .replace("timeout-ms=850", "timeout-ms=125"))
            with (running([binary, "run", "--config", config], front, root / "nexus.log"),
                  concurrent.futures.ThreadPoolExecutor(max_workers=3) as work):
                short = work.submit(query, listen, "cold-short.test", code=2)
                assert event() == "handshake"
                pending = [work.submit(query, listen, f"cold-{index}.test", ttl=29) for index in range(2)]
                short.result(timeout=2)
                for future in pending:
                    future.result(timeout=2)
                requests = [event().split(), event().split()]
                assert {tuple(row[:3]) for row in requests} == {
                    ("request", "cold-0.test", "HTTP/2.0"), ("request", "cold-1.test", "HTTP/2.0")
                }, requests
                assert requests[0][3] == requests[1][3], requests
    print(f"{host}: one cold HTTP/2 handshake survived the first waiter's cancellation")


def verify(binary, fixture, protocol, host, pooled=False):
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as bootstrap:
        root = Path(directory)
        config = root / "nexus.kdl"
        front, listen = free_port(), free_port()
        with peer(fixture, root, protocol, host, trace_pool=pooled) as (upstream, cert, event):
            authority = "resolver.test" if host == "127.0.0.1" else host
            text = config_text(protocol, front, listen, authority, upstream, cert, bootstrap.port)
            config.write_text(text)
            with running([binary, "run", "--config", config], front, root / "nexus.log"):
                ttl = 40 if protocol == "quic" else 29
                query(listen, "first.test", ttl=ttl)
                first = event().split()
                query(listen, "second.test", kind=28, transport=socket.SOCK_STREAM, ttl=ttl)
                second = event().split()
                assert first[:2] == ["request", "first.test"] and second[:2] == ["request", "second.test"]
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as work:
                    held = work.submit(query, listen, "held.test", code=2)
                    held_stream = event().split()
                    assert held_stream[:2] == ["request", "held.test"], held_stream
                    work.submit(query, listen, "partner.test", ttl=ttl).result(timeout=2)
                    held.result(timeout=2)
                    finish_events = [event().split(), event().split()]
                    partner_stream = next(row for row in finish_events if row[:2] == ["request", "partner.test"])
                    assert ["canceled", "held.test"] in finish_events, finish_events
                if protocol == "quic":
                    streams = (first, second, held_stream, partner_stream)
                    assert len({row[2] for row in streams}) == 1 and len({row[3] for row in streams}) == len(streams), streams
                    for name in ("reset.test", "bad-id.test", "extra.test"):
                        try:
                            query(listen, name, code=2)
                        except Exception as error:
                            error.add_note(f"waiting for failure response to {name}")
                            raise
                        assert event().split()[:2] == ["request", name]
                        query(listen, "after-error.test")
                        assert event().split()[:2] == ["request", "after-error.test"]
                else:
                    expected_version = {"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol]
                    streams = (first, second, held_stream, partner_stream)
                    assert all(row[2] == expected_version for row in streams)
                    if pooled:
                        assert len({row[3] for row in streams}) == 1, streams
                    for name in ("wrong-type.test", "redirect.test"):
                        query(listen, name, code=2)
                        received = event().split()
                        assert received[:2] == ["request", name]
                        if pooled:
                            assert received[3] == first[3], received
                    if pooled:
                        query(listen, "after-reset.test", ttl=ttl)
                        received = event().split()
                        assert received == ["request", "after-reset.test", expected_version, first[3]], received
                        print(f"{host}: DoH {expected_version} reused one authenticated connection through parallel stream cancellation")
                if authority != host:
                    assert bootstrap.count("resolver.test", 1), bootstrap.seen
                    assert all(name == "resolver.test" for name, *_ in bootstrap.seen), bootstrap.seen

            config.write_text(config_text(protocol, front, listen, host, upstream, cert, bootstrap.port, "wrong.test"))
            with running([binary, "run", "--config", config], front, root / "wrong.log"):
                query(listen, "wrong.test", code=2)
            if protocol != "quic":
                config.write_text(text.replace("/resolve?profile=edge", "//invalid"))
                bad = subprocess.run([binary, "run", "--config", config], capture_output=True, timeout=3)
                assert bad.returncode and b"invalid DoH request path" in bad.stderr, bad.stderr
            print(f"{protocol} {host}: authenticated DNS, binary framing, parallel cancellation and protected failure passed")


def verify_resumption(binary, fixture, host, enabled):
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as bootstrap:
        root = Path(directory)
        config = root / "nexus.kdl"
        front, listen = free_port(), free_port()
        with peer(fixture, root, "quic", host, trace_resumption=True) as (upstream, cert, event):
            text = config_text("quic", front, listen, host, upstream, cert, bootstrap.port)
            secure = next(line for line in text.splitlines() if 'server "secure"' in line)
            isolated = secure.replace('"secure"', '"isolated"', 1)
            config.write_text(text.replace('  final "secure"',
                isolated + '\n  rule domain-suffix="isolated.test" action="route" server="isolated"\n  final "secure"'))
            with running([binary, "run", "--config", config], front, root / "nexus.log"):
                rounds = (
                    ("first.test", False),
                    ("second.test", enabled),
                    ("first.isolated.test", False),
                    ("second.isolated.test", enabled),
                    ("reject-next-ticket.test", enabled),
                    ("fallback.test", False),
                    ("renewed.test", enabled),
                )
                for index, (name, resumed) in enumerate(rounds, 1):
                    if index > 1:
                        time.sleep(1.35)  # The DoQ pool retires idle connections after one second.
                    query(listen, name, ttl=40)
                    if enabled and name == "fallback.test":
                        assert event() == "ticket rejected"
                    handshake = event().split()
                    assert handshake == ["handshake", str(index), f"resumed={str(resumed).lower()}", "early=false"], handshake
                    request = event().split()
                    assert request == ["request", name, str(index), "0"], request
            if not enabled:
                config.write_text(text.replace('type="quic"', 'type="quic" early-data=#true'))
                rejected = subprocess.run([binary, "run", "--config", config], capture_output=True, timeout=3)
                assert rejected.returncode and b"DoQ early-data requires dns-quic-resumption" in rejected.stderr, rejected.stderr
    state = "resumed after idle, isolated profiles, rejected and renewed tickets" if enabled else "full handshakes only"
    print(f"quic {host}: {state}, queries stayed on 1-RTT")


def verify_early_data(binary, fixture, host):
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as bootstrap:
        root = Path(directory)
        config = root / "nexus.kdl"
        front, listen = free_port(), free_port()
        with peer(fixture, root, "quic", host, trace_resumption="early") as (upstream, cert, event):
            text = config_text("quic", front, listen, host, upstream, cert, bootstrap.port)
            text = text.replace('type="quic"', 'type="quic" early-data=#true')
            config.write_text(text.replace('  final "secure"',
                '  rule domain="abandon-early.test" action="route" server="secure" timeout-ms=100\n  final "secure"'))
            with running([binary, "run", "--config", config], front, root / "nexus.log"):
                rounds = (
                    (False, False, False, False),
                    (True, True, True, False),
                    (True, False, True, False),
                    (True, True, True, False),
                    (True, False, False, True),
                )
                for index, (resumed, early, sent, edns) in enumerate(rounds, 1):
                    if index > 1:
                        time.sleep(1.35)
                    name = f"request-{index}.test"
                    query(listen, name, kind=28 if index == 4 else 1, ttl=40, edns=edns)
                    handshake = event().split()
                    expected = [f"{field}={str(value).lower()}" for field, value in
                                zip(("resumed", "early", "sent"), (resumed, early, sent), strict=True)]
                    assert handshake == ["handshake", str(index), *expected], handshake
                    request = event().split()
                    assert request == ["request", name, str(index), "0"], request
                time.sleep(1.35)
                query(listen, "abandon-early.test", code=2)
                assert event() == "handshake 6 resumed=true early=false sent=true"
                query(listen, "after-abandon.test", ttl=40)
                assert event() == "request after-abandon.test 6 0"
    print(f"quic {host}: A/AAAA 0-RTT delivered, rejected early data retried once, EDNS and cancellation passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--assert-h2-pool", action="store_true")
    parser.add_argument("--cold-h2", action="store_true")
    parser.add_argument("protocols", choices=("h1", "h2", "quic"), nargs="+")
    parser.add_argument("--resumption", choices=("enabled", "disabled", "early"))
    args = parser.parse_args()
    for protocol in args.protocols:
        for host in ("127.0.0.1", "::1"):
            nexus, fixture = args.nexus.resolve(strict=True), args.peer.resolve(strict=True)
            if protocol == "h2" and args.cold_h2:
                verify_cold_http2(nexus, fixture, host)
            elif protocol == "quic" and args.resumption == "early":
                verify_early_data(nexus, fixture, host)
            elif protocol == "quic" and args.resumption:
                verify_resumption(nexus, fixture, host, args.resumption == "enabled")
            else:
                verify(nexus, fixture, protocol, host, protocol == "h2" and args.assert_h2_pool)


if __name__ == "__main__":
    main()
