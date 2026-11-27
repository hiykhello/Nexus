#!/usr/bin/env python3
"""Verify that an encrypted DNS transaction retains its selected egress."""

import concurrent.futures
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

from anytls_network import Origin
from connect_traffic_stats import trojan_server
from dns_encrypted_network import peer, query
from dns_https_detour_network import socks
from dns_rule_support import Echo, free_port, nexus_process
from local_control_network import run


class Health(BaseHTTPRequestHandler):
    def do_HEAD(self):
        healthy = (self.server.direct_healthy if self.client_address[0] == "127.0.0.2"
                   else self.server.edge_healthy)
        self.send_response(204 if healthy else 503)
        self.end_headers()

    def log_message(self, *_):
        pass


def selection(binary, control, name, chosen):
    end = time.monotonic() + 4
    while time.monotonic() < end:
        status = run(binary, control, "status")
        if f"group={name} selected={chosen}" in status.splitlines():
            return
        time.sleep(.02)
    raise RuntimeError(status)


def verify(binary, fixture, mode):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="nexus-dns-egress-group-")))
        upstream = stack.enter_context(trojan_server(binary, root))
        port, cert, event = stack.enter_context(peer(fixture, root, "h2", "127.0.0.1", trace_pool=True))
        service = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Health))
        service.direct_healthy = True
        service.edge_healthy = mode != "url-test"
        worker = threading.Thread(target=service.serve_forever, daemon=True)
        worker.start()
        stack.callback(worker.join)
        stack.callback(service.shutdown)
        listen, front = free_port(), free_port()
        control, config = root / "control.sock", root / "client.kdl"
        health = (f'probe-url "http://127.0.0.1:{service.server_port}/health"; '
                  'probe-interval-ms 500; probe-timeout-ms 600;') if mode != "manual" else ""
        group = "selector" if mode == "manual" else mode
        initial = 'selected "direct";' if mode == "manual" else ""
        source = f'''schema-version 1
role "client"
control socket="{control}"
workers 2
inbound "input" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbounds {{
    direct "direct" {{ inet4-bind-address "127.0.0.2"; }}
    {upstream}
    {group} "egress" {{ member "direct"; member "edge"; {initial} {health} }}
    selector "nested" {{ member "egress"; }}
}}
dns {{
    listen host="127.0.0.1" port={listen}
    server "secure" type="https" host="127.0.0.1" port={port} path="/resolve?profile=edge" server-name="dns.test" ca-file="{cert}" detour="nested"
    final "secure"
    strategy "ipv4_only"
}}
routing {{ final "direct"; }}
'''
        config.write_text(source)

        def observed(name, address):
            row = event().split()
            assert row[:3] == ["request", name, "HTTP/2.0"] and row[3].rsplit(":", 1)[0] == address, row
            return row[3]

        with (nexus_process(binary, config),
              Origin(expected=2) as origin,
              concurrent.futures.ThreadPoolExecutor(max_workers=1) as work):
            query(listen, "cached-message.test")
            first = observed("cached-message.test", "127.0.0.2")
            socks(front, "cached-address.test", origin.port, True)
            observed("cached-address.test", "127.0.0.2")
            in_flight = work.submit(query, listen, "switch-slow.test")
            assert observed("switch-slow.test", "127.0.0.2") == first

            if mode == "manual":
                run(binary, control, "select", "egress", "edge")
            else:
                service.edge_healthy = True
                service.direct_healthy = False
            selection(binary, control, "egress", "edge")
            assert not in_flight.done(), "the original query finished before egress changed"
            query(listen, "cached-message.test", transport=socket.SOCK_STREAM)
            second = observed("cached-message.test", "127.0.0.1")
            socks(front, "cached-address.test", origin.port, True)
            observed("cached-address.test", "127.0.0.1")
            origin.wait()
            in_flight.result(timeout=3)

            if mode == "manual":
                run(binary, control, "select", "egress", "direct")
            else:
                service.direct_healthy = True
                if mode == "url-test":
                    service.edge_healthy = False
            selection(binary, control, "egress", "direct")
            query(listen, "cached-message.test")
            third = observed("cached-message.test", "127.0.0.2")
            assert third != first and third != second

        cycle = source.replace('server host="127.0.0.1"', 'server host="edge.test"').replace(
            'authentication { password-file', 'bootstrap-resolver "secure"; authentication { password-file')
        config.write_text(cycle)
        invalid = subprocess.run([binary, "run", "--config", config], capture_output=True, timeout=5)
        assert invalid.returncode and b"outbound or DNS dependency cycle" in invalid.stderr, invalid.stderr

    print(f"DNS {mode} changed egress without reusing cached answers or the old pool")


def verify_balance(binary, fixture):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="nexus-dns-load-balance-")))
        upstream = stack.enter_context(trojan_server(binary, root))
        front, listen = free_port(), free_port()
        endpoints = []
        for host in ("127.0.0.1", "127.0.0.2"):
            directory = root / host
            directory.mkdir()
            port, cert, event = stack.enter_context(peer(fixture, directory, "h2", host, trace_pool=True))
            endpoints.append((host, port, cert, event))
        definitions = "\n    ".join(
            f'server "resolver-{i}" type="https" host="{host}" port={port} path="/resolve?profile=edge" '
            f'server-name="dns.test" ca-file="{cert}" detour="nested"'
            for i, (host, port, cert, _) in enumerate(endpoints))
        config = root / "client.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "input" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbounds {{
    direct "direct" {{ inet4-bind-address "127.0.0.2"; }}
    {upstream}
    load-balance "balance" {{ member "direct"; member "edge"; }}
    selector "nested" {{ member "balance"; }}
}}
dns {{
    listen host="127.0.0.1" port={listen}
    {definitions}
    rule domain-suffix="secondary.test" action="route" server="resolver-1"
    final "resolver-0"
    disable-cache #true
}}
routing {{ final "direct"; }}
''')
        origins = set()
        with nexus_process(binary, config):
            for i, name in enumerate(("first.primary.test", "first.secondary.test")):
                event = endpoints[i][3]
                query(listen, name)
                initial = event().split()
                assert initial[:3] == ["request", name, "HTTP/2.0"], initial
                origins.add(initial[3].rsplit(":", 1)[0])
                next_name = name.replace("first.", "second.")
                query(listen, next_name, transport=socket.SOCK_STREAM)
                repeated = event().split()
                assert repeated == ["request", next_name, "HTTP/2.0", initial[3]], repeated
        assert origins == {"127.0.0.1", "127.0.0.2"}, origins
    print("DNS load-balance used the same outbound and connection for each fixed upstream")


if __name__ == "__main__":
    binary, fixture = (str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:3])
    for mode in ("manual", "fallback", "url-test"):
        verify(binary, fixture, mode)
    verify_balance(binary, fixture)
