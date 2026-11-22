#!/usr/bin/env python3
"""A fixed TCP listener routes each connection to its admitted generation's target."""

from contextlib import contextmanager
from pathlib import Path
import socket
import sys
import tempfile
from threading import Thread

from dns_rule_support import DnsPeer, exact, nexus_process
from proxy_listener_reload_network import reload


@contextmanager
def origin(host, label):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family) as server:
        server.settimeout(5)
        server.bind((host, 0))
        server.listen(1)
        errors = []

        def serve():
            try:
                raw, _ = server.accept()
                with raw:
                    raw.settimeout(5)
                    assert exact(raw, 3) == b"one"
                    raw.sendall(label)
                    assert exact(raw, 3) == b"two"
                    assert raw.recv(1) == b""
                    raw.sendall(b"end-" + label)
                    raw.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)

        task = Thread(target=serve)
        task.start()
        try:
            yield server.getsockname()[1]
        finally:
            task.join(6)
        assert not task.is_alive()
        if errors:
            raise errors[0]


def test(binary, root, listen_host):
    family = socket.AF_INET6 if ":" in listen_host else socket.AF_INET
    with socket.socket(family) as reserve:
        reserve.bind((listen_host, 0))
        front = reserve.getsockname()[1]
    config = root / "fixed.kdl"
    with DnsPeer() as dns, origin("127.0.0.1", b"ipv4") as first, origin("::1", b"ipv6") as second:
        def write(target, port, reject=False):
            action = 'rule action="reject";' if reject else 'rule action="route" outbound="direct";'
            config.write_text(f'''schema-version 1
role "server"
workers 2
shutdown-grace-ms 4500
inbounds {{
    fixed-tcp "input" {{
        listen host="{listen_host}" port={front}
        target host="{target}" port={port}
    }}
}}
outbound "direct" type="direct"
routing {{
    default-outbound "direct"
    tcp-program sniff-timeout-ms=100 unknown="skip" {{
        {action}
    }}
}}
dns {{
    server "dns" type="udp" host="{dns.host}" port={dns.port}
    final "dns"
}}
''')

        write("fixed-target.test", first)
        with nexus_process(binary, config) as process:
            with socket.create_connection((listen_host, front), timeout=3) as old:
                old.sendall(b"one")
                assert exact(old, 4) == b"ipv4"
                assert dns.count("fixed-target.test", 1) >= 1
                write("::1", second)
                assert reload(process) == 2
                with socket.create_connection((listen_host, front), timeout=3) as new:
                    new.sendall(b"one")
                    assert exact(new, 4) == b"ipv6"
                    for stream, label in ((old, b"ipv4"), (new, b"ipv6")):
                        stream.sendall(b"two")
                        stream.shutdown(socket.SHUT_WR)
                        assert exact(stream, 8) == b"end-" + label
                        assert stream.recv(1) == b""
        write("::1", second, reject=True)
        with nexus_process(binary, config), socket.create_connection((listen_host, front), timeout=3) as rejected:
            assert rejected.recv(1) == b""


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-fixed-tcp-") as folder:
        for listener in ("127.0.0.1", "::1"):
            test(cli, Path(folder), listener)
    print("Fixed TCP listeners forwarded IPv4/IPv6 targets, preserved old generation and half-close, and applied route rejection")
