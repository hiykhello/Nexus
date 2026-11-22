#!/usr/bin/env python3
"""A stalled HTTP probe times out on each QUIC worker's routing executor."""

from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import exact, nexus_process
from outbound_group_health_network import configure
from quic_proxy_route_reload_network import peer_config
from udp_bind_port_network import certificate


def check(binary, directory, protocol):
    root = directory / protocol
    root.mkdir(mode=0o700)
    certificate(root)
    with socket.socket(type=socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        peer_port = reservation.getsockname()[1]
    config, _ = peer_config(root, protocol, peer_port)
    text = config.read_text()
    control = root / "control.sock"
    with socket.socket() as peer:
        peer.settimeout(5)
        peer.bind(("127.0.0.1", 0))
        peer.listen(1)
        configure(config, text[text.index("inbound "):text.index('outbound "direct"')], control,
                  "127.0.0.1", peer.getsockname()[1], role="server")
        config.write_text(config.read_text().replace("probe-timeout-ms 1700", "probe-timeout-ms 350")
                          .replace("probe-interval-ms 500", "probe-interval-ms 60000"))
        closed = threading.Event()
        errors = []

        def stall():
            try:
                raw, _ = peer.accept()
                with raw:
                    raw.settimeout(2)
                    request = bytearray()
                    while not request.endswith(b"\r\n\r\n"):
                        assert len(request) < 1024
                        request.extend(exact(raw, 1))
                    assert request.startswith(b"HEAD /health HTTP/1.1\r\n")
                    assert raw.recv(1) == b""
                    closed.set()
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=stall)
        thread.start()
        try:
            with nexus_process(binary, config):
                assert closed.wait(1.6), (protocol, "stalled probe was not canceled")
                until = time.monotonic() + 1.5
                while True:
                    state = subprocess.check_output([binary, "control", control, "group-health", "backup"],
                                                    text=True, timeout=3)
                    if "member=direct state=down " in state:
                        break
                    assert time.monotonic() < until, state
                    time.sleep(.02)
        finally:
            thread.join(6)
        if errors:
            raise errors[0]
    print(f"Stalled health probe on {protocol} closed at its deadline and published down")


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-probe-deadline-") as temp:
        for listener in ("hysteria2", "tuic"):
            check(cli, Path(temp), listener)
