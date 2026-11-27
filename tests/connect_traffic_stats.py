"""Exercise the production CONNECT counters, including prefetched payload."""
import contextlib
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ordered_tcp_network import exact, headers
from detour_network import reserve, running


def snapshot(proc, expected_active):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        proc.send_signal(signal.SIGUSR1)
        assert select.select([proc.stderr], [], [], 2)[0], "missing SIGUSR1 snapshot"
        kind, *fields = proc.stderr.readline().decode().split()
        assert kind == "traffic", (kind, fields)
        totals = dict(field.split("=", 1) for field in fields)
        rows = {}
        for _ in range(int(totals["active"])):
            assert select.select([proc.stderr], [], [], 2)[0], "missing connection row"
            kind, *fields = proc.stderr.readline().decode().split()
            assert kind == "connection", (kind, fields)
            row = dict(field.split("=", 1) for field in fields)
            rows[row["protocol"]] = row
        assert select.select([proc.stderr], [], [], 2)[0], "missing process total"
        kind, *fields = proc.stderr.readline().decode().split()
        assert kind == "traffic-total", (kind, fields)
        combined = dict(field.split("=", 1) for field in fields)
        assert all(combined[name] == totals[name] for name in ("active", "upload", "download")), combined
        if int(totals["active"]) == expected_active:
            return (int(totals["upload"]), int(totals["download"])), rows
        time.sleep(.05)
    raise AssertionError(f"unexpected active connections: {totals}")


@contextlib.contextmanager
def trojan_server(binary, root, direct_address=None):
    port = reserve()
    cert, key, password = (root / name for name in ("cert", "key", "password"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-keyout", str(key), "-out", str(cert), "-nodes", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost", "-days", "1"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    password.write_text("traffic-stats-test")
    password.chmod(0o600)
    direct = ('outbound "direct" type="direct"' if direct_address is None else
              f'outbound "direct" type="direct" {{ inet4-bind-address "{direct_address}"; }}')
    config = root / "trojan.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbound "edge" type="trojan" {{
    listen host="127.0.0.1" port={port}
    authentication {{ user "test" password-file="{password}"; }}
    tls {{ certificate-file "{cert}"; private-key-file "{key}"; }}
}}
{direct}
routing {{ final "direct"; }}
''')
    with running([binary, "run", "--config", str(config)], port, root / "trojan.log"):
        yield f'''trojan "edge" {{
    server host="127.0.0.1" port={port}
    authentication {{ password-file "{password}"; }}
    tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
}}
'''


def run(binary, ordered, fast_open, trojan=False):
    with socket.socket() as destination, tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
        destination.bind(("127.0.0.1", 0))
        destination.listen()
        destination.settimeout(5)
        target_port = destination.getsockname()[1]
        listen_port = reserve()
        direct = "{ tcp-fast-open #true; }" if fast_open else ""
        outbound = stack.enter_context(trojan_server(binary, Path(directory))) if trojan else ""
        selected = "edge" if trojan else "direct"
        program = ('tcp-program sniff-timeout-ms=100 unknown="skip" { '
                   f'rule action="sniff"; rule action="route" outbound="{selected}"; }}') if ordered else ""
        config = Path(directory, "proxy.kdl")
        config.write_text(f'''schema-version 1
role "client"
workers 2
inbounds {{
    mixed "local" {{
        listen host="127.0.0.1" port={listen_port}
        authentication "none"
    }}
}}
outbounds {{
    direct "direct" {direct}
    {outbound}
}}
routing {{
    {program}
    final "{selected}"
}}
''')
        command = [binary, "run", "--traffic-stats", "--config", str(config)]
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, bufsize=0) as proc:
            try:
                totals = verify(proc, listen_port, destination, target_port, ordered, "tunnel" if trojan else "direct")
                if not ordered:
                    totals = verify_forward(proc, listen_port, destination, target_port, totals)
                    verify_udp(proc, listen_port, totals)
            finally:
                proc.terminate()
                proc.wait(timeout=5)
            assert proc.returncode == 0, proc.stderr.read().decode()


def verify(proc, listen_port, destination, target_port, ordered, path):
    for _ in range(100):
        assert proc.poll() is None, proc.stderr.read().decode()
        try:
            http = socket.create_connection(("127.0.0.1", listen_port), timeout=.1)
            break
        except OSError:
            time.sleep(.05)
    else:
        raise AssertionError("listener did not start")
    first = b"GET / HTTP/1.1\r\nHost: stats.test\r\n\r\n"
    with http, socket.create_connection(("127.0.0.1", listen_port), timeout=5) as socks:
        http.settimeout(5)
        target = f"127.0.0.1:{target_port}"
        http.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode() + first)
        response = headers(http)
        assert response.startswith(b"HTTP/1.1 200 "), response
        peer_http, _ = destination.accept()
        with peer_http:
            peer_http.settimeout(5)
            assert exact(peer_http, len(first)) == first
            socks.sendall(b"\x05\x01\x00")
            assert exact(socks, 2) == b"\x05\x00"
            request = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target_port)
            socks.sendall(request + (first if ordered else b""))
            assert exact(socks, 10)[:2] == b"\x05\x00"
            if not ordered:
                socks.sendall(first)
            peer_socks, _ = destination.accept()
            with peer_socks:
                peer_socks.settimeout(5)
                assert exact(peer_socks, len(first)) == first
                peer_http.sendall(b"HTTP")
                peer_socks.sendall(b"SOCKS")
                assert exact(http, 4) == b"HTTP"
                assert exact(socks, 5) == b"SOCKS"
                totals, rows = snapshot(proc, 2)
                assert totals == (2 * len(first), 9), totals
                assert set(rows) == {"http-connect", "socks5"}, rows
                assert len({row["id"] for row in rows.values()}) == 2
                for protocol, client, received in (("http-connect", http, 4), ("socks5", socks, 5)):
                    row = rows[protocol]
                    assert row["path"] == path and int(row["destination-port"]) == target_port, row
                    assert int(row["source-port"]) == client.getsockname()[1], (row, client.getsockname())
                    assert (int(row["upload"]), int(row["download"])) == (len(first), received), row
                http.shutdown(socket.SHUT_WR)
                assert peer_http.recv(1) == b""
                peer_http.sendall(b"tail")
                assert exact(http, 4) == b"tail"
                peer_http.shutdown(socket.SHUT_WR)
                assert http.recv(1) == b""
                peer_socks.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    totals, rows = snapshot(proc, 0)
    assert totals == (2 * len(first), 13) and not rows, (totals, rows)
    return totals


def verify_forward(proc, listen_port, destination, target_port, previous):
    with socket.create_connection(("127.0.0.1", listen_port), timeout=5) as client:
        authority = f"127.0.0.1:{target_port}"
        client.sendall(f"POST http://{authority}/stats HTTP/1.1\r\nHost: {authority}\r\n"
                       "Content-Length: 4\r\n\r\nbody".encode())
        peer, _ = destination.accept()
        with peer:
            peer.settimeout(5)
            head = headers(peer)
            assert head.startswith(b"POST /stats HTTP/1.1\r\n"), head
            assert exact(peer, 4) == b"body"
            expected_upload = len(head) + 4
            peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            response = headers(client)
            assert response.startswith(b"HTTP/1.1 200 ")
            assert exact(client, 2) == b"OK"
            expected_download = len(response) + 2
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1) == b""
    expected = (previous[0] + expected_upload, previous[1] + expected_download)
    assert snapshot(proc, 0)[0] == expected
    return expected


def verify_udp(proc, listen_port, previous):
    with (socket.create_connection(("127.0.0.1", listen_port), timeout=5) as control,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client):
        origin.bind(("127.0.0.1", 0))
        origin.settimeout(5)
        client.settimeout(5)
        control.sendall(b"\x05\x01\x00")
        assert exact(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01" + bytes(6))
        reply = exact(control, 10)
        assert reply[:4] == b"\x05\x00\x00\x01", reply
        relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:])[0])
        frame = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", origin.getsockname()[1])
        client.sendto(frame + b"probe", relay)
        payload, source = origin.recvfrom(64)
        assert payload == b"probe"
        origin.sendto(b"reply!", source)
        assert client.recvfrom(64)[0] == frame + b"reply!"
        expected = (previous[0] + 5, previous[1] + 6)
        totals, rows = snapshot(proc, 1)
        assert totals == expected, totals
        row = rows["socks5-udp"]
        assert row["path"] == "datagrams" and row["destination-port"] == "0", row
        assert int(row["source-port"]) == control.getsockname()[1], row
        assert (int(row["upload"]), int(row["download"])) == (5, 6), row
    assert snapshot(proc, 0)[0] == expected


if __name__ == "__main__":
    for ordered, fast_open in [(False, False), (True, False), (True, True)]:
        run(sys.argv[1], ordered, fast_open)
    if "--trojan" in sys.argv[2:]:
        run(sys.argv[1], True, False, trojan=True)
    print("CONNECT, forward HTTP and SOCKS UDP traffic totals passed")
