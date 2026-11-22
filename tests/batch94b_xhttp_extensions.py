"""Transport split, cancellation, and pairing checks for the XHTTP network matrix."""

from errno import EADDRINUSE
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import http.client
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import time
import uuid

from detour_network import exact, reserve, running, socks
from tls_fingerprint_cli import Observer


@contextmanager
def running_edge(command, port, log, protocol, exit_codes=(0,)):
    if protocol != "h3" and exit_codes == (0,):
        with running(command, port, log) as process:
            yield process
        return
    with log.open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            while True:
                if process.poll() is not None:
                    raise RuntimeError(log.read_text())
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "h3" else socket.SOCK_STREAM) as probe:
                    try:
                        if protocol == "h3":
                            probe.bind(("127.0.0.1", port))
                        else:
                            probe.settimeout(.2)
                            if not probe.connect_ex(("127.0.0.1", port)):
                                break
                    except OSError as error:
                        if error.errno != EADDRINUSE:
                            raise
                        break
                if time.monotonic() >= deadline:
                    raise RuntimeError("UDP listener did not start")
                time.sleep(.02)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError(f"UDP listener failed to drain: {log.read_text()}")
            if process.returncode not in exit_codes:
                raise RuntimeError(f"exit={process.returncode}: {log.read_text()}")


def download_settings(binary, root, protocol, mode, harness):
    edge, local = reserve(), reserve()
    server = harness.nexus_command(binary, root, "server", edge, edge, protocol, mode)
    with running(server, edge, root / "server.log"), Observer(edge) as upload, Observer(edge) as download:
        extra = f'''
        download-settings {{
          server host="127.0.0.1" port={download.port};
          protocol "{protocol}";
          path "{harness.PATH}";
          tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
        }}
        '''
        client = harness.nexus_command(binary, root, "client", local, upload.port, protocol, mode, extra=extra)
        with running(client, local, root / "client.log"):
            harness.exchange(local, mode == "stream-up", 5)
        assert upload.messages and len(download.messages) == 1, (upload.messages, download.messages)
    print(f"{protocol} {mode}, independent download endpoint: both TLS paths and large transfer passed")


def xmux_reuse(binary, root, harness):
    edge, local = reserve(), reserve()
    server = harness.nexus_command(binary, root, "server", edge, edge, "h2", "stream-one")
    with running(server, edge, root / "server.log"), Observer(edge) as wire:
        mux = "xmux { max-connections 1; max-concurrency 3; c-max-reuse-times 1; }"
        client = harness.nexus_command(binary, root, "client", local, wire.port, "h2", "stream-one", extra=mux)
        with running(client, local, root / "client.log"):
            harness.exchange(local, True, 6)
            harness.exchange(local, True, 7)
            assert len(wire.messages) == 1, wire.messages
            harness.exchange(local, True, 8)
            assert len(wire.messages) == 2, wire.messages
    print("h2 xmux shared one TLS connection across tunnels and rotated at its reuse limit")


def mixed_download(helper, binary, root, front, back, upload, mode, harness):
    edge, local, translated = harness.reserve_edge(back), reserve(), harness.reserve_edge(front)
    server = harness.nexus_command(binary, root, "server", edge, edge, back, mode)
    split = f'''
    download-settings {{
      server host="127.0.0.1" port={edge if upload == front else translated};
      protocol "{back if upload == front else front}";
      path "{harness.PATH}";
      tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
    }}
    '''
    client_edge = translated if upload == front else edge
    client = harness.nexus_command(binary, root, "client", local, client_edge, upload, mode, extra=split)
    reverse = [helper, front, f"127.0.0.1:{translated}", back, f"https://localhost:{edge}",
               root / "cert", root / "key"]
    with ExitStack() as stack:
        stack.enter_context(running_edge(server, edge, root / "server.log", back))
        stack.enter_context(running_edge(reverse, translated, root / "edge.log", front, exit_codes=(0, -15)))
        stack.enter_context(running(client, local, root / "client.log"))
        harness.exchange(local, mode == "stream-up", 9)
        method = "POST" if upload == front else "GET"
        protocol = {"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[front]
        if f"{protocol} {method} {harness.PATH}" not in (root / "edge.log").read_text():
            raise AssertionError((root / "edge.log").read_text())
    print(f"{upload}/{back if upload == front else front} {mode}, separate HTTP versions and TLS endpoints passed")


def pairing_and_abort(binary, root, harness):
    edge = reserve()
    path = harness.PATH
    session = str(uuid.uuid4())
    orphan = str(uuid.uuid4())
    context = ssl.create_default_context(cafile=root / "cert")
    context.set_alpn_protocols(["http/1.1"])
    injected = b"xhttp-reorder"
    authority = "localhost"
    profiles = 'max-sessions 1; pair-timeout-ms 500; sc-max-buffered-posts 3;'
    server = harness.nexus_command(binary, root, "server", edge, edge, "h1", "packet-up", extra=profiles)

    def padding(target):
        return "https://localhost" + target + "?x_padding=" + "X" * 100

    def request(method, target, body=None):
        conn = http.client.HTTPSConnection(authority, edge, context=context, timeout=5)
        conn.request(method, target, body, {"Referer": padding(target), "Connection": "close"})
        return conn, conn.getresponse()

    def post(target, body, status):
        conn, response = request("POST", target, body)
        with response:
            assert response.status == status, (target, response.status, status)
            assert not response.read()
        conn.close()

    with running(server, edge, root / "server.log") as process:
        files = Path(f"/proc/{process.pid}/fd")
        time.sleep(.1)
        baseline = harness.session_descriptors(files)
        post(f"{path}{orphan}/1", b"orphan", 200)
        post(f"{path}{session}/1", b"busy", 503)
        time.sleep(.6)

        with socket.socket() as origin, ThreadPoolExecutor(max_workers=1) as worker:
            origin.bind(("127.0.0.1", 0))
            origin.listen()
            origin.settimeout(5)
            destination = origin.getsockname()[1]
            header = b"\x00" + uuid.UUID(harness.UUID).bytes + b"\x00\x01"
            header += destination.to_bytes(2, "big") + b"\x01" + socket.inet_aton("127.0.0.1")

            def relay():
                with origin.accept()[0] as conn:
                    conn.settimeout(5)
                    assert exact(conn, len(injected)) == injected
                    conn.sendall(injected[::-1])
                    conn.shutdown(socket.SHUT_WR)

            job = worker.submit(relay)
            post(f"{path}{session}/1", injected[4:], 200)
            post(f"{path}{session}/1", b"duplicate", 409)
            post(f"{path}{session}/3", b"outside window", 409)
            post(f"{path}{session}/0", header + injected[:4], 200)
            conn, response = request("GET", f"{path}{session}")
            with response:
                assert response.status == 200, response.status
                assert response.read() == b"\x00\x00" + injected[::-1]
            conn.close()
            job.result()

        for _ in range(8):
            target = f"{path}{uuid.uuid4()}/0"
            with context.wrap_socket(socket.create_connection(("127.0.0.1", edge), timeout=5),
                                     server_hostname=authority) as abandoned:
                abandoned.sendall(
                    f"POST {target} HTTP/1.1\r\nHost: {authority}\r\nReferer: {padding(target)}\r\n"
                    "Content-Length: 1024\r\n\r\npartial".encode()
                )
                abandoned.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        post(f"{path}{uuid.uuid4()}/0", b"fresh", 200)
        deadline = time.monotonic() + 5
        while harness.session_descriptors(files) != baseline:
            assert time.monotonic() < deadline, (baseline, harness.session_descriptors(files))
            time.sleep(.05)
    print("h1 packet-up, reorder, duplicate/window rejection, orphan timeout and partial POST reset passed")


def xmux_reset(binary, root, harness):
    edge, local = reserve(), reserve()
    server = harness.nexus_command(binary, root, "server", edge, edge, "h2", "stream-one")
    with running(server, edge, root / "server.log"), Observer(edge) as wire, socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(5)
        mux = "xmux { max-connections 1; max-concurrency 3; }"
        client = harness.nexus_command(binary, root, "client", local, wire.port, "h2", "stream-one", extra=mux)
        with running(client, local, root / "client.log"), socks(local, 1, origin.getsockname())[0] as flow:
            with origin.accept()[0] as peer:
                flow.settimeout(5)
                peer.settimeout(5)
                with socks(local, 1, origin.getsockname())[0] as broken:
                    with origin.accept()[0] as lost:
                        lost.settimeout(5)
                        broken.sendall(b"x")
                        assert exact(lost, 1) == b"x"
                        broken.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    # The active flow stays on the shared carrier after its peer is reset.
                flow.sendall(b"alive")
                assert exact(peer, 5) == b"alive"
                peer.sendall(b"still-alive")
                assert exact(flow, 11) == b"still-alive"
                assert len(wire.messages) == 1, wire.messages
    print("h2 xmux, a reset stream leaves its concurrently active peer connected")


def h3_reclaim(binary, root, harness):
    edge, local = harness.reserve_edge("h3"), reserve()
    server = harness.nexus_command(binary, root, "server", edge, edge, "h3", "stream-one")
    mux = "xmux { max-connections 1; max-concurrency 1; c-max-reuse-times 1; }"
    client = harness.nexus_command(binary, root, "client", local, edge, "h3", "stream-one", extra=mux)
    with running_edge(server, edge, root / "server.log", "h3") as service, running(client, local, root / "client.log"):
        files = Path(f"/proc/{service.pid}/fd")
        baseline = harness.session_descriptors(files)
        with socket.socket() as origin, ThreadPoolExecutor(max_workers=1) as worker:
            origin.bind(("127.0.0.1", 0))
            origin.listen(1)
            origin.settimeout(5)
            payload = b"xhttp"

            def echo():
                for _ in range(68):
                    with origin.accept()[0] as peer:
                        peer.settimeout(5)
                        assert exact(peer, len(payload)) == payload
                        assert not peer.recv(1)
                        peer.sendall(payload)

            job = worker.submit(echo)
            for _ in range(68):
                with socks(local, 1, origin.getsockname())[0] as flow:
                    flow.settimeout(5)
                    flow.sendall(payload)
                    flow.shutdown(socket.SHUT_WR)
                    assert exact(flow, len(payload)) == payload and not flow.recv(1)
            job.result()
        deadline = time.monotonic() + 5
        while harness.session_descriptors(files) != baseline:
            assert time.monotonic() < deadline, (baseline, harness.session_descriptors(files))
            time.sleep(.05)
    print("h3 xmux, 34 rotated QUIC connections recover server slots and descriptors")
