#!/usr/bin/env python3
"""Complete gRPC responses under TCP backpressure before owner teardown."""
import argparse
import contextlib
import errno
import hashlib
import json
import pathlib
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time

from grpc_network import PAYLOAD, REVISION, SERVICE, UUID, box, exact, free_port, origin
from grpc_tls_network import certificates, client_config


@contextlib.contextmanager
def paced_tap(listener, remote):
    ends, errors = [], []
    state = {}

    def move(source, target, label):
        total = 0
        try:
            while True:
                part = source.recv(4096 if label == "down" else 65536)
                if not part:
                    state[label + "_eof"] = True
                    break
                target.sendall(part)
                total += len(part)
                if label == "down":
                    time.sleep(.002)
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError as error:
                if error.errno != errno.ENOTCONN:
                    raise
                state[label + "_shutdown_after_eof_errno"] = error.errno
        except Exception as error:
            errors.append(label + ": " + str(error))
        finally:
            state[label + "_bytes"] = total

    def serve():
        try:
            go, _ = listener.accept()
            nexus = socket.socket()
            ends.extend((go, nexus))
            nexus.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            nexus.settimeout(5)
            go.settimeout(5)
            nexus.connect(("127.0.0.1", remote))
            upload = threading.Thread(target=move, args=(go, nexus, "up"))
            download = threading.Thread(target=move, args=(nexus, go, "down"))
            upload.start()
            download.start()
            upload.join(6)
            download.join(6)
        except Exception as error:
            errors.append(str(error))

    worker = threading.Thread(target=serve)
    worker.start()
    failed = False
    try:
        yield state
    except BaseException:
        failed = True
        raise
    finally:
        worker.join(7)
        for end in ends:
            end.close()
        listener.close()
        worker.join(1)
        state["tap_errors"] = errors
        if not failed and (worker.is_alive() or errors or not state.get("up_eof") or not state.get("down_eof")):
            raise RuntimeError("TCP tap did not drain: " + repr(state))


def exercise(binary, peer, root, backend, tls):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        tapped_port = listener.getsockname()[1]
        command = [binary, "server", "0"]
        if tls:
            command += [root / "cert", root / "key"]
        command += [str(backend), "0"]
        if not tls:
            command += ["127.0.0.1:" + str(tapped_port)]
        server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if not select.select([server.stdout], [], [], 6)[0]:
                raise RuntimeError("fixture did not listen")
            line = server.stdout.readline()
            if not line.strip().isdigit():
                raise RuntimeError("fixture did not publish a port")
            with paced_tap(listener, int(line)) as state, origin() as target:
                front = free_port()
                config = {"log": {"level": "warn"}, "inbounds": [
                    {"type": "socks", "listen": "127.0.0.1", "listen_port": front}], "outbounds": [
                    {"type": "vless", "server": "127.0.0.1", "server_port": tapped_port, "uuid": UUID,
                     "transport": {"type": "grpc", "service_name": SERVICE}}]}
                if tls:
                    config = client_config(root, front, tapped_port)
                with box(peer, root, config, front) as go:
                    with socket.create_connection(("127.0.0.1", front), timeout=12) as client:
                        client.sendall(b"\x05\x01\x00")
                        if exact(client, 2) != b"\x05\x00":
                            raise RuntimeError("SOCKS greeting")
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
                        reply = exact(client, 4)
                        if reply[1] or reply[3] not in (1, 4):
                            raise RuntimeError("SOCKS connect")
                        exact(client, 6 if reply[3] == 1 else 18)
                        client.sendall(PAYLOAD)
                        client.shutdown(socket.SHUT_WR)
                        if exact(client, len(PAYLOAD)) != PAYLOAD or client.recv(1):
                            raise RuntimeError("payload or EOF mismatch")
                    # Keep the peer process alive until graceful owner completion.
                    # Test cleanup must not supply EOF by terminating that peer.
                    state["fixture_exit"] = server.wait(timeout=4)
                    state["peer_alive_during_drain"] = go.poll() is None
                    if state["fixture_exit"] or not state["peer_alive_during_drain"]:
                        raise RuntimeError("fixture or reference teardown failed")
            return state
        finally:
            if server.poll() is None:
                server.terminate()
            out, err = server.communicate(timeout=5)
            (root / "fixture.log").write_bytes(out + err)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plain_fixture", type=pathlib.Path)
    parser.add_argument("tls_fixture", type=pathlib.Path)
    parser.add_argument("--standard", type=pathlib.Path, required=True)
    parser.add_argument("--epoll-only", action="store_true")
    parser.add_argument("--evidence", type=pathlib.Path)
    args = parser.parse_args()
    peer = args.standard.resolve()
    version = subprocess.run([peer, "version"], capture_output=True, text=True, check=True).stdout
    if f"Revision: {REVISION}" not in version or "with_grpc" not in version:
        raise RuntimeError("unexpected standard gRPC reference")
    evidence = {"complete": False, "expected_count": 4 if args.epoll_only else 8, "results": [],
                "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in (args.plain_fixture, args.tls_fixture, peer)}}
    with tempfile.TemporaryDirectory(prefix="nexus-grpc-close-") as directory:
        for tls in (False, True):
            for backend in ((0,) if args.epoll_only else (0, 1)):
                for iteration in range(2):
                    root = pathlib.Path(directory) / f"{tls}-{backend}-{iteration}"
                    root.mkdir()
                    if tls:
                        certificates(root)
                    binary = (args.tls_fixture if tls else args.plain_fixture).resolve()
                    started = time.monotonic()
                    row = {"tls": tls, "backend": backend, "iteration": iteration}
                    try:
                        row.update(exercise(binary, peer, root, backend, tls))
                        row["pass"] = True
                    finally:
                        row["seconds"] = time.monotonic() - started
                        evidence["results"].append(row)
                        if args.evidence:
                            args.evidence.write_text(json.dumps(evidence, indent=2) + "\n")
                    print(f"gRPC paced complete response and graceful EOF: TLS={tls}, backend={backend}, iteration={iteration}", flush=True)
    evidence["complete"] = True
    if args.evidence:
        args.evidence.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
