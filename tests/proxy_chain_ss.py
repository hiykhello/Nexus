#!/usr/bin/env python3
"""Exercise two and three SS-2022 hops through the actual tunnel stream adapter."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time


def main():
    binary = pathlib.Path(sys.argv[1]).resolve()
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    reservations = [socket.socket() for _ in range(3)]
    for sock in reservations:
        sock.bind(("127.0.0.1", 0))
    ports = [sock.getsockname()[1] for sock in reservations]
    for sock in reservations:
        sock.close()
    password = base64.b64encode(bytes(range(16))).decode()
    config = {"log": {"level": "warn"}, "inbounds": [
        {"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
         "method": "2022-blake3-aes-128-gcm", "password": password} for port in ports],
        "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
    with tempfile.TemporaryDirectory(prefix="nexus-chain-ss-") as directory:
        path = pathlib.Path(directory) / "server.json"
        path.write_text(json.dumps(config))
        subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
        process = subprocess.Popen(["sing-box", "run", "-c", path], stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                try:
                    with socket.create_connection(("127.0.0.1", ports[0]), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.02)
            for hops, backend, mode in ((hops, backend, mode) for hops in (2, 3) for backend in ("epoll", "uring") for mode in ("reply", "timeout", "large", "uot", "cancel")):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if mode == "uot" else socket.SOCK_STREAM) as listener:
                    listener.bind(("127.0.0.1", 0)); listener.settimeout(10)
                    if mode != "uot": listener.listen(1)
                    errors = []
                    def peer():
                        try:
                            if mode == "uot":
                                data, address = listener.recvfrom(65535)
                                if data != b"probe": raise RuntimeError("UDP payload mismatch")
                                listener.sendto(b"good", address)
                                return
                            with listener.accept()[0] as conn:
                                conn.settimeout(8); data = bytearray()
                                expected = bytes(range(256)) * 1024 if mode == "large" else b"helloagain"
                                while len(data) < len(expected):
                                    block = conn.recv(min(65536, len(expected) - len(data)))
                                    if not block:
                                        raise RuntimeError("upload truncated")
                                    data.extend(block)
                                if data != expected or conn.recv(1):
                                    raise RuntimeError("upload or half-close mismatch")
                                if mode in ("timeout", "cancel"):
                                    time.sleep(.6)
                                else:
                                    conn.sendall(expected if mode == "large" else b"worldagain"); conn.shutdown(socket.SHUT_WR)
                        except Exception as error:
                            errors.append(error)
                    thread = threading.Thread(target=peer); thread.start()
                    result = subprocess.run([binary, *(str(port) for port in ports[:hops]), str(listener.getsockname()[1]), backend, mode], timeout=12)
                    thread.join(10)
                    if result.returncode or thread.is_alive() or errors:
                        raise RuntimeError(f"{hops} hops {backend} {mode}: exit={result.returncode}, peer={errors}")
                    print(f"{hops} SS hops {backend}: {mode} passed")
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate()


if __name__ == "__main__":
    main()
