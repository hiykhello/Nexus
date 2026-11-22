"""Reality TLS and VLESS against pinned sing-box or Xray and a local origin."""
from test_paths import optional_fixture, optional_nexus
import argparse
import base64
import concurrent.futures
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = optional_fixture("reality-client-fixture")
NEXUS = optional_nexus()
REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nexus", type=pathlib.Path, default=NEXUS, required=NEXUS is None, help="Nexus server executable")
    parser.add_argument("--fixture", type=pathlib.Path, default=FIXTURE, required=FIXTURE is None, help="Reality client fixture executable")
    parser.add_argument("--xray", help="path to Xray built from v1.260327.0")
    parser.add_argument("--trace-eof", action="store_true", help="print relative timing of the concurrent EOF experiment")
    parser.add_argument("--xray-downlink-timeout", type=int, help="override Xray server level-0 downlink-only timeout in seconds")
    parser.add_argument("--xray-client", action="store_true", help="use Xray rather than Nexus for the SOCKS client comparison; requires --xray")
    parser.add_argument("--deferred-response", action="store_true", help="have origin wait for client EOF before responding (default for sing-box)")
    parser.add_argument("--hybrid", action="store_true", help="use X25519MLKEM768 for the Nexus outbound")
    parser.add_argument("--hybrid-only", action="store_true", help="require X25519MLKEM768 for the Nexus outbound")
    args = parser.parse_args()
    if args.xray_downlink_timeout is not None and (not args.xray or args.xray_downlink_timeout < 1):
        parser.error("--xray-downlink-timeout requires --xray and a positive value")
    if args.xray_client and not args.xray:
        parser.error("--xray-client requires --xray")
    deferred = not args.xray or args.deferred_response
    if args.xray:
        version = subprocess.run(["go", "version", "-m", args.xray], capture_output=True, text=True, check=True).stdout
        if "\tmod\tgithub.com/xtls/xray-core\tv1.260327.0\th1:g4TzxMwyPrxslZh6uD+FiG3lXKTrnNO+b4ky2OhogHE=" not in version:
            raise RuntimeError("Xray module version or checksum differs from the pinned fixture")
        keys = subprocess.run([args.xray, "x25519"], capture_output=True, text=True, check=True).stdout
        values = dict(line.split(": ", 1) for line in keys.splitlines() if ": " in line)
        public_key = values["Password (PublicKey)"]
    else:
        version = subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout
        if f"Revision: {REVISION}" not in version:
            raise RuntimeError("sing-box revision differs from the pinned fixture")
        keys = subprocess.run(["sing-box", "generate", "reality-keypair"], capture_output=True, text=True, check=True).stdout
        values = dict(line.split(": ", 1) for line in keys.splitlines() if ": " in line)
        public_key = values["PublicKey"]
    public = base64.urlsafe_b64decode(public_key + "=")
    with tempfile.TemporaryDirectory(prefix="nexus-reality-") as directory:
        path = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(path / "key"),
                        "-out", str(path / "cert"), "-subj", "/CN=cover.example", "-days", "1"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        backend, front = free_port(), free_port()
        while front == backend:
            front = free_port()
        cover = subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", str(backend), "-cert", str(path / "cert"),
                                  "-key", str(path / "key")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        config = {"log": {"level": "error"}, "inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": front,
                  "users": [{"uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f"}],
                  "tls": {"enabled": True, "server_name": "cover.example", "reality": {"enabled": True,
                  "handshake": {"server": "127.0.0.1", "server_port": backend}, "private_key": values["PrivateKey"],
                  "short_id": ["0123456789abcdef"]}}}], "outbounds": [{"type": "direct"}]}
        if args.xray:
            config = {"log": {"loglevel": "error"}, "inbounds": [{"listen": "127.0.0.1", "port": front,
                      "protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f"}]},
                      "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                      "target": f"127.0.0.1:{backend}", "serverNames": ["cover.example"],
                      "privateKey": values["PrivateKey"], "shortIds": ["0123456789abcdef"]}}}],
                      "outbounds": [{"protocol": "freedom"}]}
        if args.xray_downlink_timeout is not None:
            config["policy"] = {"levels": {"0": {"downlinkOnly": args.xray_downlink_timeout}}}
        (path / "config.json").write_text(json.dumps(config))
        server = None
        origin = socket.socket()
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(15)
        origin_port = origin.getsockname()[1]
        origin_result = []
        def serve_origin():
            try:
                conn, _ = origin.accept()
                with conn:
                    conn.settimeout(10)
                    data = b""
                    while len(data) < len(b"Reality VLESS bidirectional payload"):
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    origin_result.append(data)
                    conn.sendall(data)
            except Exception as exc:
                origin_result.append(exc)
        worker = threading.Thread(target=serve_origin, daemon=True)
        worker.start()
        try:
            check_command = [args.xray, "run", "-test", "-config", str(path / "config.json")] if args.xray else ["sing-box", "check", "-c", str(path / "config.json")]
            run_command = [args.xray, "run", "-config", str(path / "config.json")] if args.xray else ["sing-box", "run", "-c", str(path / "config.json")]
            subprocess.run(check_command, check=True, capture_output=True)
            server = subprocess.Popen(run_command,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(0.5)
            if server.poll() is not None or cover.poll() is not None:
                raise RuntimeError("fixture server exited during startup")
            for key, short_id, expected in [(public, "0123456789abcdef", {0})]:
                result = subprocess.run([args.fixture, str(front), key.hex(), "cover.example", str(origin_port), short_id], capture_output=True, timeout=15)
                if result.returncode not in expected:
                    raise RuntimeError(f"Reality fixture returned {result.returncode}, expected {expected}: {result.stderr!r}")
            worker.join(timeout=15)
            if worker.is_alive() or origin_result != [b"Reality VLESS bidirectional payload"]:
                raise RuntimeError(f"origin failed: {origin_result!r}")
            proxy_origin = socket.socket()
            proxy_origin.bind(("127.0.0.1", 0))
            proxy_origin.listen(16)
            proxy_origin.settimeout(10)
            proxy_port = free_port()
            (path / "uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f")
            (path / "uuid").chmod(0o600)
            (path / "nexus.kdl").write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={proxy_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
 server host="127.0.0.1" port={front}
 authentication {{ uuid-file "{path / 'uuid'}"; }}
 tls {{ server-name "cover.example"; {'key-exchange "x25519-mlkem768-only";' if args.hybrid_only else 'key-exchange "x25519-mlkem768";' if args.hybrid else ''} reality {{ public-key "{public.hex()}"; short-id "0123456789abcdef"; }}; }}
}}
routing {{ default-outbound "edge"; }}
''')
            if args.xray_client:
                client_config = {"log": {"loglevel": "error"},
                    "inbounds": [{"listen": "127.0.0.1", "port": proxy_port, "protocol": "socks", "settings": {"auth": "noauth"}}],
                    "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": front,
                        "users": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none"}]}]},
                        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                        "fingerprint": "chrome", "serverName": "cover.example", "password": public_key,
                        "shortId": "0123456789abcdef"}}}]}
                (path / "xray-client.json").write_text(json.dumps(client_config))
                subprocess.run([args.xray, "run", "-test", "-config", str(path / "xray-client.json")], check=True, capture_output=True)
                client_command = [args.xray, "run", "-config", str(path / "xray-client.json")]
            else:
                client_command = [args.nexus, "run", "--config", path / "nexus.kdl"]
            process = subprocess.Popen(client_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"Nexus exited: {process.stderr.read()!r}")
                    try:
                        client = socket.create_connection(("127.0.0.1", proxy_port), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
                with client:
                    client.settimeout(10)
                    def exact(count):
                        data = b""
                        while len(data) < count:
                            part = client.recv(count-len(data))
                            if not part:
                                raise RuntimeError("SOCKS connection closed")
                            data += part
                        return data
                    client.sendall(b"\x05\x01\x00")
                    if exact(2) != b"\x05\x00": raise RuntimeError("SOCKS authentication failed")
                    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + proxy_origin.getsockname()[1].to_bytes(2, "big"))
                    if exact(10)[:2] != b"\x05\x00": raise RuntimeError("SOCKS connect failed")
                    with proxy_origin.accept()[0] as connection:
                        connection.settimeout(10)
                        client.sendall(b"hello")
                        data = b""
                        while len(data) < 5:
                            part = connection.recv(5-len(data))
                            if not part: raise RuntimeError("origin connection closed")
                            data += part
                        if data != b"hello": raise RuntimeError("origin data mismatch")
                        connection.sendall(b"world")
                        if exact(5) != b"world": raise RuntimeError("client data mismatch")
                # Exercise independent sessions and EOF propagation through both workers.
                count = 8
                trace_start = time.monotonic()
                def trace(event):
                    if args.trace_eof:
                        print(f"{time.monotonic() - trace_start:.3f}s {event}", file=sys.stderr, flush=True)
                def echo_connection(connection):
                    with connection:
                        connection.settimeout(10)
                        data = bytearray()
                        while True:
                            part = connection.recv(4096)
                            if not part:
                                trace(f"origin EOF after {len(data)} bytes")
                                break
                            data.extend(part)
                            if not deferred:
                                connection.sendall(part)
                        if deferred:
                            connection.sendall(data)
                        connection.shutdown(socket.SHUT_WR)

                def concurrent_client(index):
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
                        sock.settimeout(10)
                        def read_exact(size):
                            result = bytearray()
                            while len(result) < size:
                                part = sock.recv(size - len(result))
                                if not part:
                                    trace(f"client {index} EOF after {len(result)} of {size} bytes")
                                    raise RuntimeError("concurrent SOCKS connection closed")
                                result.extend(part)
                            return bytes(result)
                        sock.sendall(b"\x05\x01\x00")
                        if read_exact(2) != b"\x05\x00":
                            raise RuntimeError("concurrent SOCKS authentication failed")
                        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + proxy_origin.getsockname()[1].to_bytes(2, "big"))
                        if read_exact(10)[:2] != b"\x05\x00":
                            raise RuntimeError("concurrent SOCKS connect failed")
                        payload = (f"Reality concurrent session {index}:".encode() * 512)
                        sock.sendall(payload)
                        if deferred:
                            trace(f"client {index} half-close")
                            sock.shutdown(socket.SHUT_WR)
                        if read_exact(len(payload)) != payload:
                            raise RuntimeError("concurrent payload mismatch")
                        if not deferred:
                            sock.shutdown(socket.SHUT_WR)
                        if sock.recv(1) != b"":
                            raise RuntimeError("concurrent payload or EOF mismatch")

                with concurrent.futures.ThreadPoolExecutor(max_workers=count * 2) as pool:
                    clients = [pool.submit(concurrent_client, i) for i in range(count)]
                    origins = [pool.submit(echo_connection, proxy_origin.accept()[0]) for _ in range(count)]
                    for future in clients + origins:
                        future.result(timeout=15)
            finally:
                process.terminate()
                process.communicate(timeout=5)
                proxy_origin.close()
            for key, short_id in [(bytes([public[0] ^ 1]) + public[1:], "0123456789abcdef"),
                                  (public, "1123456789abcdef")]:
                result = subprocess.run([args.fixture, str(front), key.hex(), "cover.example", str(origin_port), short_id], capture_output=True, timeout=15)
                if result.returncode not in {11, 12}:
                    raise RuntimeError(f"invalid Reality identity returned {result.returncode}: {result.stderr!r}")
            print(f"{'Xray' if args.xray_client else 'Nexus'} client to {'Xray' if args.xray else 'sing-box'} Reality VLESS bidirectional and concurrent EOF passed (deferred response: {deferred}); wrong public key and short ID rejected")
        finally:
            origin.close()
            if server:
                server.terminate()
                server.communicate(timeout=5)
            cover.terminate()
            cover.wait(timeout=5)


if __name__ == "__main__":
    main()
