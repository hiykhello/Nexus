"""Exercise FakeIP translation through VLESS/TLS and SS-2022 TCP inbounds."""
import base64
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def run(root, mode, workers, scenario="success"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as target:
        dns.bind(("127.0.0.1", 0)); dns.settimeout(5)
        target.bind(("127.0.0.1", 0)); target.listen(1); target.settimeout(5)
        errors = []
        received = threading.Event()
        release = threading.Event()
        def answer():
            try:
                query, peer = dns.recvfrom(512)
                received.set()
                if query[12:].lower() != b"\x07example\x04test\x00\x00\x01\x00\x01":
                    raise RuntimeError("unexpected DNS query")
                if scenario == "block":
                    raise RuntimeError("blocked domain reached DNS")
                if scenario == "stop" and not release.wait(5):
                    raise RuntimeError("pending DNS was not released")
                reply = bytearray(query); reply[2:4] = b"\x81\x80"; reply[7] = 2
                record = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04"
                reply.extend(record + b"\xc6\x12\x00\x01" + record + b"\x7f\x00\x00\x01")
                dns.sendto(reply, peer)
            except TimeoutError as exc:
                if scenario != "block": errors.append(exc)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=answer); thread.start()
        args = [str(binary), str(dns.getsockname()[1]), str(workers), mode]
        if mode == "vless": args += [str(root / "cert.der"), str(root / "key.der"), str(root / "uuid")]
        if scenario == "block": args.append("block")
        proxy = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        box = None
        try:
            port = int(proxy.stdout.readline())
            if mode == "vless":
                context = ssl.create_default_context(cafile=str(root / "cert.pem"))
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                client = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="localhost")
                client.settimeout(5)
                client.sendall(b"\x00" + bytes(range(16)) + b"\x00\x01" + target.getsockname()[1].to_bytes(2, "big") + b"\x01\xc6\x12\x00\x01")
            else:
                with socket.socket() as reserve:
                    reserve.bind(("127.0.0.1", 0)); socks_port = reserve.getsockname()[1]
                config = {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                          "outbounds": [{"type": "shadowsocks", "tag": "ss", "server": "127.0.0.1", "server_port": port,
                                         "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(bytes(range(16))).decode()}],
                          "route": {"final": "ss"}}
                path = root / "ss.json"; path.write_text(json.dumps(config))
                subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
                box = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                deadline = time.monotonic() + 5
                while True:
                    if box.poll() is not None: raise RuntimeError(box.stderr.read().decode())
                    try:
                        client = socket.create_connection(("127.0.0.1", socks_port), timeout=.2); break
                    except OSError:
                        if time.monotonic() >= deadline: raise
                        time.sleep(.02)
                client.settimeout(5); client.sendall(b"\x05\x01\x00")
                if exact(client, 2) != b"\x05\x00": raise RuntimeError("SOCKS greeting failed")
                client.sendall(b"\x05\x01\x00\x01\xc6\x12\x00\x01" + target.getsockname()[1].to_bytes(2, "big"))
                if exact(client, 10)[:2] != b"\x05\x00": raise RuntimeError("SOCKS request failed")
            if scenario != "success":
                with client:
                    if scenario == "stop":
                        if not received.wait(5): raise RuntimeError("DNS query did not start")
                        time.sleep(1.2)
                        proxy.stdin.write("probe\n"); proxy.stdin.flush()
                        if proxy.stdout.readline().strip() != "full": raise RuntimeError("pending DNS did not pin FakeIP")
                        proxy.stdin.write("halt\n"); proxy.stdin.flush()
                        if proxy.stdout.readline().strip() != "halted": raise RuntimeError("stop did not drain")
                        release.set(); thread.join(timeout=5)
                    try:
                        if client.recv(1): raise RuntimeError("unexpected data after rejection or stop")
                    except (ConnectionResetError, ssl.SSLError):
                        pass
                    if scenario == "block":
                        time.sleep(1.2)
                    proxy.stdin.write("probe\n"); proxy.stdin.flush()
                    if proxy.stdout.readline().strip() != "free": raise RuntimeError("connection pin was not released")
                    target.settimeout(.5)
                    try:
                        accepted, _ = target.accept()
                    except TimeoutError:
                        pass
                    else:
                        accepted.close(); raise RuntimeError("rejected or stopped request reached target")
                proxy.stdin.write("stop\n"); proxy.stdin.flush()
                if proxy.wait(timeout=5): raise RuntimeError("fixture failed")
                return
            with client, target.accept()[0] as peer:
                peer.settimeout(5)
                if mode == "vless" and exact(client, 2) != b"\x00\x00": raise RuntimeError("VLESS response failed")
                client.sendall(b"ping")
                if exact(peer, 4) != b"ping": raise RuntimeError("upload failed")
                peer.sendall(b"pong")
                if exact(client, 4) != b"pong": raise RuntimeError("download failed")
                time.sleep(1.2)
                proxy.stdin.write("blocked\nprobe\n"); proxy.stdin.flush()
                if int(proxy.stdout.readline()) < 1 or proxy.stdout.readline().strip() != "full":
                    raise RuntimeError("candidate filtering or connection pin failed")
            deadline = time.monotonic() + 4
            while True:
                proxy.stdin.write("probe\n"); proxy.stdin.flush()
                result = proxy.stdout.readline().strip()
                if result == "free": break
                if result != "full" or time.monotonic() >= deadline: raise RuntimeError(f"pin not released: {result}")
                time.sleep(.05)
            proxy.stdin.write("stop\n"); proxy.stdin.flush()
            if proxy.wait(timeout=5): raise RuntimeError("fixture failed")
        finally:
            release.set()
            if box is not None:
                box.terminate(); box.wait(timeout=5)
            if proxy.poll() is None: proxy.kill(); proxy.wait()
            thread.join(timeout=6)
            if errors or thread.is_alive(): raise RuntimeError(f"DNS peer failed: {errors}")


with tempfile.TemporaryDirectory(prefix="nexus-fakeip-inbounds-") as directory:
    root = pathlib.Path(directory)
    def openssl(*args): subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=10)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key.pem", "-out", root / "cert.pem",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1")
    openssl("pkey", "-in", root / "key.pem", "-outform", "DER", "-out", root / "key.der")
    openssl("x509", "-in", root / "cert.pem", "-outform", "DER", "-out", root / "cert.der")
    (root / "key.der").chmod(0o600)
    (root / "uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); (root / "uuid").chmod(0o600)
    for mode in ("vless", "ss"):
        for workers in (1, 2):
            for scenario in ("success", "block", "stop"): run(root, mode, workers, scenario)
print("VLESS/TLS and SS-2022 FakeIP routing, blocking, cancellation and pin lifecycle passed")
