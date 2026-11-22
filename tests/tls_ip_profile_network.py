"""Check IP SAN verification through the production TLS profile."""
import argparse
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("tls_profile", type=pathlib.Path)
parser.add_argument("--vless-profile", type=pathlib.Path)
args = parser.parse_args()
binary = args.tls_profile.resolve(strict=True)

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

with tempfile.TemporaryDirectory(prefix="nexus-tls-ip-") as directory:
    root = pathlib.Path(directory)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "ca.key"),
        "-out", str(root / "ca.pem"), "-days", "1", "-subj", "/CN=IP CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"), "-subj", "/CN=server.example")
    (root / "ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,IP:::1,DNS:server.example\n")
    run("openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "ca.pem"),
        "-CAkey", str(root / "ca.key"), "-set_serial", "2", "-days", "1", "-extfile", str(root / "ext"),
        "-out", str(root / "server.pem"))
    if args.vless_profile:
        vless = args.vless_profile.resolve(strict=True)
        (root / "uuid").write_text("00000000-0000-4000-8000-000000000001\n")
        (root / "uuid").chmod(0o600)
        run(str(vless), "--vless-host", str(root / "uuid"), str(root / "ca.pem"))
        print("VLESS IPv6 default and explicit HTTPUpgrade Host passed", flush=True)
    for profile in ("native", "fingerprint"):
        for name, expected in (("127.0.0.1", "accept"), ("127.0.0.2", "reject"), ("::1", "accept"), ("::2", "reject")):
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
            server = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-tls1_3",
                "-cert", str(root / "server.pem"), "-key", str(root / "server.key"), "-quiet"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            client = None
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        peer = socket.create_connection(("127.0.0.1", port), timeout=5); break
                    except ConnectionRefusedError:
                        if server.poll() is not None or time.monotonic() >= deadline: raise
                        time.sleep(.02)
                left, right = socket.socketpair()
                client = subprocess.Popen([str(binary), name, str(root / "ca.pem"), profile, expected],
                    stdin=right, stdout=right, stderr=subprocess.PIPE)
                right.close()
                def copy(source, destination):
                    try:
                        while data := source.recv(65536): destination.sendall(data)
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                threads = [threading.Thread(target=copy, args=(left, peer)), threading.Thread(target=copy, args=(peer, left))]
                for thread in threads: thread.start()
                _, errors = client.communicate(timeout=15)
                for sock in (left, peer):
                    try: sock.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    sock.close()
                for thread in threads: thread.join(2)
                if client.returncode: raise RuntimeError(f"{profile} {name} {expected}: {client.returncode}: {errors.decode()}")
                print(profile, name, expected, "passed", flush=True)
            finally:
                if client and client.poll() is None: client.kill(); client.communicate()
                server.terminate()
                try: server.communicate(timeout=2)
                except subprocess.TimeoutExpired: server.kill(); server.communicate()
