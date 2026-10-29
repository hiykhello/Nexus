"""Exercise context destruction while both real VLESS relay directions wait for input."""
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    user = root / "user.uuid"
    user.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
    user.chmod(0o600)
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(10)
        proc = subprocess.Popen([binary, cert, key, user], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            port = int(proc.stdout.readline())
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_ecdh_curve("X25519")
            with context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname="localhost") as client:
                client.settimeout(10)
                target_port = origin.getsockname()[1]
                request = bytes([0]) + bytes(range(16)) + bytes([0, 1]) + target_port.to_bytes(2, "big") + bytes([1, 127, 0, 0, 1])
                client.sendall(request)
                with origin.accept()[0]:
                    response = b""
                    while len(response) < 2:
                        part = client.recv(2-len(response))
                        if not part:
                            raise RuntimeError("missing VLESS response")
                        response += part
                    if response != b"\x00\x00":
                        raise RuntimeError(f"unexpected VLESS response {response!r}")
                    out, err = proc.communicate(timeout=15)
                    if proc.returncode:
                        raise RuntimeError(f"fixture exit {proc.returncode}: {out} {err}")
                    print(out.strip())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
