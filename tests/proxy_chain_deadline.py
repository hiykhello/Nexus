#!/usr/bin/env python3
"""Exercise the internal chain deadline through real tunnel factories."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading


def main():
    binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-chain-deadline-") as directory:
        root = pathlib.Path(directory)
        uuid = root / "uuid"
        uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
        uuid.chmod(0o600)
        key, cert = root / "key", root / "cert"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(5)
            errors = []

            def peer():
                try:
                    with listener.accept()[0] as connection:
                        connection.settimeout(5)
                        while connection.recv(4096):
                            pass
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=peer)
            thread.start()
            result = subprocess.run([binary, str(listener.getsockname()[1]), uuid, cert], timeout=8)
            thread.join(6)
            if result.returncode or thread.is_alive() or errors:
                raise RuntimeError(f"deadline fixture failed: exit={result.returncode}, peer={errors}")
    print("SS and VLESS expired deadlines and VLESS TLS deadline passed")


if __name__ == "__main__":
    main()
