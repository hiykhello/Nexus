#!/usr/bin/env python3
"""Exercise the isolated MASQUE fixture over loopback and a real UDP echo."""
import argparse
import selectors
import socket
import subprocess
import threading


def run(binary, certificate, key, family, mode):
    af = socket.AF_INET6 if family == "6" else socket.AF_INET
    host = "::1" if family == "6" else "127.0.0.1"
    echo = socket.socket(af, socket.SOCK_DGRAM)
    echo.bind((host, 0))
    echo.settimeout(0.2)
    stopped = threading.Event()
    replies = []

    def serve():
        while not stopped.is_set():
            try:
                data, peer = echo.recvfrom(65535)
                echo.sendto(data, peer)
                replies.append(data)
            except TimeoutError:
                continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    server = subprocess.Popen([binary, "server", family, "0", str(echo.getsockname()[1]), certificate, key, "0x0403", mode], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        selector = selectors.DefaultSelector()
        selector.register(server.stdout, selectors.EVENT_READ)
        if not selector.select(10):
            raise RuntimeError("server did not become ready")
        line = server.stdout.readline().strip()
        if not line.startswith("READY "):
            raise RuntimeError(f"server startup: {line}")
        port = int(line.split()[1])
        client = subprocess.run([binary, "client", family, str(port), str(echo.getsockname()[1]), certificate, key, "0x0403", mode], capture_output=True, text=True, timeout=15)
        output, _ = server.communicate(timeout=15)
        print(f"IPv{family} {mode} client rc={client.returncode}: {client.stdout.strip()} {client.stderr.strip()}")
        print(f"IPv{family} {mode} server rc={server.returncode}: {output.strip()}")
        if client.returncode or server.returncode or replies != [bytes([11, 22, 33])]:
            raise RuntimeError(f"IPv{family} failed; echo={replies!r}")
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()
        stopped.set()
        thread.join(timeout=2)
        echo.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("certificate")
    parser.add_argument("key")
    parser.add_argument("--family", choices=("4", "6", "both"), default="both")
    args = parser.parse_args()
    for family in ("4", "6") if args.family == "both" else (args.family,):
        for mode in ("datagram", "capsule"):
            run(args.binary, args.certificate, args.key, family, mode)


if __name__ == "__main__":
    main()
