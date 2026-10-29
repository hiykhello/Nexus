"""Inject a receive exception while another UDP DNS query stays pending."""
import pathlib
import socket
import subprocess
import sys
import threading

binary = pathlib.Path(sys.argv[1]).resolve()
backend = sys.argv[2] if len(sys.argv) > 2 else "epoll"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("127.0.0.1", 0))
    server.settimeout(3)
    errors = []

    def reply_once():
        try:
            _, peer = server.recvfrom(4096)
            server.sendto(b"x", peer)
        except OSError as error:
            errors.append(error)

    peer = threading.Thread(target=reply_once)
    peer.start()
    try:
        subprocess.run([binary, str(server.getsockname()[1]), "exception", backend], check=True, timeout=5)
    finally:
        peer.join()
    if errors:
        raise errors[0]
