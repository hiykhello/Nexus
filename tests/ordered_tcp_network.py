import socket
import subprocess
import sys
import threading


def exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise AssertionError("unexpected EOF")
        data += part
    return data


def headers(sock):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += exact(sock, 1)
    return data


def main():
    peer = socket.socket()
    peer.bind(("127.0.0.1", 0))
    peer.listen(2)
    peer.settimeout(5)
    port = peer.getsockname()[1]
    errors = []

    def serve():
        try:
            for expected in (b"hello", b"GET / HTTP/1.1\r\nHost: ok.example\r\n\r\nbody"):
                conn, _ = peer.accept()
                with conn:
                    conn.settimeout(5)
                    assert exact(conn, len(expected)) == expected
                    conn.sendall(b"OK")
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve)
    thread.start()
    proc = subprocess.Popen([sys.argv[1]], stdout=subprocess.PIPE, text=True)
    try:
        proxy_port = int(proc.stdout.readline())
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
            sock.sendall(b"\x05\x01\x00")
            assert exact(sock, 2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2, "big"))
            reply = exact(sock, 4)
            assert reply[:2] == b"\x05\x00"
            exact(sock, 6 if reply[3] == 1 else 18)
            sock.sendall(b"hello")
            assert exact(sock, 2) == b"OK"
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
            payload = b"GET / HTTP/1.1\r\nHost: ok.example\r\n\r\nbody"
            sock.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode() + payload)
            assert headers(sock).startswith(b"HTTP/1.1 200 ")
            assert exact(sock, 2) == b"OK"
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
            sock.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode() + b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            assert headers(sock).startswith(b"HTTP/1.1 403 ")
        thread.join(5)
        assert not thread.is_alive() and not errors, errors
        print("ordered SOCKS timeout fallback, CONNECT prefetch and reject passed")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        peer.close()
        thread.join(5)


if __name__ == "__main__":
    main()
