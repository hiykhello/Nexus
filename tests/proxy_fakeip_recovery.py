"""Exercise restart and migration through the experimental proxy, on loopback."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def command(process, text):
    process.stdin.write(text + "\n")
    process.stdin.flush()
    return process.stdout.readline().strip()


def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def fakeip_query(port, expected):
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(query, ("127.0.0.1", port))
        reply, source = client.recvfrom(512)
    if source != ("127.0.0.1", port) or reply[:2] != query[:2] or len(reply) < 12:
        raise RuntimeError("invalid FakeIP DNS response")
    if expected is None:
        if reply[3] & 15 != 2 or reply[6:8] != b"\x00\x00":
            raise RuntimeError(f"quarantined DNS answer: {reply!r}")
    elif reply[3] & 15 or reply[6:8] != b"\x00\x01" or reply[-4:] != socket.inet_aton(expected):
        raise RuntimeError(f"incorrect FakeIP DNS answer: {reply!r}")


def socks(proxy, address, target):
    conn = socket.create_connection(("127.0.0.1", proxy), timeout=3)
    conn.settimeout(3)
    conn.sendall(b"\x05\x01\x00")
    if exact(conn, 2) != b"\x05\x00":
        raise RuntimeError("greeting failed")
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(address) + target.to_bytes(2, "big"))
    return conn, exact(conn, 10)[1]


def run(workers):
    with tempfile.TemporaryDirectory(prefix="nexus-fakeip-restart-") as path:
        root = pathlib.Path(path)
        (root / "instance.id").write_bytes(bytes(range(16)))
        (root / "history.key").write_bytes(bytes(range(32)))
        (root / "instance.id").chmod(0o600)
        (root / "history.key").chmod(0o600)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as target:
            dns.bind(("127.0.0.1", 0))
            dns.settimeout(3)
            target.bind(("127.0.0.1", 0))
            target.listen(1)
            target.settimeout(3)
            processes = []

            def start(mode, pool):
                p = subprocess.Popen([str(binary), path, str(dns.getsockname()[1]), str(workers), mode, pool],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(p)
                return p

            try:
                first = start("new", "old")
                int(first.stdout.readline())
                dns_port = int(command(first, "dns-port"))
                fakeip_query(dns_port, None)
                time.sleep(2.1)
                fakeip_query(dns_port, "198.18.0.1")
                first.kill()
                if first.wait(timeout=5) != -9:
                    raise RuntimeError("first process was not killed")
                second = start("existing", "new")
                proxy = int(second.stdout.readline())
                dns_port = int(command(second, "dns-port"))
                if command(second, "old") != "protected":
                    raise RuntimeError("migration did not retain old pool or quarantine new pool")
                fakeip_query(dns_port, None)
                conn, status = socks(proxy, "198.19.0.1", target.getsockname()[1])
                conn.close()
                if status != 2:
                    raise RuntimeError("quarantined address was not blocked")
                conn, status = socks(proxy, "198.18.0.1", target.getsockname()[1])
                conn.close()
                if status != 2:
                    raise RuntimeError("old address was not blocked")
                duplicate = start("existing", "new")
                if duplicate.wait(timeout=5) != 3:
                    raise RuntimeError("second live owner was not refused")
                time.sleep(2.1)
                fakeip_query(dns_port, "198.19.0.1")

                def serve():
                    query, peer = dns.recvfrom(512)
                    if query[12:-4].lower() != b"\x07example\x04test\x00":
                        raise RuntimeError("unexpected DNS query")
                    reply = bytearray(query); reply[2:4] = b"\x81\x80"; reply[7] = 2
                    prefix = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04"
                    reply.extend(prefix + socket.inet_aton("198.18.0.1") + prefix + socket.inet_aton("127.0.0.1"))
                    dns.sendto(reply, peer)
                    accepted, _ = target.accept()
                    with accepted:
                        if exact(accepted, 4) != b"ping":
                            raise RuntimeError("bad relay payload")
                        accepted.sendall(b"pong")

                failures = []
                def guarded():
                    try:
                        serve()
                    except Exception as error:
                        failures.append(error)

                thread = threading.Thread(target=guarded); thread.start()
                conn, status = socks(proxy, "198.19.0.1", target.getsockname()[1])
                with conn:
                    if status != 0:
                        raise RuntimeError("recovered mapping was not routed")
                    conn.sendall(b"ping")
                    if exact(conn, 4) != b"pong":
                        raise RuntimeError("recovered relay failed")
                thread.join(5)
                if thread.is_alive() or failures:
                    raise RuntimeError(f"peer failed: {failures}")
                if int(command(second, "blocked")) < 1:
                    raise RuntimeError("historical DNS candidate was not filtered")
                second.stdin.write("stop\n"); second.stdin.flush()
                if second.wait(timeout=5):
                    raise RuntimeError("second process failed")
                third = start("existing", "new")
                int(third.stdout.readline())
                if command(third, "old") != "protected":
                    raise RuntimeError("reopen lost migration history")
                fakeip_query(int(command(third, "dns-port")), None)
                third.stdin.write("stop\n"); third.stdin.flush()
                if third.wait(timeout=5):
                    raise RuntimeError("third process failed")
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill(); process.wait()


for workers in (1, 2):
    run(workers)
print("FakeIP persisted migration, quarantine and proxy relay passed")
