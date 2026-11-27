"""Exercise local bootstrap search through the real DNS message listener."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

binary = Path(sys.argv[1]).resolve()
if len(sys.argv) == 2:
    subprocess.run(["unshare", "-Urnm", sys.executable, __file__, str(binary), "inside"], check=True)
    sys.exit(0)
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
subprocess.run(["mount", "--make-rprivate", "/"], check=True)


def name_and_type(wire):
    pos = 12
    labels = []
    while wire[pos]:
        size = wire[pos]
        pos += 1
        labels.append(wire[pos:pos + size].decode())
        pos += size
    return ".".join(labels), struct.unpack_from("!H", wire, pos + 1)[0]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


with tempfile.TemporaryDirectory(prefix="nexus-bootstrap-search-") as directory:
    root = Path(directory)
    resolv, hosts = root / "resolv", root / "hosts"
    resolv.write_text("nameserver 127.0.0.2\nsearch first.test second.test\noptions ndots:1 timeout:1 attempts:1\n")
    hosts.write_text("")
    for source, target in ((resolv, "/etc/resolv.conf"), (hosts, "/etc/hosts")):
        subprocess.run(["mount", "--bind", str(source), target], check=True)
    bootstrap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bootstrap.bind(("127.0.0.2", 53))
    remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    remote.bind(("127.0.0.1", 0))
    for sock in (bootstrap, remote):
        sock.settimeout(.2)
    stop = threading.Event()
    observed = []
    failures = []

    def serve(sock, local):
        try:
            while not stop.is_set():
                try:
                    request, peer = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                name, qtype = name_and_type(request)
                answer = bytearray(request)
                answer[2:4] = b"\x81\x80"
                if local:
                    observed.append((name, qtype))
                    if name == "resolver.first.test":
                        answer[3] = 0x83
                    elif name == "nodata.first.test":
                        answer[9] = 1
                        answer.extend(bytes.fromhex("c00c000600010000003c00160000" + "00000001" * 5))
                    elif name == "failure.first.test":
                        answer[3] = 0x82
                    else:
                        assert name in ("resolver.second.test", "nodata.second.test", "resolver"), name
                        answer[7] = 1
                        if qtype == 1:
                            answer.extend(bytes.fromhex("c00c000100010000003c00047f000001"))
                        else:
                            answer.extend(bytes.fromhex("c00c001c00010000003c001000000000000000000000000000000001"))
                else:
                    answer[7] = 1
                    answer.extend(bytes.fromhex("c00c000100010000003c0004c0000201"))
                sock.sendto(answer, peer)
        except Exception as error:
            failures.append(error)

    threads = [threading.Thread(target=serve, args=(sock, local)) for sock, local in ((bootstrap, True), (remote, False))]
    for thread in threads:
        thread.start()
    try:
        for hostname, expected, successful in (("resolver", [("resolver.first.test", 1), ("resolver.second.test", 1), ("resolver.second.test", 28)], True),
                                               ("nodata", [("nodata.first.test", 1), ("nodata.first.test", 28), ("nodata.second.test", 1), ("nodata.second.test", 28)], True),
                                               ("failure", [("failure.first.test", 1)], False),
                                               ("resolver.", [("resolver", 1), ("resolver", 28)], True)):
            observed.clear()
            listen, proxy = port(), port()
            while proxy == listen:
                proxy = port()
            config = root / "config.kdl"
            config.write_text(f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={listen}; server "local" type="local"; server "remote" type="udp" host="{hostname}" port={remote.getsockname()[1]} domain-resolver="local"; final "remote"; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
            process = subprocess.Popen([str(binary), "run", "--config", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(80):
                    if process.poll() is not None:
                        raise RuntimeError(process.stderr.read().decode())
                    try:
                        with socket.create_connection(("127.0.0.1", listen), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("DNS listener failed to start")
                request = struct.pack("!HHHHHH", 123, 0x0100, 1, 0, 0, 0) + b"\x05query\x04test\0\0\1\0\1"
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(5)
                    client.sendto(request, ("127.0.0.1", listen))
                    answer, _ = client.recvfrom(4096)
                assert answer[:2] == request[:2], answer.hex()
                if successful:
                    assert answer[-4:] == bytes([192, 0, 2, 1]), answer.hex()
                else:
                    assert answer[3] & 15 == 2, answer.hex()
                assert observed == expected, observed
            finally:
                process.terminate()
                _, err = process.communicate(timeout=5)
                if process.returncode:
                    raise RuntimeError(err.decode())
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=3)
        bootstrap.close()
        remote.close()
    assert not failures and all(not thread.is_alive() for thread in threads), failures
print("DNS local bootstrap NXDOMAIN/NODATA search, server failure and absolute name passed")
