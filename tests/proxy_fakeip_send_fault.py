"""Inject an EIO before/after UDP delivery and check conservative FakeIP reuse."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
source = pathlib.Path(__file__).with_name("proxy_fakeip_send_fault.c")
query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01"


def command(process, line):
    process.stdin.write(line + "\n"); process.stdin.flush()
    return process.stdout.readline().strip()


def exact(sock, count):
    result = b""
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        result += chunk
    return result


with tempfile.TemporaryDirectory(prefix="nexus-fakeip-send-fault-") as path:
    root = pathlib.Path(path)
    injector = root / "fault.so"
    subprocess.run(["cc", "-shared", "-fPIC", source, "-o", injector], check=True)
    for workers in (1, 2):
        for mode in ("before", "delivered"):
            directory = root / f"{workers}-{mode}"
            directory.mkdir(mode=0o700)
            for name, size in (("instance.id", 16), ("history.key", 32)):
                (directory / name).write_bytes(bytes(range(size)))
                (directory / name).chmod(0o600)
            env = os.environ.copy()
            env.update(LD_PRELOAD=str(injector), NEXUS_FAKEIP_SEND_FAULT=mode)
            args = [str(binary), str(directory), "9", str(workers), "new", "old"]
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=env)
            active = None
            target = socket.socket()
            target.bind(("127.0.0.1", 0)); target.listen(1); target.settimeout(3)
            peer = None
            try:
                proxy_line = process.stdout.readline().strip()
                if not proxy_line.isdigit():
                    raise RuntimeError("fixture startup failed")
                proxy_port = int(proxy_line)
                active = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
                active.settimeout(3)
                active.sendall(b"\x05\x01\x00")
                if exact(active, 2) != b"\x05\x00":
                    raise RuntimeError("SOCKS session setup failed")
                active.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.getsockname()[1].to_bytes(2, "big"))
                if exact(active, 10)[:2] != b"\x05\x00":
                    raise RuntimeError("SOCKS relay setup failed")
                peer, _ = target.accept(); peer.settimeout(3)
                active.sendall(b"ping")
                if exact(peer, 4) != b"ping":
                    raise RuntimeError("SOCKS relay was not active")
                dns_port = int(command(process, "dns-port"))
                time.sleep(2.1)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(0.3)
                    client.sendto(query, ("127.0.0.1", dns_port))
                    try:
                        data, dns_peer = client.recvfrom(512)
                    except TimeoutError:
                        data = None
                    if mode == "delivered":
                        if not data or dns_peer != ("127.0.0.1", dns_port) or data[-4:] != b"\xc6\x12\x00\x01":
                            raise RuntimeError("expected response was not delivered before EIO")
                    elif data is not None:
                        raise RuntimeError("response unexpectedly delivered before EIO")
                if command(process, "other") != "full":
                    raise RuntimeError("failed send allowed premature address reuse")
                deadline = time.monotonic() + 3
                while command(process, "proxy-status") != "stopped":
                    if time.monotonic() >= deadline:
                        raise RuntimeError("DNS failure did not stop the proxy")
                    time.sleep(0.01)
                if active.recv(1):
                    raise RuntimeError("active proxy session was not drained")
                if peer.recv(1):
                    raise RuntimeError("upstream proxy session was not drained")
                try:
                    connection = socket.create_connection(("127.0.0.1", proxy_port), timeout=1)
                except OSError:
                    pass
                else:
                    connection.close()
                    raise RuntimeError("proxy still accepts after DNS failure")
                contender = subprocess.run([binary, directory, "9", str(workers), "existing", "old"],
                                           capture_output=True, timeout=5)
                if contender.returncode != 3:
                    raise RuntimeError("failed DNS listener released owner lock")
                time.sleep(1.1)
                if command(process, "other") != "free":
                    raise RuntimeError("address did not become reusable after protection period")
                process.stdin.write("stop\n"); process.stdin.flush()
                stdout, stderr = process.communicate(timeout=5)
                if process.returncode != 9 or "nexus injected DNS send EIO" not in stderr:
                    raise RuntimeError(f"send failure not observed: {stdout!r}, {stderr!r}")
            finally:
                if active is not None:
                    active.close()
                if peer is not None:
                    peer.close()
                target.close()
                if process.poll() is None:
                    process.kill(); process.wait()
print("FakeIP DNS send EIO retains protection and owner lock")
