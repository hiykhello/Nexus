"""Exercise proxy EDNS against a separate local dnsmasq over UDP and TCP."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
guard = pathlib.Path(sys.argv[2]).resolve()


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def reserve(kind):
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(("127.0.0.1", 0))
    return sock


with tempfile.TemporaryDirectory(prefix="nexus-edns-dnsmasq-") as directory:
    with reserve(socket.SOCK_DGRAM) as sock:
        dns_port = sock.getsockname()[1]
    dns = subprocess.Popen([
        "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--no-resolv", "--no-hosts",
        "--listen-address=127.0.0.1", "--bind-interfaces", f"--port={dns_port}",
        f"--pid-file={directory}/dnsmasq.pid", "--local=/nexus.test/",
        "--host-record=target.nexus.test,127.0.0.1,60",
        "--cname=alias.nexus.test,target.nexus.test,30",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if dns.poll() is not None:
                raise RuntimeError(dns.stderr.read().decode())
            probe = subprocess.run(["dig", "@127.0.0.1", "-p", str(dns_port), "+time=1", "+tries=1",
                                    "+edns=0", "+short", "target.nexus.test", "A"], capture_output=True, text=True)
            if probe.returncode == 0 and "127.0.0.1" in probe.stdout:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("dnsmasq failed to become ready")
        with reserve(socket.SOCK_STREAM) as target:
            target.listen(4)
            target.settimeout(3)
            for transport in ("udp", "tcp"):
                with reserve(socket.SOCK_STREAM) as probe:
                    proxy_port = probe.getsockname()[1]
                config = pathlib.Path(directory) / "proxy.kdl"
                config.write_text(f'''schema-version 1
role "client"
dns {{ server "upstream" type="{transport}" host="127.0.0.1" port={dns_port}; strategy "ipv4_only"; edns #true; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={proxy_port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
                env = os.environ.copy()
                env["LD_PRELOAD"] = str(guard)
                proxy = subprocess.Popen([binary, "run", "--config", config], env=env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        if proxy.poll() is not None:
                            raise RuntimeError(f"proxy exited: {proxy.stderr.read()!r}")
                        try:
                            client = socket.create_connection(("127.0.0.1", proxy_port), timeout=1)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.02)
                    with client:
                        client.settimeout(3)
                        client.sendall(b"\x05\x01\x00")
                        assert exact(client, 2) == b"\x05\x00"
                        name = b"alias.nexus.test"
                        client.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target.getsockname()[1].to_bytes(2, "big"))
                        assert exact(client, 10)[:4] == b"\x05\x00\x00\x01"
                        with target.accept()[0] as connection:
                            connection.sendall(b"ok")
                            assert exact(client, 2) == b"ok"
                finally:
                    proxy.terminate()
                    proxy.wait(timeout=5)
                    stderr = proxy.stderr.read()
                    if proxy.returncode or b"unexpected-system-resolver" in stderr:
                        raise RuntimeError(f"proxy exit {proxy.returncode}: {stderr!r}")
    finally:
        dns.terminate()
        dns.wait(timeout=5)
print("proxy EDNS dnsmasq UDP/TCP CNAME interoperability passed")
