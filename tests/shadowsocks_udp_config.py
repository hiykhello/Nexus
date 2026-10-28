"""Exercise configured SS-2022 UDP ownership and startup rollback."""
import base64
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile

nexus = pathlib.Path(sys.argv[1]).resolve()
client = nexus.with_name("nexus-shadowsocks-udp-rebind-test")

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def await_start(proxy):
    for _ in range(2):
        if not select.select([proxy.stdout], [], [], 10)[0]:
            raise RuntimeError("proxy startup timed out")
        line = proxy.stdout.readline()
        if b"listening" not in line:
            raise RuntimeError(f"startup failed: {line!r}")

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    for size in (16, 32):
        for workers in (1, 2):
            ports = [free_port(), free_port()]
            while ports[1] == ports[0]:
                ports[1] = free_port()
            key = root / "key"
            key.write_text(base64.b64encode(bytes(range(size))).decode() + "\n")
            key.chmod(0o600)
            config = root / "server.kdl"
            (root / "deny.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
            config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{
 shadowsocks "a" {{ listen host="127.0.0.1" port={ports[0]}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
 shadowsocks "b" {{ listen host="127.0.0.1" port={ports[1]}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
}}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ rule-set "deny" path="deny.kdl" format="kdl"; rule kind="rule-set" value="deny" outbound="reject"; default-outbound "direct"; }}
''')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                occupied.bind(("127.0.0.1", ports[1]))
                failed = subprocess.run([nexus, "run", "--config", config], capture_output=True, timeout=10)
                if failed.returncode == 0 or b"cannot listen for SS-2022 UDP" not in failed.stderr:
                    raise RuntimeError(f"UDP bind failure was not reported: {failed.stderr!r}")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.bind(("127.0.0.1", ports[0]))
                for port in ports:
                    with socket.socket() as probe:
                        probe.bind(("127.0.0.1", port))
            proxy = subprocess.Popen(["stdbuf", "-oL", nexus, "run", "--config", config],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            try:
                await_start(proxy)
                subprocess.run([client, str(ports[0]), str(size), "multi", str(ports[1])], check=True, timeout=10)
                proxy.send_signal(signal.SIGTERM)
                _, error = proxy.communicate(timeout=10)
                if proxy.returncode:
                    raise RuntimeError(f"stop failed: {error}")
            finally:
                if proxy.poll() is None:
                    proxy.kill()
                    proxy.communicate()
            proxy = subprocess.Popen(["stdbuf", "-oL", nexus, "run", "--config", config],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            try:
                await_start(proxy)
                subprocess.run([client, str(ports[0]), str(size), "system"], check=True, timeout=10)
                subprocess.run([client, str(ports[0]), str(size), "blocked"], check=True, timeout=10)
                proxy.send_signal(signal.SIGTERM)
                _, error = proxy.communicate(timeout=10)
                if proxy.returncode:
                    raise RuntimeError(f"stop failed: {error}")
            finally:
                if proxy.poll() is None:
                    proxy.kill()
                    proxy.communicate()
print("SS-2022 configured UDP replay, system DNS, block, workers and bind rollback passed")
