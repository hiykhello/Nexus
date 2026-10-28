"""Loopback interoperability with an isolated dnsmasq instance."""
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

client = Path(sys.argv[1]).resolve()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
with tempfile.TemporaryDirectory(prefix="nexus-dnsmasq-") as directory:
    process = subprocess.Popen([
        "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--no-resolv", "--no-hosts",
        "--listen-address=127.0.0.1", "--bind-interfaces", f"--port={port}",
        f"--pid-file={directory}/dnsmasq.pid", "--local=/nexus.test/",
        "--host-record=target.nexus.test,192.0.2.1,2001:db8::1,60",
        "--cname=alias.nexus.test,target.nexus.test,30",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            probe = subprocess.run(["dig", "@127.0.0.1", "-p", str(port), "+time=1", "+tries=1",
                                    "+short", "target.nexus.test", "A"], capture_output=True, text=True)
            if probe.returncode == 0 and "192.0.2.1" in probe.stdout:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("dnsmasq failed to become ready")
        for case in ("v4", "v6", "alias", "missing"):
            result = subprocess.run([client, str(port), case], capture_output=True, timeout=5)
            if result.returncode:
                raise RuntimeError(f"{case} failed: {result.returncode}, {result.stderr.decode(errors='replace')}")
    finally:
        process.terminate()
        process.wait(timeout=5)
print("dnsmasq A, AAAA, CNAME and NXDOMAIN rejection passed")
