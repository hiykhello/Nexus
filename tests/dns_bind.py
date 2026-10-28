"""Interoperate with an isolated authoritative BIND zone on loopback."""
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

client = Path(sys.argv[1]).resolve()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserve:
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
with tempfile.TemporaryDirectory(prefix="nexus-bind-") as directory:
    root = Path(directory)
    (root / "zone").write_text("""$TTL 120
@ IN SOA ns.nexus.test. hostmaster.nexus.test. (1 3600 600 86400 90)
  IN NS ns.nexus.test.
ns IN A 127.0.0.1
v4 IN A 192.0.2.1
v4alias 30 IN CNAME v4.nexus.test.
missingalias 30 IN CNAME absent.nexus.test.
""")
    (root / "named.conf").write_text(f'''options {{
    directory "{root}";
    listen-on port {port} {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    recursion no;
    allow-query {{ 127.0.0.1; }};
    pid-file "{root}/named.pid";
    session-keyfile "{root}/session.key";
    managed-keys-directory "{root}";
}};
zone "nexus.test" {{ type primary; file "zone"; }};
''')
    process = subprocess.Popen(["named", "-g", "-c", str(root / "named.conf"), "-n", "1", "-U", "1"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode(errors="replace"))
            probe = subprocess.run(["dig", "@127.0.0.1", "-p", str(port), "+time=1", "+tries=1",
                                    "+short", "v4.nexus.test", "A"], capture_output=True, text=True)
            if probe.returncode == 0 and "192.0.2.1" in probe.stdout:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("BIND failed to become ready")
        for case in ("bind-nodata", "bind-alias-nodata", "bind-alias-missing"):
            result = subprocess.run([client, str(port), case], capture_output=True, timeout=5)
            if result.returncode:
                raise RuntimeError(f"{case}: exit {result.returncode}, {result.stderr.decode(errors='replace')}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
print("BIND authoritative NODATA, CNAME and NXDOMAIN passed")
