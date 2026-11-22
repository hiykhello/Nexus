"""Batch 95B: verify Linux TPROXY UDP reply socket cache (#3876) in isolated netns."""
import contextlib
import os
import re
import select
import subprocess
import sys
import tempfile
from pathlib import Path

ECHO_SERVER = """
import selectors, socket, sys
family = socket.AF_INET6 if sys.argv[1] == '6' else socket.AF_INET
bind_ip, start_port, count = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sel = selectors.DefaultSelector()
for p in range(start_port, start_port + count):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((bind_ip, p))
    sel.register(s, selectors.EVENT_READ, p)
sys.stdout.write("ready\\n")
sys.stdout.flush()
while True:
    for key, _ in sel.select():
        data, addr = key.fileobj.recvfrom(2048)
        key.fileobj.sendto(f"{key.data}:".encode() + data, addr)
"""

CLIENT_BURST = """
import socket, sys
family = socket.AF_INET6 if sys.argv[1] == '6' else socket.AF_INET
target_ip, mode, port, count = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
for i in range(count):
    dst_port = port if mode == 'same' else (port + i)
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(3.0)
        payload = f"flow-{i}".encode()
        s.sendto(payload, (target_ip, dst_port))
        reply, peer = s.recvfrom(2048)
        assert peer[0] == target_ip and peer[1] == dst_port, f"spoof mismatch: got {peer}, expected {(target_ip, dst_port)}"
        assert reply == f"{dst_port}:flow-{i}".encode(), f"bad reply: {reply}"
print(f"ok:{mode}:{count}")
"""


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def ns(pid, *args):
    return command("nsenter", "-t", str(pid), "-n", *args)


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def network_namespace(stack):
    proc = subprocess.Popen(["unshare", "-n", "sh", "-c", "echo ready; exec sleep 90"], stdout=subprocess.PIPE)
    stack.callback(stop, proc)
    assert proc.stdout.readline() == b"ready\n"
    ns(proc.pid, "ip", "link", "set", "lo", "up")
    return proc.pid


def veth(peer, local, foreign):
    command("ip", "link", "add", local, "type", "veth", "peer", "name", foreign)
    command("ip", "link", "set", foreign, "netns", str(peer))
    command("ip", "link", "set", local, "up")
    ns(peer, "ip", "link", "set", foreign, "up")


def ready(proc, stdout=False):
    pipe = proc.stdout if stdout else proc.stderr
    if select.select([pipe], [], [], 5)[0]:
        return pipe.readline()
    raise AssertionError("child output did not arrive")


def launch_namespace(stack, pid, script, *args):
    proc = subprocess.Popen(
        ["nsenter", "-t", str(pid), "-n", sys.executable, "-c", script, *map(str, args)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
    )
    stack.callback(stop, proc)
    return proc


def run_suite(binary):
    command("ip", "link", "set", "lo", "up")
    with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory(prefix="nexus-95b-") as tmp:
        root = Path(tmp)
        client_ns = network_namespace(stack)
        origin_ns = network_namespace(stack)
        veth(client_ns, "vethc0", "vethc1")
        veth(origin_ns, "vetho0", "vetho1")

        command("ip", "addr", "add", "10.95.1.1/24", "dev", "vethc0")
        command("ip", "addr", "add", "10.95.2.1/24", "dev", "vetho0")
        command("ip", "-6", "addr", "add", "fd95:1::1/64", "dev", "vethc0", "nodad")
        command("ip", "-6", "addr", "add", "fd95:2::1/64", "dev", "vetho0", "nodad")
        ns(client_ns, "ip", "addr", "add", "10.95.1.2/24", "dev", "vethc1")
        ns(client_ns, "ip", "route", "add", "default", "via", "10.95.1.1")
        ns(client_ns, "ip", "-6", "addr", "add", "fd95:1::2/64", "dev", "vethc1", "nodad")
        ns(client_ns, "ip", "-6", "route", "add", "default", "via", "fd95:1::1")
        ns(origin_ns, "ip", "addr", "add", "10.95.2.2/24", "dev", "vetho1")
        ns(origin_ns, "ip", "route", "add", "default", "via", "10.95.2.1")
        ns(origin_ns, "ip", "-6", "addr", "add", "fd95:2::2/64", "dev", "vetho1", "nodad")
        ns(origin_ns, "ip", "-6", "route", "add", "default", "via", "fd95:2::1")

        command("ip", "rule", "add", "fwmark", "1", "lookup", "100")
        command("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100")
        command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100")
        command("ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "100")

        command("iptables", "-t", "mangle", "-A", "PREROUTING", "-i", "vethc0",
                "-p", "udp", "-d", "10.95.2.2", "-j", "TPROXY",
                "--on-ip", "10.95.1.1", "--on-port", "19501", "--tproxy-mark", "1")
        command("ip6tables", "-t", "mangle", "-A", "PREROUTING", "-i", "vethc0",
                "-p", "udp", "-d", "fd95:2::2", "-j", "TPROXY",
                "--on-ip", "fd95:1::1", "--on-port", "19502", "--tproxy-mark", "1")

        srv4 = launch_namespace(stack, origin_ns, ECHO_SERVER, "4", "10.95.2.2", "21000", "72")
        assert ready(srv4, stdout=True) == b"ready\n"
        srv6 = launch_namespace(stack, origin_ns, ECHO_SERVER, "6", "fd95:2::2", "22000", "16")
        assert ready(srv6, stdout=True) == b"ready\n"

        cfg = root / "tproxy95b.kdl"
        cfg.write_text("""schema-version 1
role "client"
sessions-per-listener 256
inbound "tp4" type="tproxy" { listen host="10.95.1.1" port=19501; udp #true; }
inbound "tp6" type="tproxy" { listen host="fd95:1::1" port=19502; udp #true; }
outbound "direct" type="direct"
routing { default-outbound "direct"; }
""")
        strace_log = root / "strace.log"
        proc = subprocess.Popen(
            ["strace", "-f", "-qq", "-e", "trace=bind", "-o", str(strace_log),
             binary, "run", "--config", str(cfg)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        stack.callback(stop, proc)
        line = ready(proc, stdout=False)
        assert b"listening" in line or b"ready" in line or line, line

        # 1. 24 distinct IPv4 flows targeting SAME 10.95.2.2:21000 -> expect 1 bind()!
        r4 = subprocess.run(["nsenter", "-t", str(client_ns), "-n", sys.executable, "-c",
                             CLIENT_BURST, "4", "10.95.2.2", "same", "21000", "24"],
                            check=True, capture_output=True, text=True, timeout=15)
        assert "ok:same:24" in r4.stdout, r4.stdout

        # 2. 16 distinct IPv6 flows targeting SAME [fd95:2::2]:22000 -> expect 1 bind()!
        r6 = subprocess.run(["nsenter", "-t", str(client_ns), "-n", sys.executable, "-c",
                             CLIENT_BURST, "6", "fd95:2::2", "same", "22000", "16"],
                            check=True, capture_output=True, text=True, timeout=15)
        assert "ok:same:16" in r6.stdout, r6.stdout

        # 3. 72 distinct IPv4 target ports (>64 cache cap) -> verify eviction & continued correctness!
        r72 = subprocess.run(["nsenter", "-t", str(client_ns), "-n", sys.executable, "-c",
                              CLIENT_BURST, "4", "10.95.2.2", "distinct", "21000", "72"],
                             check=True, capture_output=True, text=True, timeout=20)
        assert "ok:distinct:72" in r72.stdout, r72.stdout

        stop(proc)
        trace = strace_log.read_text()
        binds_v4_21000 = len(re.findall(r'bind\(.*sin_port=htons\(21000\).*10\.95\.2\.2', trace))
        binds_v6_22000 = len(re.findall(r'bind\(.*sin6_port=htons\(22000\).*fd95:2::2', trace))
        assert binds_v4_21000 == 1, f"expected exactly 1 bind for 24+1 IPv4 flows to :21000, saw {binds_v4_21000}"
        assert binds_v6_22000 == 1, f"expected exactly 1 bind for 16 IPv6 flows to :22000, saw {binds_v6_22000}"
        print(f"95B TPROXY UDP reply socket cache passed: 24+1 IPv4 flows to :21000 -> binds={binds_v4_21000}; "
              f"16 IPv6 flows to :22000 -> binds={binds_v6_22000}; 72-port eviction burst passed")


if __name__ == "__main__":
    if os.geteuid() != 0:
        os.execvp("unshare", ["unshare", "-Urn", sys.executable, "-B", __file__, *sys.argv[1:]])
    run_suite(sys.argv[1])
