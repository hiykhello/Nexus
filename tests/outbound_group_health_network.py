"""Check live outbound group samples on a TCP listener or routed TUN."""
import argparse
import contextlib
import http.server
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

from detour_network import reserve, running
from tailscale_endpoint_network import eventually, line, process


class Probe(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        assert self.path == "/health"
        status = self.server.reply
        if status is None:
            self.server.asked.set()
            self.server.release.wait(2)
            status = 204
        self.send_response(status)
        self.end_headers()

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def peer(address):
    with http.server.ThreadingHTTPServer((address, 0), Probe) as server:
        server.reply = None
        server.asked, server.release = threading.Event(), threading.Event()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server
        finally:
            server.release.set()
            server.shutdown()
            thread.join()


def inspect(binary, control, sample):
    def request(group):
        return subprocess.run([binary, "control", control, "group-health", group],
                              capture_output=True, text=True, timeout=4)

    def state(value):
        response = request("backup")
        if response.returncode:
            return ""
        assert "group=backup mode=fallback selected=direct" in response.stdout, response.stdout
        return next((line for line in response.stdout.splitlines()
                     if line.startswith(f"member=direct state={value} ")), "")

    assert sample.asked.wait(3), "outbound did not reach the probe HTTP peer"
    assert "probing=1" in state("unknown")
    sample.release.set()
    eventually(lambda: "latency-ms=" in state("up") and "sample-age-ms=" in state("up"))
    sample.reply = 503
    eventually(lambda: state("down") and "latency-ms=" not in state("down"))
    assert "state=not-probed" in request("manual").stdout
    assert request("absent").returncode
    sample.reply = 204
    eventually(lambda: "latency-ms=" in state("up"))


def configure(config, inbound, control, address, port, role="client"):
    config.write_text(f'''schema-version 1
role "{role}"
control socket="{control}"
{inbound}
outbound "direct" type="direct"
outbound "blocked" type="block"
outbound "backup" type="fallback" {{
    member "direct"
    member "blocked"
    probe-url "http://{address}:{port}/health"
    probe-interval-ms 500
    probe-timeout-ms 1700
}}
outbound "manual" type="selector" {{ member "backup"; }}
routing {{ default-outbound "manual"; }}
''')


def ordinary(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-group-health-") as tmp, peer("127.0.0.1") as sample:
        root = Path(tmp)
        config, control = root / "group.kdl", root / "control.sock"
        front = reserve()
        inbound = f'inbound "input" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}'
        configure(config, inbound, control, "127.0.0.1", sample.server_port)
        with running([binary, "run", "--config", config], front, root / "proxy.log"):
            inspect(binary, control, sample)
    print("Outbound group pending, up, down and recovery passed on ordinary Server")


def quic(binary):
    from dns_rule_support import nexus_process
    from quic_proxy_route_reload_network import peer_config
    from udp_bind_port_network import certificate

    for protocol in ("hysteria2", "tuic"):
        with tempfile.TemporaryDirectory(prefix="nexus-quic-group-") as tmp, peer("127.0.0.1") as sample:
            root = Path(tmp)
            certificate(root)
            with socket.socket(type=socket.SOCK_DGRAM) as upstream:
                upstream.bind(("127.0.0.1", 0))
                port=upstream.getsockname()[1]
            config,_=peer_config(root,protocol,port)
            text=config.read_text()
            control=root/"control.sock"
            configure(config,text[text.index("inbound "):text.index('outbound "direct"')],control,
                      "127.0.0.1",sample.server_port,role="server")
            with nexus_process(binary,config):
                inspect(binary,control,sample)
        print(f"Outbound group probe uses {protocol} worker's executor")


def routed_tun(binary, root, prefix):
    address = "192.0.2.2"
    command = [*prefix, "ip", "addr", "show", "dev", "nxpeer"]
    assert address in subprocess.check_output(command, text=True)
    # The strict-route rule intercepts the peer address in the parent
    # namespace. Only Nexus's marked outbound socket can reach the peer.
    relay = f"""import http.server, sys
sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
from outbound_group_health_network import Probe
with http.server.ThreadingHTTPServer(({address!r}, 0), Probe) as server:
    server.reply = 204
    print(server.server_port, flush=True)
    server.serve_forever()
"""
    config, control = root / "tun-group.kdl", root / "tun-group.sock"
    inbound = '''inbound "input" type="tun" {
    interface-name "nx-strict"
    inet4-address "198.51.100.1/32"
    inet6-address "2001:db8:2::1/128"
    auto-route #true
    strict-route #true
}'''
    with process([*prefix, "python3", "-c", relay]) as sample:
        configure(config, inbound, control, address, int(line(sample)))
        with process(["stdbuf", "-oL", binary, "run", "--config", config]) as nexus:
            assert b"TUN listening on nx-strict" in line(nexus)
            def checked():
                result = subprocess.run([binary, "control", control, "group-health", "backup"],
                                        capture_output=True, text=True, timeout=4)
                return result.returncode == 0 and "member=direct state=up" in result.stdout
            eventually(checked)
    print("Outbound group probe uses routed TUN's marked socket and executor")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--quic",action="store_true")
    options=parser.parse_args()
    binary=str(Path(options.binary).resolve())
    (quic if options.quic else ordinary)(binary)
