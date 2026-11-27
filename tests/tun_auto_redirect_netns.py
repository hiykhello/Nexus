#!/usr/bin/env python3
"""Native nftables auto-redirect from isolated host and forwarded sockets."""
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

from dns_batch93c_network import query
from dns_rule_support import DnsPeer, Echo, dns_request, exact
from routing_batch93b_network import peer_link, snapshot
from tailscale_endpoint_network import eventually, ip, line, process
from tun_nftables_probe import tables

PRIVATE = ((socket.AF_INET, "10.10.1.2"), (socket.AF_INET6, "fd10:1::2"))
ORIGIN = ((socket.AF_INET, "192.0.2.2"), (socket.AF_INET6, "2001:db8:1::2"))
CLIENTS = (("198.51.100.1", "198.51.100.2"), ("2001:db8:3::1", "2001:db8:3::2"))
MARK = 0x6E780001
DNS_LISTEN = 15553


def setup(origin, client):
    for ((_, target), (_, private), (router, sender)) in zip(ORIGIN, PRIVATE, CLIENTS):
        ipv6 = ":" in router
        flag, suffix = ("-6", "/64") if ipv6 else ("-4", "/24")
        nodad = ("nodad",) if ipv6 else ()
        out = target[:-1]+"1"
        for address, dev, namespace in ((out, "nxwan", ()), (target, "nxorigin", origin),
                                        (router, "nxlan", ()), (sender, "nxclient", client),
                                        (private, "nxorigin", origin), (private[:-1]+"1", "nxwan", ())):
            ip(flag, "addr", "add", address+suffix, "dev", dev, *nodad, prefix=namespace)
        ip(flag, "route", "add", "default", "via", target, "dev", "nxwan")
        ip(flag, "route", "add", "default", "via", router, "dev", "nxclient", prefix=client)
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"],
                   check=True, capture_output=True)
    for dev in ("nxwan", "nxlan"):
        eventually(lambda: "scope link" in ip("-6", "addr", "show", "dev", dev, "-tentative"))

PEER = r"""
import socket, socketserver, sys, threading
from contextlib import ExitStack
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)
class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        request = self.rfile.readline()
        if not request: return
        assert request.startswith(b'CONNECT '), request
        while self.rfile.readline() not in (b'\r\n', b''): pass
        self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        while data := self.request.recv(65536):
            self.request.sendall(b'PROXIED:'+data)
class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)
with ExitStack() as stack:
    for server, handler, addresses, port in (
        (socketserver.ThreadingTCPServer,Echo,sys.argv[1:5],18080),
        (socketserver.ThreadingTCPServer,Echo,sys.argv[1:3],18084),
        (socketserver.ThreadingTCPServer,Proxy,sys.argv[1:2],18082),
        (socketserver.ThreadingUDPServer,Udp,sys.argv[1:3],18081)):
        for address in addresses:
            family = socket.AF_INET6 if ':' in address else socket.AF_INET
            cls = type('Bound', (server,), {'address_family': family, 'daemon_threads': True})
            owner = stack.enter_context(cls((address,port),handler))
            threading.Thread(target=owner.serve_forever, daemon=True).start()
    print('ready', flush=True)
    sys.stdin.buffer.read(1)
"""


def configure(root, dns, marks=False, fakeip=False, enabled=True):
    conf = root / "tun.kdl"
    control = root / "control.sock"
    # Use a private-origin reject rule. If the packet improperly reaches either proxy entry, it fails.
    mark_config = 'include-routing-mark 0x20 mask=0xf0\n    exclude-routing-mark 0x23' if marks else ""
    fake = ""
    if fakeip:
        pool = root / "fakeip"
        pool.mkdir(mode=0o700,exist_ok=True)
        for name, size in (("instance.id",16),("history.key",32)):
            target=pool / name
            if not target.exists():
                target.touch(mode=0o600)
                target.write_bytes(os.urandom(size))
        fake = (f'fake-ip server="wire" ipv4-pool="198.18.0.0/29" ipv6-pool="fd15:4231::/96" '
                f'ttl-seconds=2 state-directory="{pool}" initialize=#true')
    conf.write_text(f'''schema-version 1
role "client"
log {{ privacy "verbose"; }}
control socket="{control}"
inbound "tun" type="tun" {{
    interface-name "nx-redirect"
    inet4-address "198.19.0.1/32"
    inet6-address "2001:db8:100::1/128"
    auto-route #true
    auto-redirect {"#true" if enabled else "#false"}
    strict-route #true
    route-exclude-private #true
    endpoint-independent-nat {"#false" if fakeip else "#true"}
    dns-hijack-tcp #true
    {mark_config}
}}
outbound "direct" type="direct"
outbound "edge" type="http-connect" {{ server host="192.0.2.2" port=18082; }}
dns {{
    {f'listen host="127.0.0.1" port={DNS_LISTEN}' if fakeip else ""}
    server "wire" type="udp" host="127.0.0.1" port={dns.port}
    final "wire"
    {fake}
}}
routing {{
    tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
        rule action="hijack-dns" {{ port 53; }}
        rule action="reject" {{ ip-cidr "10.0.0.0/8"; }}
        rule action="reject" {{ ip-cidr "fd10:1::/64"; }}
        rule action="reject" {{ port 18084; }}
        rule action="route" outbound="edge" {{ port 18083; }}
        rule action="route" outbound="direct"
    }}
    final "direct"
}}
''')
    return conf,control


def native(prefix, host, port, text, mark=0, local=False):
    code = """
import socket,sys,time
host,port,mark,data,hold=sys.argv[1:]
with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as sock:
    if int(mark): sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,int(mark))
    sock.settimeout(3)
    sock.connect((host,int(port)))
    sock.sendall(data.encode())
    expected=len(data)+(8 if int(port)==18083 and int(mark) not in (35, 0x6e780001) else 0)
    answer=b''
    while len(answer)<expected:
        got=sock.recv(expected-len(answer))
        if not got: break
        answer+=got
    print(answer.decode(),flush=True)
    if hold=='yes': sys.stdin.buffer.read(1)
"""
    return process([*prefix, sys.executable, "-u", "-c", code, host, str(port), str(mark), text,
                    "yes" if local else "no"], stdin=subprocess.PIPE)


def wait_ready(child):
    assert b"TUN listening" in line(child)


def check_data(binary, conf, control, client, marks=False):
    with process(["stdbuf", "-oL", binary, "run", "--traffic-stats", "--config", conf]) as proxy:
        wait_ready(proxy)
        owned = [name for name in tables() if name.startswith("nexus_auto_redirect_")]
        assert len(owned)==1, owned
        allowed = 0x2a if marks else 0
        for (family, address), (_, private) in zip(ORIGIN, PRIVATE):
            with native((), address, 18080, "direct", allowed, True) as stream:
                assert line(stream)==b"direct\n"
                listing=subprocess.check_output([binary,"control",control,"connections","0"],text=True)
                assert "protocol=redirect " in listing and "outbound=direct" in listing, listing
            with native((), address, 18083, "edge", allowed, True) as stream:
                assert line(stream)==b"PROXIED:edge\n"
                listing=subprocess.check_output([binary,"control",control,"connections","0"],text=True)
                assert "protocol=redirect " in listing and "outbound=edge" in listing, listing
            with native((), private, 18080, "private", allowed) as stream:
                assert line(stream)==b"private\n"
            if not marks:
                for port, reply in ((18080,b"forward\n"), (18083,b"PROXIED:forward\n")):
                    with native(client,address,port,"forward",local=True) as stream:
                        assert line(stream)==reply
                        listing=subprocess.check_output([binary,"control",control,"connections","0"],text=True)
                        assert any("protocol=redirect " in row and f"destination-port={port} " in row
                                   for row in listing.splitlines()), listing
            else:
                for filter_mark in (0, 0x23, MARK):
                    with native((),address,18084,"physical",filter_mark) as stream:
                        assert line(stream)==b"physical\n"
            with socket.socket(family,socket.SOCK_DGRAM) as udp:
                if allowed: udp.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,allowed)
                udp.settimeout(3)
                udp.sendto(b"tun-udp",(address,18081))
                assert udp.recv(128)==b"tun-udp"
            with socket.socket(family,socket.SOCK_STREAM) as dns:
                if allowed: dns.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,allowed)
                dns.settimeout(3)
                dns.connect((private,53))
                wire=query("private-dns.test",1 if family==socket.AF_INET else 28)
                dns.sendall(struct.pack("!H",len(wire))+wire)
                answer=exact(dns,int.from_bytes(exact(dns,2),"big"))
                assert answer[:2]==wire[:2] and answer[7]>0,answer.hex()
            with socket.socket(family,socket.SOCK_DGRAM) as dns:
                if allowed: dns.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,allowed)
                dns.settimeout(3)
                dns.sendto(wire,(private,53))
                answer,source=dns.recvfrom(4096)
                assert source[:2]==(private,53) and answer[:2]==wire[:2] and answer[7]>0,(source,answer.hex())
        if not marks:
            for _, address in ORIGIN:
                print(f"native local {address} latency/rate: {sample(address)}")
    print(f"dual-stack output, {'mark precedence' if marks else 'forwarded native TCP'}, direct/proxy, private bypass, UDP, TCP and UDP DNS")


def check_fakeip(binary, root, dns):
    conf,control=configure(root,dns,fakeip=True)
    with Echo() as echo, process(["stdbuf","-oL",binary,"run","--traffic-stats","--config",conf]) as proxy:
        wait_ready(proxy)
        for family, qtype in ((socket.AF_INET,1),(socket.AF_INET6,28)):
            deadline=time.monotonic()+14
            while True:
                rcode,alias=dns_request(DNS_LISTEN,"target.test",kind=qtype)
                if rcode!=2 or time.monotonic()>=deadline:
                    break
                time.sleep(.2)
            assert rcode==0 and alias.startswith("198.18." if qtype==1 else "fd15:4231:"),(rcode,alias)
            with socket.create_connection((alias,echo.port),timeout=3) as tcp:
                tcp.sendall(b"fakeip tcp")
                assert exact(tcp,10)==b"fakeip tcp"
                listing=subprocess.check_output([binary,"control",control,"connections","0"],text=True)
                assert "protocol=redirect " in listing, listing
            with socket.socket(family,socket.SOCK_DGRAM) as udp:
                udp.settimeout(3)
                udp.sendto(b"fakeip udp",(alias,echo.port))
                data,source=udp.recvfrom(128)
                assert (data,source[:2])==(b"fakeip udp",(alias,echo.port))
    print("dual-stack FakeIP: native TCP redirect and TUN UDP preserve the synthetic destination")


def sample(address):
    connect_ms, rates = [], []
    for _ in range(5):
        begin=time.monotonic()
        with socket.create_connection((address,18080),timeout=5) as stream:
            connect_ms.append((time.monotonic()-begin)*1000)
            data=b"x"*32768
            begin=time.monotonic()
            for _ in range(8):
                stream.sendall(data)
                assert exact(stream,len(data))==data
            rates.append(.25/(time.monotonic()-begin))
    return f"{sorted(connect_ms)[2]:.3f} ms, {sorted(rates)[2]:.1f} MiB/s"


def run(binary, root):
    ip("link","set","lo","up")
    with peer_link("nxwan","nxorigin","02:00:00:00:81:01") as origin, \
         peer_link("nxlan","nxclient","02:00:00:00:81:02") as client, \
         DnsPeer() as dns:
        setup(origin,client)
        baseline=tables(create=True)
        network=snapshot()
        reverse_paths=[Path("/proc/sys/net/ipv4/conf")/device/"rp_filter" for device in ("nxwan","nxlan")]
        filters=[path.read_text() for path in reverse_paths]
        addresses=[address for _,address in (*ORIGIN,*PRIVATE)]
        with process([*origin,sys.executable,"-u","-c",PEER,*addresses],stdin=subprocess.PIPE) as echo:
            assert line(echo)==b"ready\n"
            for marks in (False,True):
                conf,control=configure(root,dns,marks)
                check_data(binary,conf,control,client,marks)
                eventually(lambda:tables()==baseline and snapshot()==network)
            check_fakeip(binary,root,dns)
            assert tables()==baseline and snapshot()==network
            conf,_=configure(root,dns,enabled=False)
            with process(["stdbuf","-oL",binary,"run","--config",conf]) as proxy:
                wait_ready(proxy)
                assert tables()==baseline
                for _, address in ORIGIN:
                    print(f"TUN TCP local {address} latency/rate: {sample(address)}")
            conf,control=configure(root,dns)
            conf.write_text(conf.read_text().replace(f'control socket="{control}"\n',""))
            with subprocess.Popen(["stdbuf","-oL",binary,"run","--config",conf],
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE) as proxy:
                wait_ready(proxy)
                assert len(tables())==len(baseline)+1
                start=time.monotonic()
                proxy.kill()
                assert proxy.wait(timeout=3)==-9
                eventually(lambda:tables()==baseline and snapshot()==network and
                           subprocess.run(["ip","link","show","nx-redirect"],capture_output=True).returncode==1)
                assert [path.read_text() for path in reverse_paths]==filters
                print(f"SIGKILL reclaimed nftables and routing in {(time.monotonic()-start)*1000:.1f} ms; unrelated table intact")
            with process(["stdbuf","-oL",binary,"run","--config",conf]) as proxy:
                wait_ready(proxy)
                assert len(tables())==len(baseline)+1
            assert tables()==baseline and snapshot()==network

if __name__=="__main__":
    binary=str(Path(sys.argv[1]).resolve())
    if len(sys.argv)==2:
        raise SystemExit(subprocess.call(["unshare","-Urn",sys.executable,__file__,binary,"isolated"]))
    with tempfile.TemporaryDirectory(prefix="nexus-93d-") as work:
        run(binary,Path(work))
