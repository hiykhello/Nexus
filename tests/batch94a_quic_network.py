#!/usr/bin/env python3
"""Hy2 flow control and QUIC UDP ownership in the production CLI."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import heapq
from pathlib import Path
import select
import signal
import socket
from statistics import median
import struct
import subprocess
import tempfile
import threading
import time

from detour_network import exact, reserve, running, socks
from dns_rule_support import udp_client
from tailscale_endpoint_network import eventually
from tuic_singbox import free_port, start_tcp_echo

WINDOWS = """init-stream-receive-window 262144; max-stream-receive-window 1048576;
             init-conn-receive-window 1048576; max-conn-receive-window 4194304;"""


class Delay:
    """Delay each UDP direction by the same duration on a controlled link."""
    def __init__(self, port, delay):
        self.port = free_port(socket.SOCK_DGRAM)
        self.server = ("127.0.0.1",port)
        self.delay = delay
        self.stop = threading.Event()
        self.errors = []

    def run(self, socket_):
        queued = []
        client = None
        serial = 0
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                while queued and queued[0][0] <= now:
                    _,_,peer,packet = heapq.heappop(queued)
                    socket_.sendto(packet,peer)
                wait = max(0,min(.02,queued[0][0]-now)) if queued else .02
                if not select.select([socket_],[],[],wait)[0]:
                    continue
                packet,origin = socket_.recvfrom(65536)
                if origin != self.server:
                    client = origin
                peer = client if origin == self.server else self.server
                if peer is not None:
                    serial += 1
                    heapq.heappush(queued,(time.monotonic()+self.delay,serial,peer,packet))
        except Exception as error:
            self.errors.append(error)

    def __enter__(self):
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024)
        self.socket.bind(("127.0.0.1",self.port))
        self.thread = threading.Thread(target=self.run,args=(self.socket,))
        self.thread.start()
        return self.port

    def __exit__(self, kind, *_):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        if kind is None:
            assert not self.thread.is_alive() and not self.errors,self.errors


def configure(root, protocol, side, port, remote=0, large=False, idle=800):
    file = root / (side+".kdl")
    tls_in = f'tls {{ certificate-file "{root/"cert"}"; private-key-file "{root/"key"}"; }}'
    tls_out = f'tls {{ server-name "localhost"; ca-file "{root/"cert"}"; verify #true; }}'
    password = f'password-file "{root/"password"}"'
    tls = tls_in if side=="server" else tls_out
    inbound_auth = f'user "test" password-file="{root/"password"}";'
    outbound_auth = password+";"
    if protocol=="hysteria2":
        transport = f"quic {{ idle-timeout-ms {idle}; {WINDOWS if large else ''} }}"
    elif protocol=="tuic":
        transport = f'idle-timeout-ms {idle}\n    congestion-control "cubic"'
        inbound_auth = f'user "test" uuid-file="{root/"uuid"}" password-file="{root/"password"}";'
        outbound_auth = f'uuid-file "{root/"uuid"}"; {password};'
    else:
        transport = 'authority "localhost"'
        transport += '\n    allow cidr="127.0.0.0/8" first-port=1 last-port=65535' if side=="server" else f'\n    idle-timeout-ms {idle}'
        inbound_auth = outbound_auth = f'bearer-file "{root/"password"}";'
    if side=="server":
        file.write_text(f'''schema-version 1
role "server"
control socket="{root/"control.sock"}"
inbound "edge" type="{protocol}" {{
    listen host="127.0.0.1" port={port}
    authentication {{ {inbound_auth} }}
    {tls}
    {transport}
}}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    else:
        file.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="{protocol}" {{
    server host="127.0.0.1" port={remote}
    authentication {{ {outbound_auth} }}
    {tls}
    {transport}
}}
routing {{ final "edge"; }}
''')
    return file


@contextmanager
def quic_server(binary,root,config,protocol):
    path = root/"server.log"
    with path.open("wb") as output:
        child = subprocess.Popen(["stdbuf","-oL",binary,"run","--traffic-stats","--config",config],
                                 stdout=output,stderr=subprocess.STDOUT)
        try:
            name = {"hysteria2":"Hysteria2","tuic":"TUIC","masque":"MASQUE"}[protocol]
            def ready():
                assert child.poll() is None,path.read_text()
                return f"{name} listening" in path.read_text()
            eventually(ready)
            yield child
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=6)
            assert child.returncode==0,path.read_text()


def fd_count(pid):
    return len(list(Path(f"/proc/{pid}/fd").iterdir()))


def listing(binary,root):
    return subprocess.check_output([binary,"control",root/"control.sock","connections","0"],text=True,timeout=2)


def associate(front, origin, tag):
    target = origin.getsockname()[1]
    datagram = b"\x00\x00\x00\x01\x7f\x00\x00\x01"+struct.pack("!H",target)
    with udp_client(front) as (client, relay):
        client.settimeout(4)
        client.sendto(datagram+tag,relay)
        data,peer = origin.recvfrom(4000)
        assert data==tag,(data,tag)
        origin.sendto(data,peer)
        assert client.recvfrom(4000)[0]==datagram+tag
        yield


def disconnect(binary,root,protocol):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as origin:
        origin.bind(("127.0.0.1",0))
        origin.settimeout(5)
        server_port = free_port(socket.SOCK_DGRAM)
        server_cfg = configure(root,protocol,"server",server_port)
        with quic_server(binary,root,server_cfg,protocol) as server:
            baseline = fd_count(server.pid)
            traffic = f"protocol={protocol}-udp "
            for round_ in range(3):
                front = reserve()
                client_cfg = configure(root,protocol,"client",front,server_port,idle=800 if protocol=="masque" else 5000)
                with (root/"client.log").open("wb") as output:
                    client = subprocess.Popen([binary,"run","--config",client_cfg],stdout=output,stderr=subprocess.STDOUT)
                    try:
                        def ready():
                            assert client.poll() is None,(root/"client.log").read_text()
                            try:
                                with socket.create_connection(("127.0.0.1",front),timeout=.1):
                                    return True
                            except OSError:
                                return False
                        eventually(ready)
                        with contextmanager(associate)(front,origin,bytes([round_])):
                            before = listing(binary,root)
                            assert traffic in before,before
                            assert fd_count(server.pid)>baseline
                            started=time.monotonic()
                            client.send_signal(signal.SIGKILL)
                            assert client.wait(timeout=3)==-signal.SIGKILL
                            eventually(lambda:traffic not in listing(binary,root) and fd_count(server.pid)==baseline,3)
                            time_ms=(time.monotonic()-started)*1000
                            print(f"{protocol} UDP-only SIGKILL round {round_ + 1}: route and FD baseline in {time_ms:.0f} ms")
                    finally:
                        if client.poll() is None:
                            client.terminate()
                            client.wait(timeout=5)


def bulk(front,port):
    size = 2*1024*1024
    data = bytes(range(256))*(size//256)
    start = time.monotonic()
    with socks(front,1,("127.0.0.1",port))[0] as stream, ThreadPoolExecutor(1) as upload:
        stream.settimeout(24)
        def write():
            stream.sendall(data)
            stream.shutdown(socket.SHUT_WR)

        task = upload.submit(write)
        assert exact(stream,len(data))==data
        assert stream.recv(1)==b""
        task.result()
    return time.monotonic()-start


def flow_control(binary,root):
    origin,origin_port,stop = start_tcp_echo()
    runs = {}
    try:
        for large in (False,True):
            port = free_port(socket.SOCK_DGRAM)
            server = configure(root,"hysteria2","server",port,large=large,idle=6000)
            trials = []
            with quic_server(binary,root,server,"hysteria2"):
                for _ in range(3):
                    with Delay(port,.012) as relay:
                        front = reserve()
                        client = configure(root,"hysteria2","client",front,relay,large=large,idle=6000)
                        with running([binary,"run","--config",client],front,root/"client.log"):
                            trials.append(bulk(front,origin_port))
                runs[large] = median(trials)
            print(f"Hy2 large={large}, three samples in seconds: {', '.join(f'{trial:.2f}' for trial in trials)}")
        print(f"Hy2 24 ms RTT, bidirectional 2 MiB: default {runs[False]:.2f} s, configured windows {runs[True]:.2f} s")
        assert runs[True] < runs[False],runs
    finally:
        stop.set()
        origin.close()


def prepare(root):
    subprocess.run(["openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256",
                    "-nodes","-keyout",root/"key","-out",root/"cert","-days","1",
                    "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost"],
                   check=True,capture_output=True)
    for name,value in (("password","batch94a-test"),("uuid","00010203-0405-0607-0809-0a0b0c0d0e0f")):
        file = root/name
        file.write_text(value)
        file.chmod(0o600)


if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary",type=Path)
    parser.add_argument("case",choices=("windows","hysteria2","tuic","masque"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-94a-quic-") as directory:
        root = Path(directory)
        prepare(root)
        if args.case=="windows":
            flow_control(args.binary.resolve(),root)
        else:
            disconnect(args.binary.resolve(),root,args.case)
