#!/usr/bin/env python3
"""Compare direct SOCKS TCP/UDP and DNS through pinned Linux proxy binaries."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import math
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import statistics
import struct
import tempfile
import time

from detour_network import exact, reserve, running
from dns_rule_support import DnsPeer, Echo, dns_request, udp_client, wire_name

CHUNK=bytes(range(256))*256
BYTES=16*1024*1024


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads=True
    request_queue_size=256


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        code=self.request.recv(1)
        if not code:
            return
        if code==b"d":
            for _ in range(BYTES//len(CHUNK)):
                self.request.sendall(CHUNK)
            return
        if code==b"u":
            observed=hashlib.sha256()
            remaining=BYTES
            while remaining:
                data=self.request.recv(min(remaining,len(CHUNK)))
                if not data:
                    return
                remaining-=len(data)
                observed.update(data)
            self.request.sendall(observed.digest())
            return
        self.request.sendall(code)
        self.request.recv(1)


def connected(front, origin, expect=True):
    client=socket.create_connection(("127.0.0.1",front),timeout=8)
    try:
        client.sendall(b"\5\1\0")
        assert exact(client,2)==b"\5\0"
        client.sendall(b"\5\1\0\1\x7f\0\0\1"+struct.pack("!H",origin))
        reply=exact(client,4)
        if reply[3] in (1,4):
            exact(client,6 if reply[3]==1 else 18)
        elif reply[3]==3:
            exact(client,exact(client,1)[0]+2)
        else:
            raise RuntimeError(f"invalid SOCKS reply {reply!r}")
        assert (reply[1]==0)==expect,reply
        return client
    except BaseException:
        client.close()
        raise


def usage(pid):
    proc=Path("/proc")/str(pid)
    fields=(proc/"stat").read_text().rsplit(")",1)[1].split()
    cpu=(int(fields[11])+int(fields[12]))/os.sysconf("SC_CLK_TCK")
    status=dict(line.split(":",1) for line in (proc/"status").read_text().splitlines() if ":" in line)
    return {"cpu_seconds":cpu,"rss_kib":int(status["VmRSS"].split()[0]),
            "rss_peak_kib":int(status["VmHWM"].split()[0]),"fds":len(list((proc/"fd").iterdir())),
            "threads":int(status["Threads"])}


def bulk(front, origin, code, expected_digest):
    with connected(front,origin) as client:
        client.sendall(code)
        if code==b"u":
            for _ in range(BYTES//len(CHUNK)):
                client.sendall(CHUNK)
            assert exact(client,32)==expected_digest
            return
        remaining=BYTES
        digest=hashlib.sha256()
        while remaining:
            data=client.recv(min(remaining,len(CHUNK)))
            if not data:
                raise RuntimeError("short download")
            digest.update(data)
            remaining-=len(data)
        assert digest.digest()==expected_digest


def workload(process,front,origin,pool,bulk_bytes):
    failed=reserve()
    with connected(front,failed,False):
        pass
    with connected(front,origin) as client:
        client.sendall(b"r")
        assert exact(client,1)==b"r"
    time.sleep(.15)
    before=usage(process.pid)
    with contextlib.ExitStack() as active:
        def handshake(_index):
            begin=time.monotonic_ns()
            sock=connected(front,origin)
            sock.sendall(b"r")
            assert exact(sock,1)==b"r"
            return sock,(time.monotonic_ns()-begin)/1e6
        pending=[pool.submit(handshake,i) for i in range(64)]
        latencies=[]
        for item in pending:
            sock,duration=item.result()
            active.enter_context(sock)
            latencies.append(duration)
        peak=usage(process.pid)
    sha=hashlib.sha256(CHUNK*(bulk_bytes//len(CHUNK))).digest()
    rates={}
    for label,code in (("upload",b"u"),("download",b"d")):
        rates[label]=[]
        for _ in range(3):
            start=time.monotonic_ns()
            results=[pool.submit(bulk,front,origin,code,sha) for _ in range(4)]
            for item in results:
                item.result()
            rates[label].append(round(4*bulk_bytes/(time.monotonic_ns()-start)*8,3))
    time.sleep(.15)
    after=usage(process.pid)
    return {"idle":before,"64_connections":peak,"after":after,
            "traffic_cpu_seconds":round(after["cpu_seconds"]-peak["cpu_seconds"],3),
            "connection_latency_ms":{"median":round(statistics.median(latencies),3),
                "p95":round(sorted(latencies)[math.ceil(.95 * len(latencies)) - 1],3)},
            "throughput_gbps":rates}


def packet_workload(front, dns_port, udp_peer, dns_peer, identity):
    payload=b"three-party-udp"
    with udp_client(front) as (client,relay):
        header=b"\0\0\0\1\x7f\0\0\1"+struct.pack("!H",udp_peer.port)
        before=len(udp_peer.received)
        begin=time.monotonic()
        for _ in range(32):
            client.sendto(header+payload,relay)
            assert client.recv(1024)==header+payload
        udp_ms=(time.monotonic()-begin)*1000/32
        assert udp_peer.received[before:]==[payload]*32

    begin=time.monotonic()
    before=dns_peer.count("three-party.test",1)
    for index in range(32):
        assert dns_request(dns_port,"three-party.test",identifier=100+index)==(0,"127.0.0.1")
    dns_ms=(time.monotonic()-begin)*1000/32
    upstream_queries=dns_peer.count("three-party.test",1)-before

    stopped=f"canceled-{identity}.test"
    dns_peer.drop.add((stopped,1))
    query=struct.pack("!6H",1234,0x100,1,0,0,0)+wire_name(stopped)+b"\0\1\0\1"
    begin=time.monotonic()
    with socket.create_connection(("127.0.0.1",dns_port),timeout=3) as client:
        client.sendall(struct.pack("!H",len(query))+query)
        deadline=begin+3
        while not dns_peer.count(stopped,1):
            assert time.monotonic()<deadline, stopped
            time.sleep(.005)
    assert dns_request(dns_port,f"after-{identity}.test",socket.SOCK_STREAM)==(0,"127.0.0.1")
    recovery_ms=(time.monotonic()-begin)*1000
    return {"socks_udp_mean_ms":round(udp_ms,4),"dns_mean_ms":round(dns_ms,4),
            "dns_queries":32,"upstream_dns_queries":upstream_queries,
            "dns_tcp_abandon_and_recovery_ms":round(recovery_ms,4)}


def configuration(path,label,port,dns_port,upstream):
    if label=="vp_core":
        path.write_text(f"""mixed-port: {port}
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
rules:
  - MATCH,DIRECT
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  enhanced-mode: redir-host
  nameserver: ["udp://127.0.0.1:{upstream}"]
""")
    elif label=="sing_box":
        path.write_text(json.dumps({
            "log":{"level":"error"},
            "inbounds":[{"type":"mixed","tag":"socks","listen":"127.0.0.1","listen_port":port},
                        {"type":"direct","tag":"dns","listen":"127.0.0.1","listen_port":dns_port}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"rules":[{"inbound":"dns","action":"hijack-dns"}],"final":"direct"},
            "dns":{"servers":[{"type":"udp","tag":"peer","server":"127.0.0.1","server_port":upstream}],
                   "final":"peer"},
        }))
    else:
        path.write_text(f'''schema-version 1
role "client"
workers 2
inbounds {{ mixed "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
dns {{
    listen host="127.0.0.1" port={dns_port}
    server "peer" type="udp" host="127.0.0.1" port={upstream}
    final "peer"
}}
''')


def binary_sha256(path):
    with open(path,"rb") as binary:
        return hashlib.file_digest(binary,"sha256").hexdigest()


def main():
    global BYTES
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vp_core",type=Path)
    parser.add_argument("sing_box",type=Path)
    parser.add_argument("nexus_epoll",type=Path)
    parser.add_argument("nexus_uring",type=Path)
    parser.add_argument("--runs",type=int,default=3)
    parser.add_argument("--cpu",default="0,2")
    parser.add_argument("--mib",type=int,default=16)
    args=parser.parse_args()
    if args.runs<1 or args.mib<1:
        parser.error("--runs and --mib must be positive")
    BYTES=args.mib*1024*1024
    binaries={key:str(getattr(args,key).resolve(strict=True)) for key in ("vp_core","sing_box","nexus_epoll","nexus_uring")}
    print(json.dumps({"kernel":os.uname().release,"proxy_cpu":args.cpu,
        "binary_sha256":{key:binary_sha256(value) for key,value in binaries.items()},
        "bulk_bytes_each_connection":BYTES,"bulk_parallel":4,"concurrent_connections":64}),flush=True)
    with tempfile.TemporaryDirectory() as directory, Origin(("127.0.0.1",0),Handler) as origin, ThreadPoolExecutor(65) as pool, DnsPeer() as dns, Echo() as udp:
        root=Path(directory)
        worker=pool.submit(origin.serve_forever)
        try:
            keys=list(binaries)
            for trial in range(args.runs):
                for label in keys[trial%len(keys):]+keys[:trial%len(keys)]:
                    front,dns_port=reserve(),reserve()
                    extensions={"vp_core":"yaml","sing_box":"json"}
                    path=root/f"proxy.{extensions.get(label,'kdl')}"
                    configuration(path,label,front,dns_port,dns.port)
                    config_flag="-c" if label in extensions else "--config"
                    command=["env","TOKIO_WORKER_THREADS=2","GOMAXPROCS=2","taskset","-c",args.cpu,binaries[label],
                             "run",config_flag,str(path)]
                    if label=="vp_core":
                        command.extend(("-d",str(root)))
                    with running(command,front,root/f"{label}.log") as process:
                        sample=workload(process,front,origin.server_address[1],pool,BYTES)
                        sample.update(packet_workload(front,dns_port,udp,dns,f"{trial}-{label.replace('_','-')}"))
                        print(json.dumps({"implementation":label,"trial":trial+1,**sample}),flush=True)
        finally:
            origin.shutdown()
            worker.result()


if __name__=="__main__":
    main()
