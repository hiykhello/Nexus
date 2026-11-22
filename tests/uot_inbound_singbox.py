#!/usr/bin/env python3
"""Pinned sing-box UoT client through a Nexus SS-2022 inbound."""
import argparse
import base64
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("nexus",type=pathlib.Path)
parser.add_argument("--fixture",type=pathlib.Path,help="path to the separate UoT fixture")
modes=parser.add_mutually_exclusive_group()
for mode in ("chain","xudp","xudp-vision","xudp-empty"):
    modes.add_argument("--"+mode,action="store_true")
args=parser.parse_args()
nexus=args.nexus.resolve()
fixture=args.fixture.resolve() if args.fixture else nexus.with_name("nexus-proxy-uot-fixture")
chain=args.chain or args.xudp or args.xudp_vision or args.xudp_empty
xudp=args.xudp or args.xudp_vision or args.xudp_empty
vision=args.xudp_vision
empty_probe=args.xudp_empty
revision="824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box","version"],capture_output=True,text=True,check=True).stdout:
    raise RuntimeError("unexpected sing-box revision")
def port():
    with socket.socket() as s: s.bind(("127.0.0.1",0)); return s.getsockname()[1]
def exact(sock,n):
    data=b""
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part: raise RuntimeError("SOCKS EOF")
        data+=part
    return data
with tempfile.TemporaryDirectory(prefix="nexus-uot-inbound-") as directory:
    root=pathlib.Path(directory); ssport=port(); socksport=port(); upstream_port=port()
    key=base64.b64encode(bytes(range(16))).decode(); (root/"key").write_text(key); (root/"key").chmod(0o600)
    if xudp:
        (root/"uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); (root/"uuid").chmod(0o600)
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(root/"tls-key"),"-out",str(root/"cert"),"-subj","/CN=cover.example","-addext","subjectAltName=DNS:cover.example","-days","1"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    edge=(f'outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={upstream_port}; method "2022-blake3-aes-128-gcm"; key-file "{root/"key"}"; udp-over-tcp "v2"; }}' if chain else '')
    if xudp:
        flow=' flow "xtls-rprx-vision";' if vision else ''
        edge=f'outbound "edge" type="vless" {{ server host="127.0.0.1" port={upstream_port};{flow} authentication {{ uuid-file "{root/"uuid"}"; }}; tls {{ server-name "cover.example"; ca-file "{root/"cert"}"; verify #true; }} }}'
    (root/"nexus.kdl").write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={ssport}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }} }}
outbound "direct" type="direct"
outbound "reject" type="block"
{edge}
routing {{ default-outbound "{'edge' if chain else 'direct'}"; }}
''')
    config={"log":{"level":"error"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socksport}],
            "outbounds":[{"type":"shadowsocks","tag":"edge","server":"127.0.0.1","server_port":ssport,
                          "method":"2022-blake3-aes-128-gcm","password":key,"udp_over_tcp":{"enabled":True,"version":2}}],
            "route":{"final":"edge"}}
    (root/"box.json").write_text(json.dumps(config))
    subprocess.run(["sing-box","check","-c",root/"box.json"],capture_output=True,check=True)
    origins=[]; errors=[]; packets=[]; stop=threading.Event(); threads=[]
    for family,host in ((socket.AF_INET,"127.0.0.1"),(socket.AF_INET6,"::1")):
        sock=socket.socket(family,socket.SOCK_DGRAM); sock.bind((host,0)); sock.settimeout(.1); origins.append(sock)
        def echo(s=sock):
            try:
                while not stop.is_set():
                    try: data,peer=s.recvfrom(65535)
                    except socket.timeout: continue
                    packets.append((s.family,data)); s.sendto(data,peer)
            except Exception as exc: errors.append(exc)
        thread=threading.Thread(target=echo,daemon=True); thread.start(); threads.append(thread)
    server=box=upstream=None
    try:
        if chain:
            upstream_config={"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":upstream_port,"method":"2022-blake3-aes-128-gcm","password":key}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
            if xudp:
                user={"uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f"}
                if vision: user["flow"]="xtls-rprx-vision"
                upstream_config["inbounds"]=[{"type":"vless","listen":"127.0.0.1","listen_port":upstream_port,"users":[user],"tls":{"enabled":True,"certificate_path":str(root/"cert"),"key_path":str(root/"tls-key")}}]
            (root/"upstream.json").write_text(json.dumps(upstream_config))
            subprocess.run(["sing-box","check","-c",root/"upstream.json"],capture_output=True,check=True)
            upstream=subprocess.Popen(["sing-box","run","-c",root/"upstream.json"],stderr=subprocess.PIPE)
        server=subprocess.Popen([nexus,"run","--config",root/"nexus.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+5
        while True:
            if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1",ssport),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        box=subprocess.Popen(["sing-box","run","-c",root/"box.json"],stderr=subprocess.PIPE)
        deadline=time.monotonic()+5
        while True:
            if box.poll() is not None: raise RuntimeError(f"sing-box exited: {box.stderr.read()!r}")
            try: control=socket.create_connection(("127.0.0.1",socksport),timeout=.2); break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        with control,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            control.settimeout(5); client.settimeout(5); client.bind(("127.0.0.1",0))
            control.sendall(b"\x05\x01\x00"); assert exact(control,2)==b"\x05\x00"
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); result=exact(control,10)
            if result[:4]!=b"\x05\x00\x00\x01": raise RuntimeError(f"association: {result!r}")
            host=socket.inet_ntoa(result[4:8]); relay=("127.0.0.1" if host=="0.0.0.0" else host,int.from_bytes(result[8:10],"big"))
            for i,sock in enumerate(origins):
                family=socket.AF_INET if i==0 else socket.AF_INET6
                header=b"\x00\x00\x00"+bytes([1 if i==0 else 4])+socket.inet_pton(family,sock.getsockname()[0])+sock.getsockname()[1].to_bytes(2,"big")
                for payload in ((b"one",b"",b"last") if not xudp or empty_probe else (b"one",b"last")):
                    client.sendto(header+payload,relay)
                    if xudp and not payload:
                        client.settimeout(.5)
                        try: raise RuntimeError(f"unexpected empty reply: {client.recvfrom(65535)!r}")
                        except socket.timeout: pass
                        finally: client.settimeout(5)
                        continue
                    response=client.recvfrom(65535)[0]
                    if response!=header+payload: raise RuntimeError(f"reply: {response!r}")
        # The low-level fixture exercises both request modes explicitly.
        for mode in ("1","0"):
            result=subprocess.run([fixture,str(ssport),str(origins[0].getsockname()[1]),mode],capture_output=True,timeout=20)
            if result.returncode: raise RuntimeError(f"UoT request mode {mode}: {result.returncode} {result.stderr!r}")
        if empty_probe:
            before=len(packets)
            try:
                result=subprocess.run([fixture,str(ssport),str(origins[0].getsockname()[1]),"0","h"],capture_output=True,timeout=3)
                if result.returncode: raise RuntimeError(f"empty UoT fixture exit {result.returncode}: {result.stderr!r}")
                raise RuntimeError("empty packet unexpectedly echoed; update the interoperability expectation")
            except subprocess.TimeoutExpired:
                pass
            if any(family==socket.AF_INET and not data for family,data in packets[before:]):
                raise RuntimeError("origin received the empty packet; reply-path loss needs investigation")
        if errors: raise RuntimeError(errors)
        server.terminate(); _,stderr=server.communicate(timeout=10)
        if server.returncode: raise RuntimeError(f"server shutdown: {stderr!r}")
        server=None
        path = ('via Vision XUDP' if vision else 'via XUDP') if xudp else ('via UoT outbound' if chain else 'direct')
        details = ('IPv4/IPv6, origin did not receive empty UoT packet; nonempty recovery, and both request modes' if empty_probe else 'IPv4/IPv6 and both request modes') if xudp else 'IPv4/IPv6, empty datagrams and both request modes'
        print(f"sing-box UoT v2 -> Nexus SS-2022 inbound {path}: {details} passed")
    finally:
        stop.set()
        for thread in threads: thread.join(timeout=1)
        for sock in origins: sock.close()
        for process in (box,server,upstream):
            if process and process.poll() is None: process.terminate(); process.communicate(timeout=5)
