#!/usr/bin/env python3
"""UoT inbound domain preflight, resolved-IP policy and recovery."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

nexus=pathlib.Path(sys.argv[1]).resolve(); fixture=nexus.with_name("nexus-proxy-uot-fixture")
chain=len(sys.argv)>2 and sys.argv[2] in ("--chain","--xudp","--xudp-vision")
xudp=len(sys.argv)>2 and sys.argv[2] in ("--xudp","--xudp-vision")
vision=len(sys.argv)>2 and sys.argv[2]=="--xudp-vision"
if chain:
    revision="824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box","version"],capture_output=True,text=True,check=True).stdout: raise RuntimeError("unexpected sing-box revision")
with tempfile.TemporaryDirectory(prefix="nexus-uot-inbound-policy-") as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as allowed, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as denied:
    root=pathlib.Path(directory); dns.bind(("127.0.0.1",0)); dns.settimeout(.1)
    allowed.bind(("127.0.0.2",0)); allowed.settimeout(.1)
    denied.bind(("127.0.0.3",allowed.getsockname()[1])); denied.settimeout(.1)
    with socket.socket() as reserve: reserve.bind(("127.0.0.1",0)); port=reserve.getsockname()[1]
    with socket.socket() as reserve: reserve.bind(("127.0.0.1",0)); edge_port=reserve.getsockname()[1]
    key=base64.b64encode(bytes(range(16))).decode(); (root/"key").write_text(key); (root/"key").chmod(0o600)
    edge=(f'outbound "edge" type="shadowsocks" {{ server host="edge.test" port={edge_port}; bootstrap-resolver "dns"; method "2022-blake3-aes-128-gcm"; key-file "{root/"key"}"; udp-over-tcp "v2"; }}' if chain else '')
    if xudp:
        (root/"uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); (root/"uuid").chmod(0o600)
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(root/"tls-key"),"-out",str(root/"cert"),"-subj","/CN=cover.example","-addext","subjectAltName=DNS:cover.example","-days","1"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        flow=' flow "xtls-rprx-vision";' if vision else ''
        edge=f'outbound "edge" type="vless" {{ server host="edge.test" port={edge_port}; bootstrap-resolver "dns";{flow} authentication {{ uuid-file "{root/"uuid"}"; }}; tls {{ server-name "cover.example"; ca-file "{root/"cert"}"; verify #true; }} }}'
    if "--inbound" in sys.argv:
        rules='''schema-version 2
kind "predicate"
rule type="and" { rule type="inbound" value="ss"; rule type="domain-suffix" value="blocked.test"; }
rule type="and" { rule type="inbound" value="ss"; rule type="ip-cidr" value="127.0.0.3/32"; }
'''
    elif "--source" in sys.argv:
        rules='''schema-version 2
kind "predicate"
rule type="and" { rule type="source-ip-cidr" value="127.0.0.0/8"; rule type="source-port-range" value="1-65535"; rule type="domain-suffix" value="blocked.test"; }
rule type="and" { rule type="source-ip-cidr" value="127.0.0.0/8"; rule type="ip-cidr" value="127.0.0.3/32"; }
'''
    else:
        rules='schema-version 2\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\nrule type="ip-cidr" value="127.0.0.3/32"\n'
    (root/"block.kdl").write_text(rules)
    (root/"server.kdl").write_text(f'''schema-version 1
role "server"
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; }}
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }} }}
outbound "direct" type="direct"
outbound "reject" type="block"
{edge}
routing {{ rulesets {{ "block" path="block.kdl" format="kdl"; }}; rules {{ - kind="rule-set" value="block" outbound="reject"; }}; final "{'edge' if chain else 'direct'}"; }}
''')
    stop=threading.Event(); queries=[]; events=[]; packets=[]; errors=[]
    def serve_dns():
        try:
            while not stop.is_set():
                try: query,peer=dns.recvfrom(512)
                except socket.timeout: continue
                name=query[12:-4].lower(); kind=int.from_bytes(query[-4:-2],"big"); queries.append((name,kind)); events.append(("start",name,kind))
                reply=bytearray(query); reply[2:4]=b"\x81\x80"
                if kind==1:
                    suffix=1 if name==b"\x04edge\x04test\x00" else 3 if name==b"\x04deny\x04test\x00" else 2
                    reply[7]=1; reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00"+bytes([suffix]))
                elif kind==28:
                    reply[9]=1; reply.extend(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c"+bytes(20))
                if name in (b"\x04deny\x04test\x00",b"\x04edge\x04test\x00"): time.sleep(.15)
                dns.sendto(reply,peer); events.append(("finish",name,kind))
        except Exception as exc: errors.append(exc)
    def origin(sock,index):
        try:
            while not stop.is_set():
                try: data,peer=sock.recvfrom(65535)
                except socket.timeout: continue
                packets.append((index,data)); sock.sendto(data,peer)
        except Exception as exc: errors.append(exc)
    threads=[threading.Thread(target=serve_dns,daemon=True),threading.Thread(target=origin,args=(allowed,0),daemon=True),threading.Thread(target=origin,args=(denied,1),daemon=True)]
    for thread in threads: thread.start()
    server=upstream=None
    try:
        if chain:
            config={"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":edge_port,"method":"2022-blake3-aes-128-gcm","password":key}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
            if xudp:
                user={"uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f"}
                if vision: user["flow"]="xtls-rprx-vision"
                config["inbounds"]=[{"type":"vless","listen":"127.0.0.1","listen_port":edge_port,"users":[user],"tls":{"enabled":True,"certificate_path":str(root/"cert"),"key_path":str(root/"tls-key")}}]
            (root/"box.json").write_text(json.dumps(config))
            subprocess.run(["sing-box","check","-c",root/"box.json"],capture_output=True,check=True)
            upstream=subprocess.Popen(["sing-box","run","-c",root/"box.json"],stderr=subprocess.PIPE)
        server=subprocess.Popen([nexus,"run","--config",root/"server.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+5
        while True:
            if server.poll() is not None: raise RuntimeError(f"server exited: {server.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        result=subprocess.run([fixture,str(port),str(allowed.getsockname()[1]),"0","policy"],capture_output=True,timeout=20)
        if result.returncode: raise RuntimeError(f"fixture failed: {result.returncode} {result.stderr!r} queries={queries!r} packets={packets!r}")
        if any(name==b"\x07blocked\x04test\x00" for name,_ in queries) or not any(name==b"\x04deny\x04test\x00" for name,_ in queries) or packets!=[(0,b"uot-probe"),(0,b"uot-probe")] or errors:
            raise RuntimeError(f"policy failure: queries={queries!r} packets={packets!r} errors={errors!r}")
        if chain and not any(name==b"\x04edge\x04test\x00" for name,_ in queries): raise RuntimeError("bootstrap DNS was not queried")
        if chain:
            edge_finish=max(i for i,event in enumerate(events) if event[0]=="finish" and event[1]==b"\x04edge\x04test\x00")
            later_start=next(i for i,event in enumerate(events) if event[0]=="start" and event[1]==b"\x05later\x04test\x00")
            if edge_finish>=later_start: raise RuntimeError(f"bootstrap and next target overlapped: {events!r}")
        server.terminate(); _,stderr=server.communicate(timeout=5)
        if server.returncode: raise RuntimeError(f"shutdown failed: {stderr!r}")
        server=None
        print(f"UoT inbound domain preflight, resolved-IP block and same-stream recovery {'via XUDP bootstrap' if xudp else 'via bootstrap tunnel' if chain else 'direct'} passed")
    finally:
        stop.set()
        for thread in threads: thread.join(timeout=1)
        if server and server.poll() is None: server.terminate(); server.communicate(timeout=5)
        if upstream and upstream.poll() is None: upstream.terminate(); upstream.communicate(timeout=5)
