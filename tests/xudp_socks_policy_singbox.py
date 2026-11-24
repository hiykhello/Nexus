#!/usr/bin/env python3
"""SOCKS XUDP domain resolution and routing policy against fixed sing-box."""
import argparse
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

parser=argparse.ArgumentParser()
parser.add_argument('nexus')
parser.add_argument('--vision', action='store_true')
parser.add_argument('--ipv6', action='store_true')
args=parser.parse_args()
nexus=pathlib.Path(args.nexus).resolve(); vision=args.vision; ipv6=args.ipv6
revision="824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box","version"],capture_output=True,text=True,check=True).stdout:
    raise RuntimeError("unexpected sing-box revision")
def free_port():
    with socket.socket() as s: s.bind(("127.0.0.1",0)); return s.getsockname()[1]
def exact(sock,n):
    result=b""
    while len(result)<n:
        data=sock.recv(n-len(result))
        if not data: raise RuntimeError("unexpected EOF")
        result+=data
    return result
with tempfile.TemporaryDirectory(prefix="nexus-xudp-policy-") as directory:
    root=pathlib.Path(directory); front=free_port(); listen=free_port(); stop=threading.Event(); queries=[]; packets=[]; errors=[]
    (root/"uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); (root/"uuid").chmod(0o600)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root/"key"), "-out", str(root/"cert"), "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example", "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root/"block.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\nrule type="ip-cidr" value="' + ('::2/128' if ipv6 else '127.0.0.3/32') + '"\n')
    dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); dns.bind(("127.0.0.1",0)); dns.settimeout(.1)
    origins=[]
    for ip in (("::1", "::1") if ipv6 else ("127.0.0.2", "127.0.0.3")):
        sock=socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,socket.SOCK_DGRAM); sock.bind((ip,0)); sock.settimeout(.1); origins.append(sock)
    def serve_dns():
        try:
            while not stop.is_set():
                try: query,peer=dns.recvfrom(512)
                except socket.timeout: continue
                name=query[12:-4].lower(); kind=int.from_bytes(query[-4:-2],"big"); queries.append((name,kind))
                reply=bytearray(query); reply[2:4]=b"\x81\x80"
                if kind==1 and not ipv6:
                    suffix=3 if name==b"\x04deny\x04test\x00" else 2
                    reply[7]=1; reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00"+bytes([suffix]))
                elif kind==28 and ipv6:
                    address='::2' if name==b"\x04deny\x04test\x00" else '::1'
                    reply[7]=1; reply.extend(b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10"+socket.inet_pton(socket.AF_INET6,address))
                elif kind in (1,28):
                    reply[9]=1; reply.extend(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c"+bytes(20))
                dns.sendto(reply,peer)
        except Exception as exc: errors.append(exc)
    def origin(index):
        try:
            while not stop.is_set():
                try: data,peer=origins[index].recvfrom(65535)
                except socket.timeout: continue
                packets.append((index,data)); origins[index].sendto(data,peer)
        except Exception as exc: errors.append(exc)
    threads=[threading.Thread(target=serve_dns,daemon=True)]+[threading.Thread(target=origin,args=(i,),daemon=True) for i in range(2)]
    for thread in threads: thread.start()
    boxconfig={"log":{"level":"error"},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":front,"users":[{"uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f"}],"tls":{"enabled":True,"certificate_path":str(root/"cert"),"key_path":str(root/"key")}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
    if vision: boxconfig["inbounds"][0]["users"][0]["flow"]="xtls-rprx-vision"
    (root/"box.json").write_text(json.dumps(boxconfig))
    flow=' flow "xtls-rprx-vision";' if vision else ''
    (root/"config.kdl").write_text(f'''schema-version 1
role "client"
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={listen}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={front};{flow} authentication {{ uuid-file "{root/'uuid'}"; }}; tls {{ server-name "cover.example"; ca-file "{root/'cert'}"; verify #true; }} }}
routing {{ rule-set "block" path="block.kdl" format="kdl"; rules {{ - kind="rule-set" value="block" outbound="reject"; }}; default-outbound "edge"; }}
''')
    subprocess.run(["sing-box","check","-c",root/"box.json"],capture_output=True,check=True)
    box=subprocess.Popen(["sing-box","run","-c",root/"box.json"],stderr=subprocess.PIPE); proxy=None
    try:
        time.sleep(.4); proxy=subprocess.Popen([nexus,"run","--config",root/"config.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+10
        while True:
            if proxy.poll() is not None: raise RuntimeError(f"proxy exited: {proxy.stderr.read()!r}")
            try: control=socket.create_connection(("127.0.0.1",listen),timeout=.2); break
            except OSError:
                if time.monotonic()>deadline: raise
                time.sleep(.05)
        with control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            control.settimeout(5); client.settimeout(3); client.bind(("127.0.0.1",0))
            control.sendall(b"\x05\x01\x00"); assert exact(control,2)==b"\x05\x00"
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); reply=exact(control,10)
            if reply[:4]!=b"\x05\x00\x00\x01": raise RuntimeError(f"association: {reply!r}")
            relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],"big"))
            def send(name,index,payload):
                name=name.encode(); head=b"\x00\x00\x00\x03"+bytes([len(name)])+name+origins[index].getsockname()[1].to_bytes(2,"big")
                client.sendto(head+payload,relay)
            send("allowed.test",0,b"ok"); response,_=client.recvfrom(65535)
            expected=b"\x00\x00\x00"+(b"\x04"+socket.inet_pton(socket.AF_INET6,"::1") if ipv6 else b"\x01\x7f\x00\x00\x02")+origins[0].getsockname()[1].to_bytes(2,"big")+b"ok"
            if response!=expected: raise RuntimeError(f"domain reply: {response!r}")
            for name,index in (("blocked.test",0),("deny.test",1)):
                send(name,index,name.encode()); client.settimeout(.35)
                try: raise RuntimeError(f"unexpected reply {client.recvfrom(65535)!r}")
                except socket.timeout: pass
            expected_kind=28 if ipv6 else 1
            required={(b"\x07allowed\x04test\x00",expected_kind),(b"\x04deny\x04test\x00",expected_kind)}
            if not required.issubset(set(queries)) or any(name==b"\x07blocked\x04test\x00" for name,_ in queries) or len(packets)!=1 or packets[0]!=(0,b"ok") or errors:
                raise RuntimeError(f"policy failure: queries={queries!r} packets={packets!r} errors={errors!r}")
            client.settimeout(3); send("allowed.test",0,b"again")
            if client.recvfrom(65535)[0]!=expected[:-2]+b"again": raise RuntimeError("association did not recover")
        proxy.terminate(); _,stderr=proxy.communicate(timeout=10)
        if proxy.returncode: raise RuntimeError(f"shutdown: {proxy.returncode} {stderr!r}")
        proxy=None
        print("XUDP domain resolution, domain/IP block and recovery passed")
    finally:
        stop.set()
        for thread in threads: thread.join(timeout=1)
        dns.close()
        for sock in origins: sock.close()
        if proxy: proxy.terminate(); proxy.communicate(timeout=5)
        box.terminate(); box.communicate(timeout=5)
