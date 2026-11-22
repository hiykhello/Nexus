#!/usr/bin/env python3
"""SOCKS UoT domain routing, denial and opt-in against fixed sing-box."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
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
with tempfile.TemporaryDirectory(prefix="nexus-uot-policy-") as directory:
    root=pathlib.Path(directory); front=free_port(); listen=free_port(); stop=threading.Event(); queries=[]; packets=[]; errors=[]
    key=base64.b64encode(bytes(range(16))).decode(); (root/"key").write_text(key); (root/"key").chmod(0o600)
    (root/"block.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\nrule type="ip-cidr" value="127.0.0.3/32"\n')
    (root/"disabled.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.4/32"\n')
    dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); dns.bind(("127.0.0.1",0)); dns.settimeout(.1)
    origins=[]
    for ip in ("127.0.0.2","127.0.0.3","127.0.0.4"):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind((ip,0)); sock.settimeout(.1); origins.append(sock)
    def serve_dns():
        try:
            while not stop.is_set():
                try: query,peer=dns.recvfrom(512)
                except socket.timeout: continue
                name=query[12:-4].lower(); kind=int.from_bytes(query[-4:-2],"big"); queries.append((name,kind))
                reply=bytearray(query); reply[2:4]=b"\x81\x80"
                if kind==1:
                    suffix=3 if name==b"\x04deny\x04test\x00" else 4 if name==b"\x08disabled\x04test\x00" else 2
                    reply[7]=1; reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00"+bytes([suffix]))
                elif kind==28:
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
    threads=[threading.Thread(target=serve_dns,daemon=True)]+[threading.Thread(target=origin,args=(i,),daemon=True) for i in range(3)]
    for thread in threads: thread.start()
    boxconfig={"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":front,"method":"2022-blake3-aes-128-gcm","password":key}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
    (root/"box.json").write_text(json.dumps(boxconfig))
    (root/"config.kdl").write_text(f'''schema-version 1
role "client"
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; }}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={listen}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
outbound "edge" type="shadowsocks" {{ server host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
outbound "off" type="shadowsocks" {{ server host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
routing {{ rule-set "block" path="block.kdl" format="kdl"; rule-set "off" path="disabled.kdl" format="kdl"; rule kind="rule-set" value="block" outbound="reject"; rule kind="rule-set" value="off" outbound="off"; default-outbound "edge"; }}
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
            expected=b"\x00\x00\x00\x01\x7f\x00\x00\x02"+origins[0].getsockname()[1].to_bytes(2,"big")+b"ok"
            if response!=expected: raise RuntimeError(f"domain reply: {response!r}")
            for name,index in (("blocked.test",0),("deny.test",1),("disabled.test",2)):
                send(name,index,name.encode()); client.settimeout(.35)
                try: raise RuntimeError(f"unexpected reply {client.recvfrom(65535)!r}")
                except socket.timeout: pass
            if any(name==b"\x07blocked\x04test\x00" for name,_ in queries) or len(packets)!=1 or packets[0]!=(0,b"ok") or errors:
                raise RuntimeError(f"policy failure: queries={queries!r} packets={packets!r} errors={errors!r}")
            client.settimeout(3); send("allowed.test",0,b"again")
            if client.recvfrom(65535)[0]!=expected[:-2]+b"again": raise RuntimeError("association did not recover")
        proxy.terminate(); _,stderr=proxy.communicate(timeout=10)
        if proxy.returncode: raise RuntimeError(f"shutdown: {proxy.returncode} {stderr!r}")
        proxy=None
        print("UoT domain resolution, domain/IP block, opt-in denial and recovery passed")
    finally:
        stop.set()
        for thread in threads: thread.join(timeout=1)
        dns.close()
        for sock in origins: sock.close()
        if proxy: proxy.terminate(); proxy.communicate(timeout=5)
        box.terminate(); box.communicate(timeout=5)
