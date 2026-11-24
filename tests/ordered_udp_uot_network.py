#!/usr/bin/env python3
"""Ordered SOCKS UDP UoT v2 routing and shutdown with sing-box."""
import base64
import concurrent.futures
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
def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0)); return sock.getsockname()[1]
def exact(sock,size):
    data=b""
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError("unexpected SOCKS EOF")
        data+=part
    return data
with tempfile.TemporaryDirectory(prefix="nexus-uot-config-") as directory:
    root=pathlib.Path(directory); front=port(); listen=port()
    key=base64.b64encode(bytes(range(16))).decode(); (root/"key").write_text(key); (root/"key").chmod(0o600)
    (root/"ip.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
    config={"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":front,
            "method":"2022-blake3-aes-128-gcm","password":key}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
    (root/"box.json").write_text(json.dumps(config))
    (root/"nexus.kdl").write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={listen}; authentication "none"; }}
outbound "direct" type="direct"
outbound "first" type="shadowsocks" {{ server host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
outbound "second" type="shadowsocks" {{ server host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; udp-over-tcp "v2"; }}
routing {{ rule-set "second-ip" path="ip.kdl" format="kdl"; tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{ rule action="route" rule-set="second-ip" outbound="second"; rule action="route" outbound="first"; }}; default-outbound "first"; }}
''')
    subprocess.run(["sing-box","check","-c",root/"box.json"],check=True,capture_output=True)
    box=subprocess.Popen(["sing-box","run","-c",root/"box.json"],stderr=subprocess.PIPE)
    proxy=None; sockets=[]; errors=[]; seen=[set(),set(),set()]; stop=threading.Event()
    try:
        for ip in ("127.0.0.1","127.0.0.2"):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind((ip,0)); sock.settimeout(.2); sockets.append(sock)
        sock=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); sock.bind(("::1",0)); sock.settimeout(.2); sockets.append(sock)
        def echo(index):
            while not stop.is_set():
                try:
                    data, peer=sockets[index].recvfrom(65535); seen[index].add(peer); sockets[index].sendto(data,peer)
                except socket.timeout: continue
                except Exception as exc: errors.append(exc); break
        threads=[threading.Thread(target=echo,args=(i,),daemon=True) for i in range(3)]
        for thread in threads: thread.start()
        time.sleep(.4)
        proxy=subprocess.Popen([nexus,"run","--config",root/"nexus.kdl"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+10
        while True:
            if proxy.poll() is not None: raise RuntimeError(f"Nexus exited: {proxy.stderr.read()!r}")
            try:
                with socket.create_connection(("127.0.0.1",listen),timeout=.2): break
            except OSError:
                if time.monotonic()>deadline: raise
                time.sleep(.05)
        def client(index):
            with socket.create_connection(("127.0.0.1",listen),timeout=10) as control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                control.settimeout(10); udp.settimeout(10); udp.bind(("127.0.0.1",0))
                control.sendall(b"\x05\x01\x00")
                if exact(control,2)!=b"\x05\x00": raise RuntimeError("SOCKS greeting")
                control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); response=exact(control,10)
                if response[:4]!=b"\x05\x00\x00\x01": raise RuntimeError("UDP associate")
                relay=(socket.inet_ntoa(response[4:8]),int.from_bytes(response[8:10],"big"))
                for round in range(4):
                    for i in ((2,1,0) if index%2 else (0,1,2)):
                        sock=sockets[i]; addr=sock.getsockname(); data=f"{index}/{round}/{i}".encode()
                        family=socket.AF_INET6 if i==2 else socket.AF_INET
                        head=b"\x00\x00\x00"+(b"\x04" if i==2 else b"\x01")+socket.inet_pton(family,addr[0])+addr[1].to_bytes(2,"big")
                        udp.sendto(head+data,relay)
                        try: result,_=udp.recvfrom(65535)
                        except socket.timeout: raise RuntimeError(f"timeout session={index} round={round} target={i} seen={seen!r} errors={errors!r}")
                        if result!=head+data: raise RuntimeError(f"bad reply {result!r}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for task in [pool.submit(client,i) for i in range(4)]: task.result(timeout=30)
        if errors or len(seen[0])!=4 or len(seen[1])!=4 or len(seen[2])!=4 or seen[0]&seen[1]:
            raise RuntimeError(f"outbound/session isolation: {seen!r}, {errors!r}")
        # Exceed the shared 64-session quota over time to check that closing
        # control connections drains their readers and releases the leases.
        for i in range(70): client(i+10)
        if proxy.poll() is not None or errors: raise RuntimeError(f"proxy failed after churn: {errors!r}")
        proxy.terminate()
        _, stderr=proxy.communicate(timeout=10)
        if proxy.returncode != 0: raise RuntimeError(f"proxy shutdown failed: {proxy.returncode}, {stderr!r}")
        proxy=None
        print("configured UoT v2: dual stack, two outbounds, concurrent sessions, quota recovery and shutdown passed")
    finally:
        stop.set()
        for thread in locals().get("threads",[]): thread.join(timeout=1)
        for sock in sockets: sock.close()
        if proxy:
            proxy.terminate(); proxy.communicate(timeout=5)
        box.terminate(); box.communicate(timeout=5)
