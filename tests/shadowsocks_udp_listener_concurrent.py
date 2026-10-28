"""Exercise concurrent SOCKS UDP associations through the experimental listener."""
import base64
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

fixture=pathlib.Path(sys.argv[1]).resolve()
revision="824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box","version"],check=True,capture_output=True,text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")
def exact(sock,n):
    data=b""
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part: raise RuntimeError("SOCKS EOF")
        data+=part
    return data

with tempfile.TemporaryDirectory(prefix="nexus-udp-concurrent-") as directory:
    for size in (16,32):
        with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as target, socket.socket() as reserve:
            target.bind(("::1",0)); target.settimeout(3)
            reserve.bind(("127.0.0.1",0)); socks_port=reserve.getsockname()[1]; reserve.close()
            errors=[]; sources=set()
            def target_peer():
                try:
                    for _ in range(8):
                        payload,source=target.recvfrom(65535)
                        sources.add(source)
                        target.sendto(payload,source)
                except Exception as exc: errors.append(exc)
            worker=threading.Thread(target=target_peer); worker.start()
            listener=subprocess.Popen([fixture,str(size),"53","allow"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            box=None; clients=[]
            try:
                port=int(listener.stdout.readline())
                config={"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],
                        "outbounds":[{"type":"shadowsocks","tag":"edge","server":"127.0.0.1","server_port":port,
                        "method":f"2022-blake3-aes-{size*8}-gcm","password":base64.b64encode(bytes(range(size))).decode()}],"route":{"final":"edge"}}
                path=pathlib.Path(directory)/"client.json"; path.write_text(json.dumps(config))
                subprocess.run(["sing-box","check","-c",path],check=True,capture_output=True)
                box=subprocess.Popen(["sing-box","run","-c",path],stderr=subprocess.PIPE)
                deadline=time.monotonic()+2
                while True:
                    try: probe=socket.create_connection(("127.0.0.1",socks_port),timeout=.2); probe.close(); break
                    except OSError:
                        if time.monotonic()>deadline: raise
                        time.sleep(.02)
                for i in range(8):
                    tcp=socket.create_connection(("127.0.0.1",socks_port),timeout=2)
                    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind(("127.0.0.1",0)); udp.settimeout(2)
                    clients.append((tcp,udp))
                    tcp.sendall(b"\x05\x01\x00")
                    if exact(tcp,2)!=b"\x05\x00": raise RuntimeError("greeting")
                    tcp.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01"+struct.pack("!H",udp.getsockname()[1]))
                    if exact(tcp,4)!=b"\x05\x00\x00\x01": raise RuntimeError("association")
                    relay=exact(tcp,6); endpoint=("127.0.0.1",struct.unpack("!H",relay[4:])[0])
                    header=b"\x00\x00\x00\x04"+socket.inet_pton(socket.AF_INET6,"::1")+struct.pack("!H",target.getsockname()[1])
                    udp.sendto(header+f"client-{i}".encode(),endpoint)
                for i,(_,udp) in enumerate(clients):
                    result,_=udp.recvfrom(65535)
                    if result!=header+f"client-{i}".encode(): raise RuntimeError(f"wrong reply {i}: {result!r}")
                worker.join(timeout=2)
                if worker.is_alive() or errors or len(sources)!=8: raise RuntimeError(f"targets: {errors}, sources={sources}")
                if listener.wait(timeout=5)!=0: raise RuntimeError(f"listener exit {listener.returncode}: {listener.stderr.read()}")
            finally:
                for tcp,udp in clients: tcp.close(); udp.close()
                if box is not None: box.terminate(); box.communicate(timeout=3)
                if listener.poll() is None: listener.kill(); listener.communicate()
print("SS-2022 UDP eight concurrent IPv6 sessions with sing-box passed")
