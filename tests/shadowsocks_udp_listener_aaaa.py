"""Exercise experimental SS-2022 UDP listener with sing-box and local DNS."""
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

with tempfile.TemporaryDirectory(prefix="nexus-udp-listener-") as directory:
    for size in (16,32):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as target, socket.socket() as reserve:
            dns.bind(("127.0.0.1",0)); dns.settimeout(5)
            target.bind(("::1",0)); target.settimeout(5)
            reserve.bind(("127.0.0.1",0)); socks_port=reserve.getsockname()[1]; reserve.close()
            errors=[]
            def dns_peer():
                try:
                    for _ in range(2):
                        query,peer=dns.recvfrom(512); kind=int.from_bytes(query[-4:-2],"big")
                        if query[12:20]!=b"\x01a\x04test\x00":
                            raise RuntimeError(f"unexpected DNS name: {query[12:]!r}")
                        response=bytearray(query); response[2:4]=b"\x81\x80"
                        if kind==28:
                            response[7]=1
                            response.extend(b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10"+socket.inet_pton(socket.AF_INET6,"::1"))
                        else:
                            response[9]=1
                            response.extend(b"\xc0\x0e\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0e\xc0\x0e"+bytes(20))
                        dns.sendto(response,peer)
                except Exception as exc: errors.append(exc)
            def target_peer():
                try:
                    for i in range(2):
                        payload,peer=target.recvfrom(65535)
                        if payload!=b"hello"+bytes([48+i]): raise RuntimeError(f"unexpected target payload {payload!r}")
                        target.sendto(payload.upper(),peer)
                except Exception as exc: errors.append(exc)
            threads=[threading.Thread(target=dns_peer),threading.Thread(target=target_peer)]
            for thread in threads: thread.start()
            listener=subprocess.Popen([fixture,str(size),str(dns.getsockname()[1]),"ipv6"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            box=None
            try:
                port=int(listener.stdout.readline())
                config={"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],
                    "outbounds":[{"type":"shadowsocks","tag":"edge","server":"::1","server_port":port,
                    "method":f"2022-blake3-aes-{size*8}-gcm","password":base64.b64encode(bytes(range(size))).decode()}],"route":{"final":"edge"}}
                path=pathlib.Path(directory)/"client.json"; path.write_text(json.dumps(config))
                subprocess.run(["sing-box","check","-c",path],check=True,capture_output=True)
                box=subprocess.Popen(["sing-box","run","-c",path],stderr=subprocess.PIPE)
                deadline=time.monotonic()+2
                while True:
                    try: client=socket.create_connection(("127.0.0.1",socks_port),timeout=.2); break
                    except OSError:
                        if time.monotonic()>deadline: raise
                        time.sleep(.02)
                with client,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    client.settimeout(2); udp.bind(("127.0.0.1",0)); udp.settimeout(2)
                    client.sendall(b"\x05\x01\x00"); assert exact(client,2)==b"\x05\x00"
                    client.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01"+struct.pack("!H",udp.getsockname()[1]))
                    assert exact(client,4)==b"\x05\x00\x00\x01"
                    relay=exact(client,6); endpoint=("127.0.0.1",struct.unpack("!H",relay[4:])[0])
                    port_bytes=struct.pack("!H",target.getsockname()[1])
                    headers=[b"\x00\x00\x00\x04"+socket.inet_pton(socket.AF_INET6,"::1")+port_bytes,
                             b"\x00\x00\x00\x03\x06a.test"+port_bytes]
                    for i,header in enumerate(headers):
                        udp.sendto(header+b"hello"+bytes([48+i]),endpoint)
                        try: response,_=udp.recvfrom(65535)
                        except TimeoutError as exc:
                            raise RuntimeError(f"timeout at packet {i}; listener={listener.poll()}, errors={errors}") from exc
                        if not response.endswith(b"HELLO"+bytes([48+i])): raise RuntimeError(f"response {response!r}")
                    # Leave a separate DNS request pending while the listener stops.
                    pending_header=b"\x00\x00\x00\x03\x06b.test"+port_bytes
                    udp.sendto(pending_header+b"pending",endpoint)
                    udp.settimeout(4)
                    try:
                        udp.recvfrom(65535)
                        raise RuntimeError("pending DNS request unexpectedly forwarded")
                    except TimeoutError:
                        pass
                if listener.wait(timeout=5)!=0: raise RuntimeError(f"listener exit {listener.returncode}: {listener.stderr.read()}")
                for thread in threads: thread.join(timeout=1)
                if errors or any(thread.is_alive() for thread in threads): raise RuntimeError(f"peer failure {errors}")
            finally:
                if box is not None: box.terminate(); box.communicate(timeout=3)
                if listener.poll() is None: listener.kill(); listener.communicate()
print("SS-2022 IPv6 UDP listener, AAAA DNS and sing-box passed")
