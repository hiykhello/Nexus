"""A changed bootstrap address must select a different message-cache view."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

def udp(address, port=0):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind((address,port));sock.settimeout(.2);return sock

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0));return sock.getsockname()[1]

bootstrap=udp("127.0.0.1");first=udp("127.0.0.1");second=udp("127.0.0.2",first.getsockname()[1])
listen,proxy=free_port(),free_port()
while proxy==listen:proxy=free_port()
config=f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={listen}; server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap.getsockname()[1]}; server "remote" type="udp" host="resolver.test" port={first.getsockname()[1]} domain-resolver="bootstrap"; final "remote"; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
'''
stop=threading.Event();selected=[1];counts=[0,0];failures=[]
def serve(sock,kind):
    try:
        while not stop.is_set():
            try: request,peer=sock.recvfrom(65535)
            except TimeoutError:continue
            reply=bytearray(request);reply[2:4]=b"\x81\x80"
            if kind==0:
                if request[-4:-2]==b"\0\1":
                    reply[7]=1;reply.extend(bytes.fromhex("c00c000100010000003c0004")+bytes([127,0,0,selected[0]]))
                else:
                    reply[7]=1;reply.extend(bytes.fromhex("c00c001c00010000003c001000000000000000000000000000000001"))
            else:
                counts[kind-1]+=1;reply[7]=1
                reply.extend(bytes.fromhex("c00c000100010000003c0004c00002")+bytes([kind]))
            sock.sendto(reply,peer)
    except Exception as error:failures.append(error)

threads=[threading.Thread(target=serve,args=(sock,kind)) for sock,kind in ((bootstrap,0),(first,1),(second,2))]
for thread in threads:thread.start()
with tempfile.TemporaryDirectory() as directory:
    path=Path(directory)/"config.kdl";path.write_text(config)
    process=subprocess.Popen([str(Path(sys.argv[1]).resolve()),"run","--config",str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for _ in range(80):
            if process.poll() is not None:raise RuntimeError(process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1",listen),timeout=.1):break
            except OSError:time.sleep(.05)
        else:raise RuntimeError("listener failed to start")
        def query(ident):
            request=struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+bytes.fromhex("076578616d706c6504746573740000010001")
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(5);client.sendto(request,("127.0.0.1",listen));reply,_=client.recvfrom(4096)
            assert reply[:2]==request[:2] and reply[3]&15==0,reply.hex()
            return reply[-1]
        assert query(1)==1 and query(2)==1 and counts==[1,0],counts
        selected[0]=2
        assert query(3)==2 and query(4)==2 and counts==[1,1],counts
    finally:
        process.terminate();_,err=process.communicate(timeout=8)
        stop.set()
        for thread in threads:thread.join(timeout=3)
        for sock in (bootstrap,first,second):sock.close()
        if process.returncode:raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
assert not failures and all(not thread.is_alive() for thread in threads),failures
print("DNS message cache follows bootstrap endpoint changes")
