"""Exercise message cache, query isolation and cache bypass through the CLI."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upstream.bind(("127.0.0.1", 0)); upstream.settimeout(.2)
listen, proxy = free_port(), free_port()
while proxy == listen: proxy = free_port()
config = f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={listen}; server "a" type="udp" host="127.0.0.1" port={upstream.getsockname()[1]}; rule domain="bypass.test" action="route" server="a" disable-cache=#true; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
'''
requests = []; stopping = threading.Event(); failures = []
def server():
    try:
        while not stopping.is_set():
            try: request, peer = upstream.recvfrom(65535)
            except TimeoutError: continue
            requests.append(request)
            end=12
            while request[end]: end += request[end]+1
            end+=5
            response=bytearray(request[:end]);response[2:4]=b"\x81\x80";response[7]=1;response[10:12]=b"\0\0"
            if request[13:23]==b"irrelevant":
                response.extend(bytes.fromhex("c017000100010000003c0004c0000201"))
                upstream.sendto(response,peer);continue
            if request[13:21]==b"negative":
                response[3]=0x83;response[7]=0;response[9]=1
                response.extend(bytes.fromhex("c015000600010000003c0018c00cc00c0000000100000002000000030000000400000003"))
                upstream.sendto(response,peer);continue
            response.extend(bytes.fromhex("c00c000100010000000a0004c0000201"))
            upstream.sendto(response,peer)
    except Exception as error: failures.append(error)

def query(name, ident, cd=False, option=False):
    question=b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\0\0\1\0\1"
    header=struct.pack("!HHHHHH",ident,0x0110 if cd else 0x0100,1,0,0,int(option))
    opt=bytes.fromhex("00002904d0000000000004fde80000") if option else b""
    return header+question+opt, len(header+question)

with tempfile.TemporaryDirectory() as directory:
    path=Path(directory)/"config.kdl";path.write_text(config)
    process=subprocess.Popen([str(Path(sys.argv[1]).resolve()),"run","--config",str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    worker=threading.Thread(target=server);worker.start()
    try:
        for _ in range(80):
            if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1",listen),timeout=.1): break
            except OSError: time.sleep(.05)
        else: raise RuntimeError("DNS listener failed to start")
        def exchange(name,ident,cd=False,option=False,tcp=False):
            request,offset=query(name,ident,cd,option)
            if tcp:
                with socket.create_connection(("127.0.0.1",listen),timeout=3) as client:
                    client.sendall(struct.pack("!H",len(request))+request)
                    header=client.recv(2);assert len(header)==2
                    size=struct.unpack("!H",header)[0];response=b""
                    while len(response)<size:
                        data=client.recv(size-len(response));assert data;response+=data
            else:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.settimeout(3);client.sendto(request,("127.0.0.1",listen));response,_=client.recvfrom(4096)
            assert response[:2]==request[:2] and response[3]&15==0,response.hex()
            return struct.unpack_from("!I",response,offset+6)[0]
        assert exchange("cache.test",1)==10
        time.sleep(1.05)
        assert 0 < exchange("cache.test",2,tcp=True) < 10
        assert len(requests)==1
        assert exchange("cache.test",3,cd=True)==10
        assert exchange("cache.test",4,option=True)==10
        assert exchange("cache.test",5,option=True)==10
        assert exchange("bypass.test",6)==10
        assert exchange("bypass.test",7)==10
        assert len(requests)==6,len(requests)
        request,offset=query("negative.test",20)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(4);client.sendto(request,("127.0.0.1",listen));first,_=client.recvfrom(4096)
            assert first[3]&15==3 and struct.unpack_from("!I",first,offset+6)[0]==60,first.hex()
            time.sleep(1.05)
            client.sendto(bytes.fromhex("0015")+request[2:],("127.0.0.1",listen));cached,_=client.recvfrom(4096)
            assert cached[:2]==bytes.fromhex("0015") and cached[3]&15==3,cached.hex()
            assert 0<struct.unpack_from("!I",cached,offset+6)[0]<=2,cached.hex()
        assert len(requests)==7,len(requests)
        assert exchange("irrelevant.test",22)==60
        assert exchange("irrelevant.test",23)==60 and len(requests)==9,len(requests)
    finally:
        process.terminate();_,err=process.communicate(timeout=8)
        stopping.set();worker.join(timeout=3);upstream.close()
        if process.returncode: raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
    assert not worker.is_alive() and not failures,failures
print("DNS message cache TTL, TCP reuse, query isolation and bypass passed")
