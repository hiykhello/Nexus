"""Check DNS drop and reply actions on UDP and persistent TCP."""
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0));return sock.getsockname()[1]

listen,proxy=port(),port()
while listen==proxy:proxy=port()
config=f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={listen}; server "unused" type="udp" host="127.0.0.1" port=53;
 rule domain="drop.test" action="reject" reject-method="drop";
 rule domain="refused.test" action="reject" reject-method="reply";
 rule query-class="CH" action="reject";
 rule action="predefined" {{ record section="answer" name="@" type=1 address="192.0.2.1"; }}
}}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
'''
def query(name,ident):
    question=b"".join(bytes([len(label)])+label.encode() for label in name.split("."))+b"\0\0\1\0\1"
    return struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+question

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
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(.3);client.sendto(query("drop.test",1),("127.0.0.1",listen))
            try:response,_=client.recvfrom(4096);raise AssertionError(response.hex())
            except TimeoutError:pass
            client.settimeout(3);client.sendto(query("refused.test",2),("127.0.0.1",listen));response,_=client.recvfrom(4096)
            assert response[:2]==b"\0\2" and response[3]&15==5,response.hex()
            chaos=query("ok.test",5)[:-2]+b"\0\3";client.sendto(chaos,("127.0.0.1",listen));response,_=client.recvfrom(4096)
            assert response[:2]==b"\0\5" and response[3]&15==5,response.hex()
        with socket.create_connection(("127.0.0.1",listen),timeout=3) as client:
            a=query("drop.test",3);b=query("ok.test",4)
            client.sendall(struct.pack("!H",len(a))+a+struct.pack("!H",len(b))+b)
            header=client.recv(2);assert len(header)==2
            size=struct.unpack("!H",header)[0];response=b""
            while len(response)<size:
                data=client.recv(size-len(response));assert data;response+=data
            assert response[:2]==b"\0\4" and response[3]&15==0 and response[-4:]==bytes([192,0,2,1]),response.hex()
    finally:
        process.terminate();_,err=process.communicate(timeout=8)
        if process.returncode:raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
print("DNS reject drop/reply and TCP continuation passed")
