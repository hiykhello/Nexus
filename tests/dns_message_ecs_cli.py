"""Check ECS response validation and exact-prefix cache isolation."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0));return sock.getsockname()[1]

upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.bind(("127.0.0.1",0));upstream.settimeout(.2)
listen,proxy=port(),port()
while listen==proxy:proxy=port()
config=f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={listen}; server "a" type="udp" host="127.0.0.1" port={upstream.getsockname()[1]}; rule domain="synthetic.test" action="predefined" {{ record section="answer" name="@" type=1 address="192.0.2.1" ttl=60; }} }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
'''
stopping=threading.Event();received=[];failures=[]
def serve():
    try:
        while not stopping.is_set():
            try: request,peer=upstream.recvfrom(65535)
            except TimeoutError:continue
            received.append(request);end=12
            while request[end]:end+=request[end]+1
            end+=5
            if request[13:18]==b"retry" and bytes.fromhex("00080007") in request[end:]:
                reply=bytearray(request[:end]);reply[2:4]=b"\x81\x85";reply[10:12]=b"\0\0"
                upstream.sendto(reply,peer);continue
            reply=bytearray(request[:end]);reply[2:4]=b"\x81\x80";reply[7]=1;reply[10:12]=b"\0\1"
            reply.extend(bytes.fromhex("c00c000100010000003c0004c0000201"))
            if request[13:19]==b"middle":
                reply[10:12]=b"\0\2";reply.extend(bytes.fromhex("00002904d0000000000000"))
                reply.extend(bytes.fromhex("c00c000100010000003c0004c0000202"));upstream.sendto(reply,peer);continue
            if request[13:19]==b"unsafe":
                reply[10:12]=b"\0\3";reply.extend(bytes.fromhex("00002904d0000000000000"))
                target=len(reply);reply.extend(bytes.fromhex("046c617465047465737400000100010000003c0004c0000202"))
                reply.extend(struct.pack("!H",0xc000|target)+bytes.fromhex("000100010000003c0004c0000203"))
                upstream.sendto(reply,peer);continue
            if request[13:19]==b"opaque":
                reply[10:12]=b"\0\2";reply.extend(bytes.fromhex("00002904d0000000000000"))
                reply.extend(bytes.fromhex("c00cfde800010000003c0002c0ff"));upstream.sendto(reply,peer);continue
            if request[13:18]==b"rdata":
                reply[10:12]=b"\0\3";reply.extend(bytes.fromhex("00002904d0000000000000"))
                target=len(reply);reply.extend(bytes.fromhex("046c617465047465737400000100010000003c0004c0000202"))
                reply.extend(bytes.fromhex("c00c000500010000003c0002")+struct.pack("!H",0xc000|target))
                upstream.sendto(reply,peer);continue
            if request[13:18]==b"chaos":
                reply[10:12]=b"\0\4";reply.extend(bytes.fromhex("00002904d0000000000000"))
                target=len(reply);reply.extend(bytes.fromhex("046c617465047465737400000100010000003c0004c0000202"))
                reply.extend(bytes.fromhex("c00c000100030000003c0004"));name_offset=len(reply)
                reply.extend(struct.pack("!H",0xc000|target)+bytes.fromhex("1234"))
                reply.extend(struct.pack("!H",0xc000|name_offset)+bytes.fromhex("000100010000003c0004c0000203"))
                upstream.sendto(reply,peer);continue
            if request[13:18]==b"minfo":
                reply[10:12]=b"\0\4";reply.extend(bytes.fromhex("00002904d0000000000000"))
                target=len(reply);reply.extend(bytes.fromhex("046c617465047465737400000100010000003c0004c0000202"))
                reply.extend(bytes.fromhex("c00c000e00010000003c0004"));name_offset=len(reply)
                reply.extend(struct.pack("!H",0xc000|target)+b"\xc0\x0c")
                reply.extend(struct.pack("!H",0xc000|name_offset)+bytes.fromhex("000100010000003c0004c0000203"))
                upstream.sendto(reply,peer);continue
            if request[13:16]==b"srv":
                reply[10:12]=b"\0\3";reply.extend(bytes.fromhex("00002904d0000000000000"))
                reply.extend(bytes.fromhex("c00c002100010000003c0011c0ff00010035"));name_offset=len(reply)
                reply.extend(bytes.fromhex("046c617465047465737400"))
                reply.extend(struct.pack("!H",0xc000|name_offset)+bytes.fromhex("000100010000003c0004c0000203"))
                upstream.sendto(reply,peer);continue
            if request[13:15]==b"rp":
                reply[10:12]=b"\0\3";reply.extend(bytes.fromhex("00002904d0000000000000"))
                reply.extend(bytes.fromhex("c00c001100010000003c000d"));name_offset=len(reply)
                reply.extend(bytes.fromhex("046c617465047465737400c00c"))
                reply.extend(struct.pack("!H",0xc000|name_offset)+bytes.fromhex("000100010000003c0004c0000203"))
                upstream.sendto(reply,peer);continue
            if request[13:17]==b"svcb":
                reply[10:12]=b"\0\3";reply.extend(bytes.fromhex("00002904d0000000000000"))
                reply.extend(bytes.fromhex("c00c004000010000003c00130001"));name_offset=len(reply)
                reply.extend(bytes.fromhex("046c61746504746573740000010002c0ff"))
                reply.extend(struct.pack("!H",0xc000|name_offset)+bytes.fromhex("000100010000003c0004c0000203"))
                upstream.sendto(reply,peer);continue
            if request[13:16]==b"txt":
                reply[10:12]=b"\0\2";reply.extend(bytes.fromhex("00002904d0000000000000"))
                reply.extend(bytes.fromhex("c00c001000010000003c000302c0ff"))
                upstream.sendto(reply,peer);continue
            if request[13:18] in (b"noecs",b"retry"):
                reply[10:12]=b"\0\0";upstream.sendto(reply,peer);continue
            if len(request)>end:
                opt=bytearray(request[end:]);opt[-4]=25
                if request[13:16]==b"bad":opt[-1]^=1
            else:
                opt=bytearray.fromhex("00002904d000000000000b0008000700011800c00002")
            reply.extend(opt);upstream.sendto(reply,peer)
    except Exception as error:failures.append(error)

worker=threading.Thread(target=serve);worker.start()
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
        last_reply=[]
        def ask(name,ident,subnet):
            question=b"".join(bytes([len(label)])+label.encode() for label in name.split("."))+b"\0\0\1\0\1"
            request=struct.pack("!HHHHHH",ident,0x0100,1,0,0,int(subnet is not None))+question
            if subnet is not None:request+=bytes.fromhex("00002904d000000000000b0008000700011800")+bytes(subnet)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(4);client.sendto(request,("127.0.0.1",listen));reply,_=client.recvfrom(4096)
            assert reply[:2]==request[:2],reply.hex()
            last_reply[:]=[reply]
            return reply[3]&15
        assert ask("ok.test",1,[192,0,2])==0
        assert ask("ok.test",2,[192,0,2])==0 and len(received)==1
        assert ask("ok.test",3,[198,51,100])==0 and len(received)==2
        assert ask("bad.test",4,[192,0,2])==2
        assert ask("bad.test",5,[192,0,2])==2 and len(received)==4
        assert ask("unexpected.test",6,None)==2 and len(received)==5
        expected=bytes.fromhex("0008000700011800c00002")
        assert ask("noecs.test",7,[192,0,2])==0 and last_reply[0].endswith(expected)
        assert ask("noecs.test",8,[192,0,2])==0 and len(received)==6
        assert ask("retry.test",9,[192,0,2])==0 and last_reply[0].endswith(expected)
        assert len(received)==8 and bytes.fromhex("00080007") not in received[-1]
        assert ask("synthetic.test",10,[192,0,2])==0 and last_reply[0].endswith(expected) and len(received)==8
        assert ask("middle.test",11,[192,0,2])==0 and expected in last_reply[0]
        assert ask("middle.test",12,[192,0,2])==0 and len(received)==9
        assert ask("unsafe.test",13,[192,0,2])==0 and len(received)==10
        moved=last_reply[0].index(bytes.fromhex("046c617465047465737400"))
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-16)[0]==0xc000|moved
        assert ask("unsafe.test",14,[192,0,2])==0 and len(received)==10
        assert ask("opaque.test",15,[192,0,2])==2 and len(received)==11
        assert ask("rdata.test",16,[192,0,2])==0 and len(received)==12
        moved=last_reply[0].index(bytes.fromhex("046c617465047465737400"))
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-2)[0]==0xc000|moved
        assert ask("chaos.test",24,[192,0,2])==0 and len(received)==13
        moved=last_reply[0].index(bytes.fromhex("046c617465047465737400"))
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-20)[0]==0xc000|moved
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-16)[0]==0xc000|(len(last_reply[0])-20)
        assert ask("txt.test",29,[192,0,2])==0 and len(received)==14
        assert last_reply[0].endswith(bytes.fromhex("c00c001000010000003c000302c0ff"))
        assert ask("svcb.test",28,[192,0,2])==0 and len(received)==15
        moved=last_reply[0].index(bytes.fromhex("046c617465047465737400"))
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-16)[0]==0xc000|moved
        assert ask("rp.test",27,[192,0,2])==0 and len(received)==16
        moved=last_reply[0].index(bytes.fromhex("046c617465047465737400"))
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-16)[0]==0xc000|moved
        assert ask("srv.test",26,[192,0,2])==0 and len(received)==17
        moved=last_reply[0].index(bytes.fromhex("046c617465047465737400"))
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-16)[0]==0xc000|moved
        assert ask("minfo.test",25,[192,0,2])==0 and len(received)==18
        moved=last_reply[0].index(bytes.fromhex("046c617465047465737400"))
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-20)[0]==0xc000|moved
        assert struct.unpack_from("!H",last_reply[0],len(last_reply[0])-16)[0]==0xc000|(len(last_reply[0])-20)
        question=bytes.fromhex("076578616d706c6504746573740000010001")
        malformed_ecs=struct.pack("!HHHHHH",17,0x0100,1,0,0,1)+question+bytes.fromhex("00002904d000000000000b0008000700011801c00002")
        malformed_name=struct.pack("!HHHHHH",18,0x0110,1,0,0,0)+b"\x08bad"
        unknown_opcode=struct.pack("!HHHHHH",19,0x1100,1,0,0,0)+question
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            for request,rcode in ((malformed_ecs,1),(malformed_name,1),(unknown_opcode,4)):
                client.sendto(request,("127.0.0.1",listen));response,_=client.recvfrom(512)
                assert response[:2]==request[:2] and response[3]&15==rcode,response.hex()
                if request is malformed_name:assert response[2:4]==bytes.fromhex("8191") and response[4:12]==bytes(8)
        with socket.create_connection(("127.0.0.1",listen),timeout=3) as client:
            for request,rcode in ((malformed_name,1),(malformed_ecs,1)):
                client.sendall(struct.pack("!H",len(request))+request)
                header=client.recv(2);assert len(header)==2
                size=struct.unpack("!H",header)[0];response=b""
                while len(response)<size:
                    data=client.recv(size-len(response));assert data;response+=data
                assert response[:2]==request[:2] and response[3]&15==rcode,response.hex()
        assert len(received)==18
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(4)
            for ident in range(100,164):
                client.sendto(struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+b"\x08bad",("127.0.0.1",listen))
            valid=struct.pack("!HHHHHH",200,0x0100,1,0,0,1)+bytes.fromhex("026f6b04746573740000010001")+bytes.fromhex("00002904d000000000000b0008000700011800c00002")
            client.sendto(valid,("127.0.0.1",listen))
            answers={}
            for _ in range(65):
                response,_=client.recvfrom(512);answers[struct.unpack_from("!H",response)[0]]=response[3]&15
            assert all(answers.get(ident)==1 for ident in range(100,164)) and answers.get(200)==0,answers
    finally:
        process.terminate();_,err=process.communicate(timeout=8)
        stopping.set();worker.join(timeout=3);upstream.close()
        if process.returncode:raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
assert not failures and not worker.is_alive(),failures
print("DNS ECS response validation and exact-prefix caching passed")
