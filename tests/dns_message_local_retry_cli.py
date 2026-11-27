"""Exercise local DNS server response retry in isolated network/mount namespaces."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

binary=Path(sys.argv[1]).resolve()
if len(sys.argv)==2:
    subprocess.run(["unshare","-Urnm",sys.executable,__file__,str(binary),"inside"],check=True)
    sys.exit(0)
subprocess.run(["ip","link","set","lo","up"],check=True)
subprocess.run(["mount","--make-rprivate","/"],check=True)
def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0));return sock.getsockname()[1]

with tempfile.TemporaryDirectory(prefix="nexus-dns-message-local-") as directory:
    root=Path(directory);resolv=root/"resolv";hosts=root/"hosts"
    resolv.write_text("nameserver 127.0.0.2\nnameserver 127.0.0.3\noptions timeout:1 attempts:1\n");hosts.write_text("")
    for source,target in ((resolv,"/etc/resolv.conf"),(hosts,"/etc/hosts")):
        subprocess.run(["mount","--bind",str(source),target],check=True)
    sockets=[]
    for address in ("127.0.0.2","127.0.0.3"):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind((address,53));sock.settimeout(.2);sockets.append(sock)
    stopping=threading.Event();seen=[[],[]];errors=[]
    def serve(index):
        try:
            while not stopping.is_set():
                try:request,peer=sockets[index].recvfrom(65535)
                except TimeoutError:continue
                seen[index].append(request);response=bytearray(request);response[2:4]=b"\x81\x80"
                if request[13:17]==b"hold":continue
                if index==0 and request[13:20]==b"timeout":continue
                if index==0:response[3]=0x82
                elif request[13:16]==b"all":response[3]=0x85
                else:response[7]=1;response.extend(bytes.fromhex("c00c000100010000003c0004c0000201"))
                sockets[index].sendto(response,peer)
        except Exception as error:errors.append(error)
    threads=[threading.Thread(target=serve,args=(i,)) for i in range(2)]
    for thread in threads:thread.start()
    listen,proxy=free_port(),free_port()
    while listen==proxy:proxy=free_port()
    config=root/"config.kdl";config.write_text(f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={listen}; server "local" type="local"; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
    process=subprocess.Popen([str(binary),"run","--config",str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for _ in range(80):
            if process.poll() is not None:raise RuntimeError(process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1",listen),timeout=.1):break
            except OSError:time.sleep(.05)
        else:raise RuntimeError("DNS listener failed to start")
        def ask(name,ident):
            labels=b"".join(bytes([len(part)])+part.encode() for part in name.split("."))+b"\0\0\1\0\1"
            request=struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+labels
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(4);client.sendto(request,("127.0.0.1",listen));answer,_=client.recvfrom(4096)
            assert answer[:2]==request[:2],answer.hex()
            return answer
        answer=ask("ok.test",1);assert answer[3]&15==0 and answer[-4:]==bytes([192,0,2,1]),answer.hex()
        answer=ask("all.test",2);assert answer[3]&15==5,answer.hex()
        assert [len(items) for items in seen]==[2,2],list(map(len,seen))
        # A repeated query uses the second server's cached response after the
        # first server's SERVFAIL; changing hosts must supersede that cache.
        answer=ask("ok.test",3);assert answer[-4:]==bytes([192,0,2,1])
        assert [len(items) for items in seen]==[3,2],list(map(len,seen))
        hosts.write_text("192.0.2.9 ok.test\n")
        deadline=time.monotonic()+4
        while True:
            answer=ask("ok.test",4)
            if answer[-4:]==bytes([192,0,2,9]):break
            if time.monotonic()>=deadline:raise RuntimeError("hosts snapshot did not update")
            time.sleep(.1)
        hosts.write_text("");before=len(seen[1]);deadline=time.monotonic()+4
        while True:
            answer=ask("ok.test",5)
            if answer[-4:]==bytes([192,0,2,1]):break
            if time.monotonic()>=deadline:raise RuntimeError("hosts snapshot removal did not update")
            time.sleep(.1)
        assert len(seen[1])==before+1,list(map(len,seen))
        started=time.monotonic();answer=ask("timeout.test",7);elapsed=time.monotonic()-started
        assert answer[3]&15==0 and answer[-4:]==bytes([192,0,2,1]) and .7<=elapsed<4,(answer.hex(),elapsed)
        # Shutdown while the first local server has a live unanswered query.
        hold=struct.pack("!HHHHHH",6,0x0100,1,0,0,0)+bytes.fromhex("04686f6c6404746573740000010001")
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.sendto(hold,("127.0.0.1",listen));deadline=time.monotonic()+3
            while not any(request[13:17]==b"hold" for request in seen[0]):
                if time.monotonic()>=deadline:raise RuntimeError("active local request not observed")
                time.sleep(.01)
            started=time.monotonic();process.terminate();_,err=process.communicate(timeout=4)
            assert process.returncode==0 and time.monotonic()-started<4,err.decode()
    finally:
        if process.poll() is None:process.terminate();_,err=process.communicate(timeout=8)
        stopping.set()
        for thread in threads:thread.join(timeout=3)
        for sock in sockets:sock.close()
        if process.returncode:raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
    assert not errors and all(not thread.is_alive() for thread in threads),errors
print("DNS local retry, snapshot cache isolation and active shutdown passed")
