#!/usr/bin/env python3
"""Exercise the production DNS-over-TLS client against an independent TLS peer."""
import base64
import concurrent.futures
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from detour_network import exact, reserve, running
from dns_rule_support import DnsPeer, Echo, datagram_request, ss_client, udp_client

def make_query(txid, name, qtype):
    labels=b"".join(bytes([len(part)])+part.encode() for part in name.split("."))+b"\0"
    return struct.pack("!HHHHHH",txid,0x100,1,0,0,0)+labels+struct.pack("!HH",qtype,1)

class DotServer:
    def __init__(self,root,host,family):
        cert=root/"dot.pem"
        key=root/"dot-key.pem"
        subprocess.run(["openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256",
            "-nodes","-days","1","-keyout",str(key),"-out",str(cert),"-subj","/CN=dot.test",
            "-addext","subjectAltName=DNS:dot.test"],check=True,capture_output=True)
        self.cert=cert
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(cert,key)
        self.socket=socket.socket(family)
        self.socket.bind((host,0))
        self.socket.listen()
        self.socket.settimeout(.1)
        self.port=self.socket.getsockname()[1]
        self.host=host
        self.cleartext=socket.socket(family,socket.SOCK_DGRAM)
        self.cleartext.bind((host,self.port))
        self.queries=[]
        self.wire_queries=[]
        self.seen={name:threading.Event() for name in ("first.test","abandoned.test","old.test")}
        self.release=threading.Event()
        self.workers=[]
        self.closed=[]
        self.stale_reset=False
        self.stop=threading.Event()
        self.errors=[]
        self.first_record=[]
        self.hung=threading.Event()
        self.canceled=threading.Event()
        self.thread=threading.Thread(target=self.serve,daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self,*args):
        self.stop.set()
        self.thread.join(timeout=5)
        self.socket.close()
        for worker in self.workers:
            worker.join(timeout=5)
            assert not worker.is_alive(), "TLS fixture connection did not stop"
        ready=select.select([self.cleartext],[],[],0)[0]
        self.cleartext.close()
        assert not ready, "upstream received cleartext DNS over UDP"
        assert not self.errors,self.errors

    def serve(self):
        while not self.stop.is_set():
            try:
                client,_=self.socket.accept()
            except TimeoutError:
                continue
            self.closed.append(threading.Event())
            worker=threading.Thread(target=self.connection,args=(client,len(self.workers)),daemon=True)
            self.workers.append(worker)
            worker.start()

    @staticmethod
    def reply(query,end,qtype,kind):
        if qtype==1:
            address=socket.inet_pton(socket.AF_INET,"127.0.0.1")
        elif qtype==28:
            address=socket.inet_pton(socket.AF_INET6,"::1")
        else:
            address=b""
        reply=query[:2]+struct.pack("!HHHHH",0x8180,1,bool(address),0,0)+query[12:end+4]
        if address:
            reply+=b"\xc0\x0c"+struct.pack("!HHIH",qtype,kind,40,len(address))+address
        return struct.pack("!H",len(reply))+reply

    def connection(self,client,index):
        with client:
            client.settimeout(4)
            try:
                first_record=client.recv(1,socket.MSG_PEEK)
                if not first_record:
                    return
                self.first_record.append(first_record)
                with self.context.wrap_socket(client,server_side=True) as tls:
                    tls.settimeout(.5)
                    deferred=None
                    while not self.stop.is_set():
                        try:
                            first=tls.recv(1)
                        except TimeoutError:
                            continue
                        if not first:
                            return
                        size=int.from_bytes(first+exact(tls,1),"big")
                        query=exact(tls,size)
                        labels,end=[],12
                        while query[end]:
                            n=query[end]
                            labels.append(query[end+1:end+1+n].decode())
                            end+=n+1
                        end+=1
                        qtype,kind=struct.unpack("!HH",query[end:end+4])
                        name=".".join(labels)
                        self.queries.append((name,qtype))
                        self.wire_queries.append((name,index,int.from_bytes(query[:2],"big")))
                        if name=="held.test":
                            self.hung.set()
                            tls.settimeout(3)
                            try:
                                assert not tls.recv(1)
                            except ConnectionResetError:
                                pass
                            self.canceled.set()
                            return
                        frame=self.reply(query,end,qtype,kind)
                        if name in ("first.test","abandoned.test"):
                            deferred=frame
                            self.seen[name].set()
                            continue
                        if name=="old.test":
                            self.seen[name].set()
                            if not self.release.wait(3):
                                raise RuntimeError("reload did not release the old query")
                        if name=="partner.test":
                            if not self.release.wait(3):
                                raise RuntimeError("cancel did not release the companion query")
                            if deferred:
                                tls.sendall(deferred)
                                deferred=None
                        if name=="reset.test" and not self.stale_reset:
                            self.stale_reset=True
                            tls.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack("ii",1,0))
                            return
                        tls.sendall(frame[:1])
                        tls.sendall(frame[1:])
                        if name=="second.test" and deferred:
                            tls.sendall(deferred)
                            deferred=None
            except ssl.SSLError:
                pass
            except (BrokenPipeError,ConnectionResetError):
                pass
            except Exception as error:
                self.errors.append(error)
            finally:
                self.closed[index].set()

def write_config(path, dot, front, dns_port, identity="dot.test"):
    path.write_text(f'''schema-version 1
role "client"
workers 2
inbounds {{ mixed "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
dns {{
    listen host="127.0.0.1" port={dns_port}
    servers {{
        server "protected" type="tls" host="{dot.host}" port={dot.port} server-name="{identity}" ca-file="{dot.cert}"
    }}
    final "protected"
    strategy "ipv4_only"
}}
routing {{ default-outbound "direct"; }}
''')

def dns_roundtrip(port, network, query, success=True):
    if network==socket.SOCK_STREAM:
        with socket.create_connection(("127.0.0.1",port),timeout=5) as sock:
            sock.sendall(struct.pack("!H",len(query))+query)
            response=exact(sock,int.from_bytes(exact(sock,2),"big"))
    else:
        with socket.socket(socket.AF_INET,network) as sock:
            sock.settimeout(5)
            sock.sendto(query,("127.0.0.1",port))
            response=sock.recv(512)
    transaction, flags, questions, answers=struct.unpack_from("!HHHH",response)
    assert transaction==int.from_bytes(query[:2],"big") and questions==1 and flags&0x8000
    assert ((flags&15)==0 and answers==1) if success else ((flags&15)==2 and not answers),response
    return response

def socks_connect(front, host, port):
    sock=socket.create_connection(("127.0.0.1",front),timeout=5)
    sock.sendall(b"\x05\x01\x00")
    assert exact(sock,2)==b"\x05\x00"
    name=host.encode()
    sock.sendall(b"\x05\x01\x00\x03"+bytes([len(name)])+name+struct.pack("!H",port))
    response=exact(sock,10)
    assert response[:2]==b"\x05\x00",response
    return sock

def verify_idle(binary, root, dot):
    config=root/"idle.kdl"
    front, dns_port=reserve(), reserve()
    write_config(config,dot,front,dns_port)
    with running([binary,"run","--config",str(config)],front,root/"idle.log"):
        dns_roundtrip(dns_port,socket.SOCK_DGRAM,make_query(901,"idle.test",1))
        initial=next(conn for name,conn,_ in dot.wire_queries if name=="idle.test")
        start=time.monotonic()
        assert dot.closed[initial].wait(18), "idle TLS socket remained open without queries"
        assert time.monotonic()-start>13, "TLS socket closed before the idle deadline"
        dns_roundtrip(dns_port,socket.SOCK_DGRAM,make_query(902,"after-idle.test",1))
        following=next(conn for name,conn,_ in dot.wire_queries if name=="after-idle.test")
        assert initial!=following
    print("Idle DNS-over-TLS socket closed without a new request, then reconnected")


def verify_reuse(binary, root, dot):
    config=root/"reuse.kdl"
    front,dns_port=reserve(),reserve()
    write_config(config,dot,front,dns_port)
    control=root/"reuse.sock"
    text=config.read_text().replace('workers 2',f'workers 2\ncontrol socket="{control}"').replace(
        '    final "protected"', '    rule domain="abandoned.test" action="route" server="protected" timeout-ms=150\n'
        '    final "protected"\n    disable-cache #true')
    config.write_text(text)
    with running([binary,"run","--config",str(config)],front,root/"reuse.log") as process, \
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as jobs:
        def query(name,identifier,success=True):
            return dns_roundtrip(dns_port,socket.SOCK_DGRAM,make_query(identifier,name,1),success)

        query("warm.test",1)
        query("warm-again.test",2)
        first=jobs.submit(query,"first.test",0x4444)
        assert dot.seen["first.test"].wait(2),dot.wire_queries
        second=jobs.submit(query,"second.test",0x4444)
        second.result(timeout=3)
        first.result(timeout=3)
        abandoned=jobs.submit(query,"abandoned.test",4,False)
        assert dot.seen["abandoned.test"].wait(2),dot.wire_queries
        partner=jobs.submit(query,"partner.test",5)
        abandoned.result(timeout=3)
        dot.release.set()
        partner.result(timeout=3)
        dot.release.clear()

        paired={name:(connection,wire_id) for name,connection,wire_id in dot.wire_queries}
        names=("warm.test","warm-again.test","first.test","second.test","abandoned.test","partner.test")
        assert len({paired[name][0] for name in names})==1,dot.wire_queries
        assert len({paired[name][1] for name in names})==len(names),dot.wire_queries

        query("reset.test",6)
        resets=[index for name,index,_ in dot.wire_queries if name=="reset.test"]
        assert len(resets)==2 and resets[0]!=resets[1],dot.wire_queries
        query("after-reset.test",7)

        old=jobs.submit(query,"old.test",8)
        assert dot.seen["old.test"].wait(2),dot.wire_queries
        successor=root/"successor"
        successor.mkdir()
        family=socket.AF_INET6 if ":" in dot.host else socket.AF_INET
        with DotServer(successor,dot.host,family) as replacement:
            new_text=text.replace(str(dot.port),str(replacement.port)).replace(str(dot.cert),str(replacement.cert))
            config.write_text(new_text)
            process.send_signal(signal.SIGHUP)
            until=time.monotonic()+2
            while time.monotonic()<until:
                status=subprocess.run([binary,"control",control,"status"],check=True,capture_output=True,text=True)
                if "listener-generation=2" in status.stdout:
                    break
                time.sleep(.02)
            else:
                raise RuntimeError(f"DNS TLS reload did not publish a new generation: {status.stdout}")
            query("new.test",9)
            assert ("new.test",1) in replacement.queries and ("new.test",1) not in dot.queries
            dot.release.set()
            old.result(timeout=3)
    print(f"DoT {dot.host} reused connections, reordered replies, isolated cancellation, retried RST and drained a TLS generation")


if __name__=="__main__":
    binary=str(Path(sys.argv[1]).resolve(strict=True))
    for address,family in (("127.0.0.1",socket.AF_INET),("::1",socket.AF_INET6)):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as destination:
            root=Path(directory)
            destination.bind(("127.0.0.1",0))
            destination.listen()
            destination.settimeout(5)
            with DotServer(root,address,family) as dot:
                config=root/"proxy.kdl"
                front,dns_port=reserve(),reserve()
                write_config(config,dot,front,dns_port)
                with running([binary,"run","--config",str(config)],front,root/"proxy.log"):
                    assert dns_roundtrip(dns_port,socket.SOCK_DGRAM,make_query(1,"dns.test",28)).endswith(socket.inet_pton(socket.AF_INET6,"::1"))
                    assert dns_roundtrip(dns_port,socket.SOCK_STREAM,make_query(2,"dns.test",28)).endswith(socket.inet_pton(socket.AF_INET6,"::1"))
                    assert dot.queries.count(("dns.test",28))==1,dot.queries
                    with socks_connect(front,"origin.test",destination.getsockname()[1]) as user:
                        peer,_=destination.accept()
                        with peer:
                            peer.settimeout(5)
                            user.sendall(b"ping")
                            assert exact(peer,4)==b"ping"
                            peer.sendall(b"pong")
                            assert exact(user,4)==b"pong"
                    with Echo() as echo, udp_client(front) as (sock,relay):
                        datagram_request(sock,relay,echo.port,"udp.test")
                    assert ("origin.test",1) in dot.queries and ("udp.test",1) in dot.queries,dot.queries
                intercepted=reserve()
                (root/"dns.kdl").write_text(f'schema-version 2\nkind "predicate"\nrule type="port" value="{intercepted}"\n')
                content=config.read_text().replace('routing { default-outbound "direct"; }', """
    routing {
      rule-set "dns" path="dns.kdl" format="kdl"
      tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {
        rule action="hijack-dns" rule-set="dns"
        rule action="route" outbound="direct"
      }
      default-outbound "direct"
    }""")
                config.write_text(content)
                with running([binary,"run","--config",str(config)],front,root/"hijack.log"):
                    with udp_client(front) as (sock,relay):
                        prefix=b"\0\0\0\1"+socket.inet_aton("127.0.0.1")+struct.pack("!H",intercepted)
                        request=make_query(0x431,"hijacked.test",1)
                        sock.sendto(prefix+request,relay)
                        response=sock.recv(512)
                        assert response.startswith(prefix+request[:2]),response
                        assert response.endswith(socket.inet_aton("127.0.0.1")),response
                        assert ("hijacked.test",1) in dot.queries,dot.queries
                write_config(config,dot,front,dns_port)
                key=bytes(range(16))
                key_path=root/"key"
                key_path.write_text(base64.b64encode(key).decode())
                key_path.chmod(0o600)
                ss=reserve()
                updated=config.read_text().replace('role "client"', 'role "server"').replace(
                    'authentication "none"; }; }', f'authentication "none"; }}; shadowsocks "ss" {{ listen host="127.0.0.1" port={ss}; method "2022-blake3-aes-128-gcm"; key-file "{key_path}"; }}; }}')
                config.write_text(updated)
                with running([binary,"run","--config",str(config)],front,root/"ss.log"):
                    with Echo() as echo, ss_client(root,ss,key) as (sock,relay):
                        datagram_request(sock,relay,echo.port,"native.test")
                    assert ("native.test",1) in dot.queries,dot.queries
                    with socket.create_connection(("127.0.0.1",dns_port),timeout=2) as client:
                        payload=make_query(0x671,"held.test",1)
                        client.sendall(struct.pack("!H",len(payload))+payload)
                        assert dot.hung.wait(2),"TLS peer did not receive held query"
                assert dot.canceled.wait(2),"stopping failed to cancel active TLS query"
                with DnsPeer() as bootstrap:
                    write_config(config,dot,front,dns_port)
                    content=config.read_text().replace(
                        f'server "protected" type="tls" host="{dot.host}"',
                        f'server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap.port}\n'
                        '        server "protected" type="tls" host="resolver-location.test" domain-resolver="bootstrap"')
                    config.write_text(content)
                    with running([binary,"run","--config",str(config)],front,root/"bootstrap.log"):
                        dns_roundtrip(dns_port,socket.SOCK_DGRAM,make_query(4,"bootstrapped.test",1))
                    assert bootstrap.count("resolver-location.test",1),bootstrap.seen
                    assert not bootstrap.count("bootstrapped.test",1),bootstrap.seen
                    assert ("bootstrapped.test",1) in dot.queries,dot.queries
                before=list(dot.queries)
                write_config(config,dot,front,dns_port,"wrong.test")
                with running([binary,"run","--config",str(config)],front,root/"reject.log"):
                    dns_roundtrip(dns_port,socket.SOCK_DGRAM,make_query(3,"wrong.test",1),False)
                    assert dot.queries==before,dot.queries
                assert dot.first_record and all(data==b"\x16" for data in dot.first_record),dot.first_record
                if "--reuse" in sys.argv[2:]:
                    verify_reuse(binary,root,dot)
                if "--idle" in sys.argv[2:] and dot.host=="127.0.0.1":
                    verify_idle(binary,root,dot)
    print("DoT verified TLS identity, message cache, SOCKS TCP/UDP resolution, SOCKS UDP DNS interception, native SS UDP, active cancellation and no plaintext fallback with IPv4/IPv6 upstreams")
