#!/usr/bin/env python3
"""Retry a later routed DNS address after a VLESS pre-request failure."""
import argparse
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from httpupgrade_cli_network import HOST, TARGET, transport_kdl
from httpupgrade_tls_network import RESPONSE, header

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary',type=pathlib.Path)
parser.add_argument('mode',choices=('retry','blocked','partial','stop'),default='retry',nargs='?',
                    help='partial requires the dedicated NEXUS_TEST_VLESS_PARTIAL_REQUEST build')
parser.add_argument('--httpupgrade',action='store_true')
parser.add_argument('--workers',type=int,choices=(1,2),default=1)
parser.add_argument('--failure',choices=('status','framing','alpn'),default='status',
                    help='pre-VLESS HTTPUpgrade rejection; used in retry/blocked modes')
args=parser.parse_args()
binary,mode=args.binary.resolve(),args.mode
if not args.httpupgrade and args.failure!='status': parser.error('--failure requires --httpupgrade')
blocked=mode=="blocked"

def exact(sock,n):
    data=bytearray()
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk: raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)

with tempfile.TemporaryDirectory(prefix="nexus-vless-candidate-") as directory:
    root=pathlib.Path(directory); cert=root/"cert"; key=root/"key"; uuid=root/"uuid"; rules=root/"rules.kdl"; block_rules=root/"block.kdl"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,
                    "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1"],check=True,capture_output=True,timeout=10)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    rules.write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.1/32"\n')
    block_rules.write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket() as origin, socket.socket() as reserve, socket.socket() as tls_listener:
        dns.bind(("127.0.0.1",0)); dns.settimeout(5)
        origin.bind(("127.0.0.2",0)); origin.listen(1); origin.settimeout(5)
        reserve.bind(("127.0.0.1",0)); closed=reserve.getsockname()[1]; reserve.close()
        if mode in ("partial", "stop") or args.httpupgrade:
            tls_listener.bind(("127.0.0.1",0)); tls_listener.listen(1); tls_listener.settimeout(5)
            closed=tls_listener.getsockname()[1]
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1",0)); port=reservation.getsockname()[1]
        config=root/"config.kdl"
        block_outbound='outbound "reject" type="block"' if blocked else ''
        block_route=f'rule-set "blocked" path="{block_rules}" format="kdl";' if blocked else ''
        block_rule='- kind="rule-set" value="blocked" outbound="reject";' if blocked else ''
        config.write_text(f'''schema-version 1
role "client"
workers {args.workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
dns {{ server "dns" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}
outbound "direct" type="direct"
{block_outbound}
outbound "edge" type="vless" {{ server host="127.0.0.1" port={closed}; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; }}
 {transport_kdl() if args.httpupgrade else ''}
}}
routing {{ rule-set "first" path="{rules}" format="kdl"; {block_route} rules {{ - kind="rule-set" value="first" outbound="edge"; {block_rule} }}; default-outbound "direct"; }}
''')
        errors=[]
        def dns_peer():
            try:
                query,peer=dns.recvfrom(512)
                if query[12:]!=b"\x06target\x04test\x00\x00\x01\x00\x01": raise RuntimeError("unexpected DNS query")
                response=bytearray(query); response[2:4]=b"\x81\x80"; response[7]=2
                for address in (1,2): response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00"+bytes([address]))
                dns.sendto(response,peer)
            except Exception as exc: errors.append(exc)
        thread=threading.Thread(target=dns_peer); thread.start()
        tls_thread=None
        handshake_started=threading.Event()
        if mode=="stop" and not args.httpupgrade:
            def stalled_tls_peer():
                try:
                    with tls_listener.accept()[0] as raw:
                        raw.settimeout(5)
                        if not raw.recv(4096): raise RuntimeError("missing TLS ClientHello")
                        handshake_started.set()
                        while raw.recv(4096): pass
                except Exception as exc: errors.append(exc)
            tls_thread=threading.Thread(target=stalled_tls_peer); tls_thread.start()
        if mode=="partial" or args.httpupgrade:
            def tls_peer():
                try:
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_3
                    # The client deliberately closes after its partial request.
                    # Do not let post-handshake tickets turn the EOF check into
                    # a write to that already-closed connection.
                    context.num_tickets=0
                    if args.httpupgrade and (args.failure!='alpn' or mode not in ('retry','blocked')):
                        context.set_alpn_protocols(['http/1.1'])
                    context.load_cert_chain(cert,key)
                    with tls_listener.accept()[0] as raw:
                        raw.settimeout(5)
                        with context.wrap_socket(raw,server_side=True) as tls:
                            if args.httpupgrade:
                                if args.failure=='alpn' and mode in ('retry','blocked'):
                                    if tls.selected_alpn_protocol() is not None or tls.recv(1): raise RuntimeError('ALPN rejection sent Upgrade/VLESS bytes')
                                    return
                                wire=header(tls)
                                if tls.selected_alpn_protocol()!='http/1.1' or not wire.startswith(f'GET {TARGET} HTTP/1.1\r\nHost: {HOST}\r\n'.encode()):
                                    raise RuntimeError('candidate did not receive the configured TLS Upgrade')
                                if mode=='stop':
                                    tls.sendall(b'HTTP/1.1 101 Switching Protocols\r\n')
                                    handshake_started.set()
                                    if tls.recv(1): raise RuntimeError('stopped partial Upgrade sent VLESS')
                                    return
                                if mode in ('retry','blocked'):
                                    rejected=RESPONSE.replace(b' 101 ',b' 403 ') if args.failure=='status' else RESPONSE[:-2]+b'Content-Length: 1\r\n\r\n'
                                    tls.sendall(rejected)
                                    if tls.recv(1): raise RuntimeError('failed Upgrade candidate received VLESS identity')
                                    return
                                tls.sendall(RESPONSE)
                            if exact(tls,8)!=b"\x00"+bytes(range(7)): raise RuntimeError("incorrect partial request")
                            try: remaining=tls.recv(1024)
                            except (ConnectionResetError,ssl.SSLError): remaining=b""
                            if remaining: raise RuntimeError("unexpected remaining VLESS data")
                except Exception as exc: errors.append(exc)
            tls_thread=threading.Thread(target=tls_peer); tls_thread.start()
        env=os.environ.copy()
        if mode=="partial": env["NEXUS_TEST_VLESS_PARTIAL_REQUEST"]="1"
        process=subprocess.Popen([binary,"run","--config",config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env)
        try:
            deadline=time.monotonic()+5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try: client=socket.create_connection(("127.0.0.1",port),timeout=.2); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(5); client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("SOCKS negotiation failed")
                client.sendall(b"\x05\x01\x00\x03\x0btarget.test"+origin.getsockname()[1].to_bytes(2,"big"))
                if mode=="stop":
                    if not handshake_started.wait(5): raise RuntimeError("TLS handshake did not start")
                    process.terminate()
                    if process.wait(timeout=5)!=0: raise RuntimeError(process.stderr.read().decode())
                    if client.recv(1)!=b"": raise RuntimeError("client remained open after stop")
                    origin.settimeout(.3)
                    try:
                        unexpected,_=origin.accept(); unexpected.close()
                        raise RuntimeError("later candidate connected after stop")
                    except TimeoutError: pass
                    reply=None
                else:
                    reply=exact(client,10)
                if blocked or mode=="partial":
                    if reply[:2]==b"\x05\x00": raise RuntimeError("blocked second address was connected")
                    origin.settimeout(.3)
                    try:
                        unexpected,_=origin.accept(); unexpected.close()
                        raise RuntimeError("blocked origin received a connection")
                    except TimeoutError: pass
                elif mode!="stop" and reply[:2]!=b"\x05\x00": raise RuntimeError("candidate retry failed")
                if not blocked and mode not in ("partial", "stop"):
                  with origin.accept()[0] as peer:
                    peer.settimeout(5); client.sendall(b"request")
                    if exact(peer,7)!=b"request": raise RuntimeError("wrong upload")
                    peer.sendall(b"response")
                    if exact(client,8)!=b"response": raise RuntimeError("wrong download")
            thread.join(timeout=5)
            if tls_thread: tls_thread.join(timeout=5)
            if thread.is_alive() or (tls_thread and tls_thread.is_alive()) or errors: raise RuntimeError(f"peer failure: {errors}")
        finally:
            if process.poll() is None: process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            thread.join(timeout=6)
            if tls_thread: tls_thread.join(timeout=6)
        if process.returncode!=0: raise RuntimeError(process.stderr.read().decode())
print(("stalled VLESS handshake stopped without retry" if mode=="stop" else "partial request did not retry" if mode=="partial" else "blocked next address rejected" if blocked else "VLESS pre-request failure retries the next routed DNS address")+
      f': transport={"httpupgrade" if args.httpupgrade else "TLS"}, workers={args.workers}, failure={args.failure}')
