#!/usr/bin/env python3
"""Test hybrid fallback and strict downgrade rejection on a VLESS outbound."""
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
mode=sys.argv[2] if len(sys.argv)>2 else "fallback"
if mode not in ("fallback", "strict", "forged-retry", "forged-final", "bootstrap", "bootstrap-chain"): raise ValueError("invalid mode")
strict=mode not in ("fallback", "bootstrap", "bootstrap-chain")

def exact(sock, length):
    data=bytearray()
    while len(data)<length:
        part=sock.recv(length-len(data))
        if not part: raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)

def inspect_hello(record):
    if record[0]!=22 or record[5]!=1: raise RuntimeError("not a ClientHello")
    p=5+4+2+32
    p+=1+record[p]
    length=int.from_bytes(record[p:p+2],"big"); p+=2+length
    p+=1+record[p]
    end=p+2+int.from_bytes(record[p:p+2],"big"); p+=2
    extensions={}
    while p<end:
        kind=int.from_bytes(record[p:p+2],"big"); size=int.from_bytes(record[p+2:p+4],"big"); p+=4
        extensions[kind]=record[p:p+size]; p+=size
    groups=extensions[10]; shares=extensions[51]
    if groups!=(b"\x00\x02\x11\xec" if strict else b"\x00\x04\x11\xec\x00\x1d"): raise RuntimeError(f"wrong supported groups: {groups.hex()}")
    if len(shares)!=1222 or shares[:6]!=b"\x04\xc4\x11\xec\x04\xc0":
        raise RuntimeError("initial share is not exclusively X25519MLKEM768")

with tempfile.TemporaryDirectory(prefix="nexus-vless-hybrid-outbound-") as directory:
    root=pathlib.Path(directory); cert=root/"cert.pem"; key=root/"key.pem"; uuid=root/"uuid"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,
                    "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1"],
                   check=True,capture_output=True,timeout=10)
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert,key); context.set_ecdh_curve("X25519")
    with socket.socket() as upstream, socket.socket() as reserved, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns_root:
        upstream.bind(("127.0.0.1",0)); upstream.listen(1); upstream.settimeout(8)
        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
        errors=[]; payload=b"hybrid fallback payload"
        dns_calls=[]; dns_threads=[]
        if mode in ("bootstrap", "bootstrap-chain"):
            dns.bind(("127.0.0.1",0)); dns.settimeout(8)
            def dns_peer():
                try:
                    query,source=dns.recvfrom(512); dns_calls.append(query)
                    if query[12:]!=b"\x04edge\x04test\x00\x00\x01\x00\x01": raise RuntimeError("unexpected bootstrap DNS query")
                    response=bytearray(query); response[2:4]=b"\x81\x80"; response[7]=1
                    response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                    dns.sendto(response,source)
                except Exception as exc: errors.append(exc)
            dns_threads.append(threading.Thread(target=dns_peer))
            if mode=="bootstrap-chain":
                dns_root.bind(("127.0.0.1",0)); dns_root.settimeout(8)
                def root_peer():
                    try:
                        query,source=dns_root.recvfrom(512); dns_calls.append(query)
                        if query[12:]!=b"\x04leaf\x04test\x00\x00\x01\x00\x01": raise RuntimeError("unexpected root DNS query")
                        response=bytearray(query); response[2:4]=b"\x81\x80"; response[7]=1
                        response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                        dns_root.sendto(response,source)
                    except Exception as exc: errors.append(exc)
                dns_threads.append(threading.Thread(target=root_peer))
            for dns_thread in dns_threads: dns_thread.start()
        def peer():
            try:
                with upstream.accept()[0] as raw:
                    raw.settimeout(8)
                    header=raw.recv(5,socket.MSG_PEEK|socket.MSG_WAITALL)
                    if len(header)!=5: raise RuntimeError("truncated TLS header")
                    size=5+int.from_bytes(header[3:5],"big")
                    record=raw.recv(size,socket.MSG_PEEK|socket.MSG_WAITALL)
                    if len(record)!=size: raise RuntimeError("truncated initial ClientHello")
                    inspect_hello(record)
                    if mode in ("forged-retry", "forged-final"):
                        if exact(raw,size)!=record: raise RuntimeError("ClientHello changed while peeking")
                        session_length=record[43]
                        session=record[44:44+session_length]
                        retry_random=bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
                        if mode=="forged-retry":
                            random=retry_random
                            extensions=bytes.fromhex("002b0002030400330002001d")
                        else:
                            random=bytes(range(32))
                            extensions=bytes.fromhex("002b0002030400330024001d0020")+bytes([9])*32
                        body=b"\x03\x03"+random+bytes([session_length])+session+b"\x13\x01\x00"+len(extensions).to_bytes(2,"big")+extensions
                        message=b"\x02"+len(body).to_bytes(3,"big")+body
                        raw.sendall(b"\x16\x03\x03"+len(message).to_bytes(2,"big")+message)
                        try:
                            reply=raw.recv(4096)
                        except ConnectionResetError:
                            reply=b""
                        if reply and reply[0]!=21:
                            raise RuntimeError("client sent unexpected data after forged ServerHello")
                        return
                    if strict:
                        try:
                            context.wrap_socket(raw,server_side=True)
                        except ssl.SSLError:
                            return
                        raise RuntimeError("X25519-only server unexpectedly negotiated TLS")
                    with context.wrap_socket(raw,server_side=True) as tls:
                        request=exact(tls,26)
                        if request[:18]!=bytes([0])+bytes(range(16))+b"\x00" or request[18:21]!=b"\x01\x04\xd2" or request[21:]!=b"\x01\x7f\x00\x00\x01":
                            raise RuntimeError(f"unexpected VLESS request: {request!r}")
                        tls.sendall(b"\x00\x00")
                        if exact(tls,len(payload))!=payload: raise RuntimeError("incorrect payload")
                        tls.sendall(payload)
                        try: tls.unwrap().close()
                        except (OSError,ssl.SSLError): pass
            except Exception as exc: errors.append(exc)
        thread=threading.Thread(target=peer); thread.start()
        config=root/"proxy.kdl"
        exchange="x25519-mlkem768-only" if strict else "x25519-mlkem768"
        server_host="edge.test" if mode in ("bootstrap", "bootstrap-chain") else "127.0.0.1"
        resolver='bootstrap-resolver "boot";' if mode in ("bootstrap", "bootstrap-chain") else ''
        dns_config=f'dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; }}' if mode in ("bootstrap", "bootstrap-chain") else ''
        if mode=="bootstrap-chain":
            dns_config=f'dns {{ server "root" type="udp" host="127.0.0.1" port={dns_root.getsockname()[1]}; server "boot" type="udp" host="leaf.test" port={dns.getsockname()[1]} domain-resolver="root"; strategy "ipv4_only"; }}'
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
{dns_config}
outbound "edge" type="vless" {{ {resolver} server host="{server_host}" port={upstream.getsockname()[1]}; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{cert}"; verify #true; key-exchange "{exchange}"; }}; }}
routing {{ final "edge"; }}
''')
        env=os.environ.copy()
        if len(sys.argv)>3: env["LD_PRELOAD"]=str(pathlib.Path(sys.argv[3]).resolve())
        process=subprocess.Popen([nexus,"run","--config",config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env)
        try:
            deadline=time.monotonic()+5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try: client=socket.create_connection(("127.0.0.1",port),timeout=.2); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(8); client.sendall(b"\x05\x01\x00")
                if exact(client,2)!=b"\x05\x00": raise RuntimeError("SOCKS negotiation failed")
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2"+payload)
                if strict:
                    received=bytearray()
                    try:
                        while True:
                            chunk=client.recv(1024)
                            if not chunk: break
                            received.extend(chunk)
                    except ConnectionResetError:
                        pass
                    if len(received)>=2 and received[:2]==b"\x05\x00":
                        raise RuntimeError("proxy reported successful connection on rejected TLS handshake")
                    thread.join(timeout=8)
                    if thread.is_alive() or errors: raise RuntimeError(f"upstream failure: {errors}")
                else:
                    response=exact(client,10)
                    if response[:2]!=b"\x05\x00":
                        thread.join(timeout=1); raise RuntimeError(f"SOCKS connect failed: {response!r}, upstream: {errors}")
                    if exact(client,len(payload))!=payload: raise RuntimeError(f"SOCKS transfer failed: {errors}")
            thread.join(timeout=8)
            if thread.is_alive() or errors: raise RuntimeError(f"upstream failure: {errors}")
            for dns_thread in dns_threads: dns_thread.join(timeout=8)
            if any(t.is_alive() for t in dns_threads) or len(dns_calls)!=len(dns_threads) or errors: raise RuntimeError(f"bootstrap failure: {errors}")
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            thread.join(timeout=9)
            for dns_thread in dns_threads: dns_thread.join(timeout=9)
        diagnostics=process.stderr.read().decode()
        if process.returncode!=0 or "unexpected-system-resolver" in diagnostics: raise RuntimeError(f"proxy exit: {process.returncode}, {diagnostics}")
print(f"{mode}: strict hybrid rejected X25519 downgrade" if strict else f"{mode}: hybrid fallback and VLESS transfer passed")
