#!/usr/bin/env python3
"""Independent VLESS/TLS client through a local test relay."""
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
workers = int(sys.argv[2]) if len(sys.argv)>2 else 1
chain = "chain" in sys.argv[3:]
pem = "pem" in sys.argv[3:]
longchain = "longchain" in sys.argv[3:]
systembundle = "systembundle" in sys.argv[3:]
largecert = "largecert" in sys.argv[3:]
hybrid = "hybrid" in sys.argv[3:]
if longchain and (not pem or not chain):
    raise ValueError("longchain requires chain and pem")
if systembundle and not chain:
    raise ValueError("systembundle requires chain")
if largecert and (not chain or pem):
    raise ValueError("largecert requires chain and DER credentials")
if hybrid and not chain:
    raise ValueError("hybrid requires chain")
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock, size):
    result=bytearray()
    while len(result)<size:
        data=sock.recv(size-len(result))
        if not data: raise RuntimeError("unexpected EOF")
        result.extend(data)
    return bytes(result)

with tempfile.TemporaryDirectory(prefix="nexus-vless-async-inbound-") as directory, socket.socket() as listener, socket.socket() as target, socket.socket() as reserved:
    root=pathlib.Path(directory); key=root/"key.pem"; key_der=root/"key.der"; cert=root/"cert.pem"; cert_der=root/"cert.der"
    def openssl(*args): subprocess.run(["openssl",*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
    ca=root/"ca.pem"; ca_key=root/"ca-key.pem"; csr=root/"server.csr"; ext=root/"server.ext"
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(ca_key),"-out",str(ca),"-subj","/CN=Test CA","-days","1")
    openssl("req","-new","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(csr),"-subj","/CN=localhost")
    ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    issuer,issuer_key=ca,ca_key
    if pem:
        issuer=root/"intermediate.pem"; issuer_key=root/"intermediate-key.pem"; intermediate_csr=root/"intermediate.csr"; intermediate_ext=root/"intermediate.ext"
        openssl("req","-new","-newkey","rsa:2048","-nodes","-keyout",str(issuer_key),"-out",str(intermediate_csr),"-subj","/CN=Test Intermediate")
        intermediate_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
        openssl("x509","-req","-in",str(intermediate_csr),"-CA",str(ca),"-CAkey",str(ca_key),"-CAcreateserial","-out",str(issuer),"-days","1","-extfile",str(intermediate_ext))
    openssl("x509","-req","-in",str(csr),"-CA",str(issuer),"-CAkey",str(issuer_key),"-CAcreateserial","-out",str(cert),"-days","1","-extfile",str(ext))
    openssl("pkey","-in",str(key),"-outform","DER","-out",str(key_der))
    openssl("x509","-in",str(cert),"-outform","DER","-out",str(cert_der))
    trust=ca
    if systembundle:
        trust=root/"trust.pem"
        system=pathlib.Path("/etc/ssl/certs/ca-certificates.crt").read_text()
        if system.count("-----BEGIN CERTIFICATE-----") <= 64:
            raise RuntimeError("system trust bundle does not exercise the former 64-anchor limit")
        trust.write_text(ca.read_text()+system)
    key_der.chmod(0o600); key.chmod(0o600)
    fullchain=root/"fullchain.pem"
    if pem:
        fullchain.write_text(cert.read_text()+issuer.read_text())
        if longchain:
            for serial in range(1, 15):
                extra=root/f"extra-{serial}.pem"
                openssl("x509","-req","-in",str(intermediate_csr),"-CA",str(ca),"-CAkey",str(ca_key),"-set_serial",str(serial),"-out",str(extra),"-days","1","-extfile",str(intermediate_ext))
                with fullchain.open("a") as out: out.write(extra.read_text())
        without=subprocess.run(["openssl","verify","-CAfile",str(ca),str(cert)],capture_output=True)
        if without.returncode==0: raise RuntimeError("leaf unexpectedly verifies without intermediate")
        openssl("verify","-CAfile",str(ca),"-untrusted",str(issuer),str(cert))
    server_cert=fullchain if pem else cert_der
    server_key=key if pem else key_der
    downstream_cert=server_cert
    if largecert:
        large_ext=root/"large.ext"; downstream_cert=root/"large.der"; too_large=root/"too-large.der"
        base=ext.read_text()
        def make_large(path, padding):
            large_ext.write_text(base+"1.2.3.4=ASN1:UTF8String:"+"x"*padding+"\n")
            openssl("x509","-req","-in",str(csr),"-CA",str(ca),"-CAkey",str(ca_key),"-set_serial","1234","-out",str(path),"-outform","DER","-days","1","-extfile",str(large_ext))
        padding=1047000
        make_large(downstream_cert,padding)
        padding+=1048571-downstream_cert.stat().st_size
        make_large(downstream_cert,padding)
        make_large(too_large,padding+1)
        if downstream_cert.stat().st_size!=1048571 or too_large.stat().st_size!=1048572:
            raise RuntimeError("could not construct exact-size DER certificates")
    uuid=root/"uuid"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    listener.bind(("127.0.0.1",0)); server_port=listener.getsockname()[1]; listener.close()
    target.bind(("127.0.0.1",0)); target.listen(1); target.settimeout(6)
    reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
    config={"log":{"level":"warn"},
            "inbounds":[{"type":"socks","tag":"local","listen":"127.0.0.1","listen_port":port}],
            "outbounds":[{"type":"vless","tag":"edge","server":"127.0.0.1","server_port":server_port,
                          "uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f", "tls":{"enabled":True,"server_name":"localhost","certificate_path":str(ca)}}],"route":{"final":"edge"}}
    path=pathlib.Path(directory)/"client.json"; path.write_text(json.dumps(config))
    subprocess.run(["sing-box","check","-c",path],check=True,capture_output=True)
    downstream=None
    outbound='direct "direct";'
    final='direct'
    if chain:
        with socket.socket() as hold:
            hold.bind(("127.0.0.1",0)); downstream_port=hold.getsockname()[1]
        downstream_config=root/"downstream.kdl"
        downstream_config.write_text(f'''schema-version 1
role "server"
inbounds {{ vless "edge" {{ listen host="127.0.0.1" port={downstream_port}; authentication {{ user "client" uuid-file="{uuid}"; }}; tls {{ certificate-file "{downstream_cert}"; private-key-file "{server_key}"; }}; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        if largecert:
            bad_config=root/"too-large.kdl"
            bad_config.write_text(downstream_config.read_text().replace(str(downstream_cert),str(too_large)))
            try:
                rejected=subprocess.run([fixture,"run","--config",bad_config],capture_output=True,timeout=3)
            except subprocess.TimeoutExpired:
                raise RuntimeError("oversized certificate was accepted at startup") from None
            if rejected.returncode==0 or b"invalid or mismatched TLS credential" not in rejected.stderr:
                raise RuntimeError(f"unexpected oversized certificate result: {rejected.stderr.decode()}")
        downstream=subprocess.Popen([fixture,"run","--config",downstream_config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        deadline=time.monotonic()+5
        while True:
            if downstream.poll() is not None: raise RuntimeError(downstream.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1",downstream_port),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        exchange=' key-exchange "x25519-mlkem768";' if hybrid else ''
        outbound+=f' vless "next" {{ server host="127.0.0.1" port={downstream_port}; authentication {{ uuid-file "{uuid}"; }}; tls {{ server-name "localhost"; ca-file "{trust}"; verify #true;{exchange} }}; }};'
        final='next'
    server_config=root/"server.kdl"
    server_config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{ vless "edge" {{
  listen host="127.0.0.1" port={server_port}
  authentication {{ user "client" uuid-file="{uuid}"; }}
  tls {{ certificate-file "{server_cert}"; private-key-file "{server_key}"; }}
}} }}
outbounds {{ {outbound} }}
routing {{ default-outbound "{final}"; }}
''')
    if pem:
        valid_chain=fullchain.read_text()
        for invalid in (valid_chain+cert.read_text(), valid_chain+"garbage\n"):
            fullchain.write_text(invalid)
            rejected=subprocess.run([fixture,"run","--config",server_config],capture_output=True,timeout=5)
            if rejected.returncode==0: raise RuntimeError("invalid certificate chain accepted")
        fullchain.write_text(valid_chain+" \t\n")
    peer=subprocess.Popen([fixture,"run","--config",server_config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    deadline=time.monotonic()+5
    while True:
        if peer.poll() is not None: raise RuntimeError(peer.stderr.read().decode())
        try:
            with socket.create_connection(("127.0.0.1",server_port),timeout=.2): break
        except OSError:
            if time.monotonic()>=deadline: raise
            time.sleep(.02)
    box=subprocess.Popen(["sing-box","run","-c",path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    errors=[]
    payload=b"hello"*6710887
    origin_ready=threading.Event()
    release_origin=threading.Event()
    def origin():
        try:
            with target.accept()[0] as conn:
                conn.settimeout(5)
                origin_ready.set()
                if not release_origin.wait(5): raise RuntimeError("origin was not released")
                received=0
                while True:
                    data=conn.recv(8192)
                    if not data: break
                    if data!=payload[received:received+len(data)]: raise RuntimeError("incorrect upload")
                    received+=len(data)
                    conn.sendall(data)
                if received!=len(payload): raise RuntimeError("truncated upload")
                conn.shutdown(socket.SHUT_WR)
        except Exception as exc: errors.append(exc)
    thread=threading.Thread(target=origin); thread.start()
    try:
        deadline=time.monotonic()+5
        while True:
            if box.poll() is not None: raise RuntimeError(box.stderr.read().decode())
            try:
                client=socket.create_connection(("127.0.0.1",port),timeout=.2); break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        with client:
            client.settimeout(5); client.sendall(b"\x05\x01\x00")
            if exact(client,2)!=b"\x05\x00": raise RuntimeError("SOCKS greeting failed")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+target.getsockname()[1].to_bytes(2,"big"))
            head=exact(client,4)
            if head[1]!=0: raise RuntimeError(f"SOCKS connect failed: {head!r}")
            exact(client,6 if head[3]==1 else 18)
            def upload():
                try:
                    client.sendall(payload)
                    client.shutdown(socket.SHUT_WR)
                except Exception as exc: errors.append(exc)
            sender=threading.Thread(target=upload); sender.start()
            if not origin_ready.wait(5): raise RuntimeError(f"origin did not accept: {errors}, sender alive={sender.is_alive()}, server={peer.poll()}, downstream={downstream.poll() if downstream else None}")
            sender.join(timeout=.3)
            if not sender.is_alive(): raise RuntimeError(f"upload did not encounter backpressure: {errors}")
            release_origin.set()
            if exact(client,len(payload))!=payload: raise RuntimeError("incorrect response")
            if client.recv(1)!=b"": raise RuntimeError("missing download EOF")
            sender.join(timeout=6)
            if sender.is_alive(): raise RuntimeError("upload did not finish")
        peer.terminate()
        if peer.wait(timeout=5)!=0: raise RuntimeError(f"inbound server failed: {peer.returncode}: {peer.stderr.read().decode()}")
        thread.join(timeout=6)
        if thread.is_alive() or errors: raise RuntimeError(f"origin failure: {errors}")
    finally:
        release_origin.set()
        if peer.poll() is None: peer.kill(); peer.wait()
        if downstream is not None:
            downstream.terminate()
            if downstream.wait(timeout=5)!=0: raise RuntimeError(downstream.stderr.read().decode())
        box.terminate()
        try: box.communicate(timeout=5)
        except subprocess.TimeoutExpired: box.kill(); box.communicate()
        thread.join(timeout=6)
print("configured VLESS/TLS inbound local transfer, backpressure and half-close passed")
