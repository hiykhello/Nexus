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
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1")
    openssl("pkey","-in",str(key),"-outform","DER","-out",str(key_der))
    openssl("x509","-in",str(cert),"-outform","DER","-out",str(cert_der))
    key_der.chmod(0o600)
    uuid=root/"uuid"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    listener.bind(("127.0.0.1",0)); listener.listen(1)
    target.bind(("127.0.0.1",0)); target.listen(1); target.settimeout(6)
    reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]; reserved.close()
    config={"log":{"level":"warn"},
            "inbounds":[{"type":"socks","tag":"local","listen":"127.0.0.1","listen_port":port}],
            "outbounds":[{"type":"vless","tag":"edge","server":"127.0.0.1","server_port":listener.getsockname()[1],
                          "uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f", "tls":{"enabled":True,"server_name":"localhost","certificate_path":str(cert)}}],"route":{"final":"edge"}}
    path=pathlib.Path(directory)/"client.json"; path.write_text(json.dumps(config))
    subprocess.run(["sing-box","check","-c",path],check=True,capture_output=True)
    peer=subprocess.Popen([fixture,str(listener.fileno()),str(cert_der),str(key_der),str(uuid)],pass_fds=(listener.fileno(),))
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
            if not origin_ready.wait(5):
                raise RuntimeError(f"origin did not accept: fixture exit={peer.poll()}, origin errors={errors}")
            sender.join(timeout=.3)
            if not sender.is_alive(): raise RuntimeError(f"upload did not encounter backpressure: {errors}")
            release_origin.set()
            if exact(client,len(payload))!=payload: raise RuntimeError("incorrect response")
            if client.recv(1)!=b"": raise RuntimeError("missing download EOF")
            sender.join(timeout=6)
            if sender.is_alive(): raise RuntimeError("upload did not finish")
        if peer.wait(timeout=5)!=0: raise RuntimeError(f"inbound fixture failed: {peer.returncode}")
        thread.join(timeout=6)
        if thread.is_alive() or errors: raise RuntimeError(f"origin failure: {errors}")
    finally:
        failed = sys.exc_info()[0] is not None
        fixture_exit = peer.poll()
        release_origin.set()
        if peer.poll() is None: peer.kill(); peer.wait()
        box.terminate()
        try: _, box_stderr = box.communicate(timeout=5)
        except subprocess.TimeoutExpired: box.kill(); _, box_stderr = box.communicate()
        thread.join(timeout=6)
        if failed:
            print(f"fixture exit before cleanup: {fixture_exit}; origin errors: {errors}; "
                  f"sing-box stderr: {box_stderr.decode(errors='replace')}", file=sys.stderr)
print("Corosio VLESS/TLS inbound local transfer, backpressure and half-close passed")
