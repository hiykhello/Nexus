#!/usr/bin/env python3
"""Inject relay start and coroutine failures through real TLS connections."""
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time

binary=pathlib.Path(sys.argv[1]).resolve()
user=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
with tempfile.TemporaryDirectory(prefix="nexus-relay-throw-") as directory:
    root=pathlib.Path(directory)
    key,cert,keyder,certder=(root/name for name in ("key.pem","cert.pem","key.der","cert.der"))
    def openssl(*args): subprocess.run(["openssl",*map(str,args)],check=True,capture_output=True,timeout=10)
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1")
    openssl("pkey","-in",key,"-outform","DER","-out",keyder)
    openssl("x509","-in",cert,"-outform","DER","-out",certder)
    keyder.chmod(0o600)
    uuid=root/"uuid"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
    context=ssl.create_default_context(cafile=str(cert)); context.minimum_version=ssl.TLSVersion.TLSv1_3
    for point in range(1,5):
        with socket.socket() as hold, socket.socket() as target:
            hold.bind(("127.0.0.1",0)); port=hold.getsockname()[1]; hold.close()
            target.bind(("127.0.0.1",0)); target.listen(); target.settimeout(5)
            config=root/"config.kdl"
            config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ vless "edge" {{ listen host="127.0.0.1" port={port}; authentication {{ user "u" uuid-file="{uuid}"; }}; tls {{ certificate-file "{certder}"; private-key-file "{keyder}"; }}; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
            env=os.environ.copy(); env["NEXUS_TEST_VLESS_RELAY_THROW"]=str(point)
            server=subprocess.Popen([binary,"run","--config",config],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+5
                while True:
                    if server.poll() is not None: raise RuntimeError(server.stderr.read().decode())
                    try:
                        with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                    except OSError:
                        if time.monotonic()>=deadline: raise
                        time.sleep(.02)
                for i in range(70):
                    with context.wrap_socket(socket.create_connection(("127.0.0.1",port),timeout=5),server_hostname="localhost") as client:
                        client.settimeout(5)
                        client.sendall(b"\x00"+user+b"\x00\x01"+target.getsockname()[1].to_bytes(2,"big")+b"\x01\x7f\x00\x00\x01")
                        with target.accept()[0] as peer:
                            peer.settimeout(5)
                            try:
                                while client.recv(4096): pass
                            except (ConnectionResetError,ssl.SSLError): pass
                            if peer.recv(1)!=b"": raise RuntimeError(f"point {point}: target remained open")
                    if server.poll() is not None: raise RuntimeError(f"point {point}: server exited: {server.stderr.read().decode()}")
                server.terminate()
                if server.wait(timeout=5)!=0: raise RuntimeError(server.stderr.read().decode())
            finally:
                if server.poll() is None: server.kill(); server.wait()
print("VLESS relay launch and coroutine exceptions close sessions and recover quota")
