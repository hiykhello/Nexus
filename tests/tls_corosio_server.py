#!/usr/bin/env python3
import pathlib
import socket
import subprocess
import sys
import tempfile

fixture=pathlib.Path(sys.argv[1]).resolve()
def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
with tempfile.TemporaryDirectory(prefix="nexus-tls-corosio-server-") as directory:
    root=pathlib.Path(directory); key=root/"key.pem"; key_der=root/"key.der"; cert=root/"cert.pem"; cert_der=root/"cert.der"
    run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-days","1")
    run("openssl","pkey","-in",str(key),"-outform","DER","-out",str(key_der))
    run("openssl","x509","-in",str(cert),"-outform","DER","-out",str(cert_der))
    run(str(fixture),str(cert_der),str(key_der),"failures")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0)); listener.listen(1)
        server=subprocess.Popen([fixture,cert_der,key_der,str(listener.fileno())],pass_fds=(listener.fileno(),))
        try:
            result=subprocess.run(["openssl","s_client","-connect",f"127.0.0.1:{listener.getsockname()[1]}","-tls1_3","-groups","X25519","-servername","localhost","-verify_hostname","localhost","-verify_return_error","-CAfile",str(cert),"-quiet"],input=b"hello",capture_output=True,timeout=8)
            code=server.wait(timeout=5)
            if code or result.returncode or result.stdout!=b"hello": raise RuntimeError(f"server={code} openssl={result.returncode} output={result.stdout!r} error={result.stderr!r}")
        finally:
            if server.poll() is None: server.kill(); server.wait()
print("Corosio TLS server OpenSSL exchange, timeout and cancellation passed")
