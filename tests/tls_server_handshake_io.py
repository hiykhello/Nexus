#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="nexus-server-handshake-io-") as directory:
    root=pathlib.Path(directory); key=root/"key.pem"; key_der=root/"key.der"; cert=root/"cert.der"
    def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
    run("openssl","genpkey","-algorithm","ED25519","-out",str(key))
    run("openssl","pkey","-in",str(key),"-outform","DER","-out",str(key_der))
    run("openssl","req","-new","-x509","-key",str(key),"-subj","/CN=localhost","-days","1","-outform","DER","-out",str(cert))
    subprocess.run([str(pathlib.Path(sys.argv[1]).resolve()),str(cert),str(key_der)],check=True,timeout=10)
    large_cert=root/"large.der"
    extension="1.2.3.4=DER:"+":".join(["AA"]*20000)
    run("openssl","req","-new","-x509","-key",str(key),"-subj","/CN=localhost","-days","1",
        "-addext",extension,"-outform","DER","-out",str(large_cert))
    subprocess.run([str(pathlib.Path(sys.argv[1]).resolve()),str(large_cert),str(key_der),"large"],check=True,timeout=30)
