"""Seven implemented TLS1.3 signature schemes against independent OpenSSL."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

def run(*command):
    return subprocess.run([str(x) for x in command],text=True,capture_output=True,check=True,timeout=20)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("unit",type=Path)
    parser.add_argument("client",type=Path)
    parser.add_argument("report",type=Path)
    args=parser.parse_args();unit=args.unit.resolve();client=args.client.resolve();records=[]
    cases=(
        ("RSA",["-pkeyopt","rsa_keygen_bits:2048"],"rsa_pss_rsae_sha256",0x0804,"sha256"),
        ("RSA",["-pkeyopt","rsa_keygen_bits:2048"],"rsa_pss_rsae_sha384",0x0805,"sha384"),
        ("RSA",["-pkeyopt","rsa_keygen_bits:2048"],"rsa_pss_rsae_sha512",0x0806,"sha512"),
        ("EC",["-pkeyopt","ec_paramgen_curve:P-256"],"ecdsa_secp256r1_sha256",0x0403,"sha256"),
        ("EC",["-pkeyopt","ec_paramgen_curve:P-384"],"ecdsa_secp384r1_sha384",0x0503,"sha384"),
        ("EC",["-pkeyopt","ec_paramgen_curve:P-521"],"ecdsa_secp521r1_sha512",0x0603,"sha512"),
        ("ED25519",[],"ed25519",0x0807,None))
    def save():
        args.report.write_text(json.dumps({"complete":len(records)==259,"expected":259,"cases":records,"binaries":{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (unit,client)}},indent=2)+"\n")
    with tempfile.TemporaryDirectory(prefix="nexus-signatures-") as directory:
        root=Path(directory)
        run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",root/"ca.key","-out",root/"ca.pem","-days","1","-subj","/CN=Signature CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign")
        run("openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes","-keyout",root/"wrong.key","-out",root/"wrong.pem","-days","1","-subj","/CN=Wrong CA","-addext","basicConstraints=critical,CA:TRUE")
        (root/"ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n")
        data=root/"input";data.write_bytes(b" "*64+b"TLS 1.3, server CertificateVerify\0"+bytes([0x42])*32)
        for algorithm,options,name,scheme,digest in cases:
            run("openssl","genpkey","-algorithm",algorithm,*options,"-out",root/"key.pem")
            run("openssl","pkey","-in",root/"key.pem","-outform","DER","-out",root/"key.der")
            run("openssl","pkey","-in",root/"key.pem","-pubout","-out",root/"public.pem")
            run("openssl","req","-new","-key",root/"key.pem","-out",root/"server.csr","-subj","/CN=server.example")
            run("openssl","x509","-req","-in",root/"server.csr","-CA",root/"ca.pem","-CAkey",root/"ca.key","-set_serial","2","-days","1","-extfile",root/"ext","-out",root/"server.pem")
            run("openssl","x509","-in",root/"server.pem","-outform","DER","-out",root/"server.der")
            checked=run(unit,root/"server.der",root/"key.der",hex(scheme),root/"signature",root/"ca.pem")
            if algorithm=="ED25519":run("openssl","pkeyutl","-verify","-pubin","-inkey",root/"public.pem","-rawin","-in",data,"-sigfile",root/"signature")
            else:
                options=["-sigopt","rsa_padding_mode:pss","-sigopt",f"rsa_pss_saltlen:{int(digest[3:])//8}","-sigopt",f"rsa_mgf1_md:{digest}"] if algorithm=="RSA" else []
                run("openssl","dgst","-"+digest,"-verify",root/"public.pem","-signature",root/"signature",*options,data)
            records.append({"kind":"signature-unit+OpenSSL-oracle","scheme":hex(scheme),"exit":0,"stdout":checked.stdout});save()
            for cipher in ("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"):
              for mode,group in (("x25519","X25519"),("hybrid","X25519MLKEM768"),("x25519-retry","X25519"),("hybrid-retry","X25519MLKEM768")):
               for identity in ("valid","wrong","untrusted"):
                with socket.socket() as reserve:reserve.bind(("127.0.0.1",0));port=reserve.getsockname()[1]
                server=subprocess.Popen(["openssl","s_server","-accept",f"127.0.0.1:{port}","-tls1_3","-cert",str(root/"server.pem"),"-key",str(root/"key.pem"),"-sigalgs",name,"-groups",group,"-ciphersuites",cipher,"-alpn","http/1.1","-www"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:
                    deadline=time.monotonic()+5
                    while True:
                        try:peer=socket.create_connection(("127.0.0.1",port),timeout=5);break
                        except ConnectionRefusedError:
                            if server.poll() is not None or time.monotonic()>deadline:raise
                            time.sleep(.01)
                    with peer:
                        peer.settimeout(None)
                        result=subprocess.run([str(client),mode,str(root/("wrong.pem" if identity=="untrusted" else "ca.pem")),identity,"randomized",hex(scheme)],stdin=peer,stdout=peer,stderr=subprocess.PIPE,timeout=10)
                    if result.returncode:raise RuntimeError(f"{name} {cipher} {mode} {identity}: {result.returncode} {result.stderr.decode()}")
                    records.append({"kind":"authenticated-TLS","scheme":hex(scheme),"cipher":cipher,"mode":mode,"identity":identity,"exit":result.returncode});save()
                finally:
                    server.terminate()
                    try:server.communicate(timeout=2)
                    except subprocess.TimeoutExpired:server.kill();server.communicate()
            print(name,"unit/OpenSSL sign oracle and36 authenticated handshake/identity trials passed",flush=True)
if __name__=="__main__":main()
