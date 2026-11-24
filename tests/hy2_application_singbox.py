#!/usr/bin/env python3
"""Fixed sing-box authenticates real Hy2 TCP client/server application paths."""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from quic_udp_network import credential,ready
from dns_rule_support import proxy_client,exact
from tcp_keepalive_network import reserve

REVISION="824dbcfb4dd0a95921840b1737b950cde590241e"
def payload(size,seed):return bytes((i*71+seed)%256 for i in range(size))
def connect(front):
    end=time.monotonic()+4
    while True:
        try:return socket.create_connection(("127.0.0.1",front),timeout=4)
        except ConnectionRefusedError:
            if time.monotonic()>=end:raise
            time.sleep(.02)

def socks(front,host,port):
    client=connect(front);client.settimeout(10)
    client.sendall(bytes([5,1,0]));assert exact(client,2)==bytes([5,0])
    raw=host.encode();client.sendall(bytes([5,1,0,3,len(raw)])+raw+port.to_bytes(2,"big"))
    head=exact(client,4);assert head[1]==0
    assert head[3] in (1,4);exact(client,6 if head[3]==1 else 18)
    return client

def pair(binary,root,cert,key,scheme,role,family,backend,total,standard_client=False):
    host="::1" if family=="6" else "127.0.0.1"
    af=socket.AF_INET6 if family=="6" else socket.AF_INET
    tls={"enabled":True,"server_name":"localhost","certificate_path":str(root/"cert.pem"),"alpn":["h3"]}
    if role=="server":
        cpp,port,first=ready([binary,role,family,0,cert,key,scheme,backend,total,"target.example:443","single"])
        try:
            with proxy_client(root,{"type":"hysteria2","server":host,"server_port":port,"password":"test-password","tls":tls,"disable_chrome_parrot":standard_client}) as front:
                with socks(front,"target.example",443) as client:
                    client.sendall(payload(total,37));client.shutdown(socket.SHUT_WR)
                    received=bytearray()
                    while chunk:=client.recv(65536):received.extend(chunk)
                    assert received==payload(total,19)
            output,error=cpp.communicate(timeout=13)
            if cpp.returncode:raise RuntimeError(f"Nexus server {cpp.returncode}: {first+output}{error}")
            return {"role":role,"family":family,"backend":backend,"bytes_each":total,"stdout":first+output,"stderr":error,"exit":cpp.returncode}
        except BaseException as failure:
            if cpp.poll() is None:cpp.kill()
            output,error=cpp.communicate()
            raise RuntimeError(f"peer exchange failed: {failure!r}; Nexus={first+output!r} stderr={error!r}") from failure
        finally:
            if cpp.poll() is None:cpp.kill();cpp.wait()
    listener=socket.socket(af,socket.SOCK_STREAM);listener.bind((host,0));listener.listen(1);listener.settimeout(10)
    target=listener.getsockname()[1];result={}
    def origin():
        try:
            with listener.accept()[0] as client:
                client.settimeout(10);client.sendall(payload(total,19));client.shutdown(socket.SHUT_WR)
                received=bytearray()
                while chunk:=client.recv(65536):received.extend(chunk)
                result["received"]=len(received);result["valid"]=received==payload(total,37)
        except BaseException as error:result["error"]=repr(error)
    thread=threading.Thread(target=origin);thread.start()
    port=reserve();config=root/"hy2-server.json"
    server_tls=dict(tls,key_path=str(root/"key.pem"));server_tls.pop("server_name")
    config.write_text(json.dumps({"log":{"level":"warn"},"inbounds":[{"type":"hysteria2","listen":host,"listen_port":port,
        "users":[{"name":"test","password":"test-password"}],"tls":server_tls}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}))
    box=subprocess.Popen(["sing-box","run","-c",str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    cpp=None
    try:
        time.sleep(.15)
        if box.poll() is not None:raise RuntimeError(box.communicate())
        address=f"[{host}]:{target}" if family=="6" else f"{host}:{target}"
        cpp,_,first=ready([binary,role,family,port,cert,key,scheme,backend,total,address,"single"])
        output,error=cpp.communicate(timeout=13);thread.join(timeout=12)
        if cpp.returncode or thread.is_alive() or not result.get("valid"):raise RuntimeError(f"Nexus client {cpp.returncode}: {first+output}{error} origin={result}")
        return {"role":role,"family":family,"backend":backend,"bytes_each":total,"stdout":first+output,"stderr":error,"exit":cpp.returncode,"origin":result}
    finally:
        if cpp and cpp.poll() is None:cpp.kill();cpp.wait()
        box.terminate();box.communicate(timeout=5);listener.close();thread.join(timeout=1)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("binary",type=Path);parser.add_argument("--report",type=Path,required=True);parser.add_argument("--quick",action="store_true")
    args=parser.parse_args();binary=args.binary.resolve(strict=True)
    version=subprocess.run(["sing-box","version"],capture_output=True,text=True,check=True).stdout
    if f"Revision: {REVISION}" not in version:raise RuntimeError("fixed peer revision mismatch")
    report={"complete":False,"expected":2 if args.quick else 24,"cases":[],"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"peer_revision":REVISION}
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-hy2-singbox-") as directory:
            root=Path(directory)
            for name,algorithm,options,scheme in [("p256","EC",["-pkeyopt","ec_paramgen_curve:P-256"],"0x0403")]+([] if args.quick else [
                    ("rsa","RSA",["-pkeyopt","rsa_keygen_bits:2048"],"0x0804"),("ed25519","ED25519",[],"0x0807")]):
                cert,key=credential(root,name,algorithm,options)
                subprocess.run(["openssl","x509","-inform","DER","-in",cert,"-out",root/"cert.pem"],check=True,capture_output=True)
                subprocess.run(["openssl","pkey","-inform","DER","-in",key,"-out",root/"key.pem"],check=True,capture_output=True)
                for role in ["client","server"]:
                    for family in (["4"] if args.quick else ["4","6"]):
                        for backend in (["0"] if args.quick else ["0","1"]):
                            record=pair(binary,root,cert,key,scheme,role,family,backend,65537,standard_client=name=="ed25519" and role=="server")
                            record["peer_chrome_parrot"]=not(name=="ed25519" and role=="server")
                            record["algorithm"]=name;report["cases"].append(record)
                            print(name,role,family,backend,"fixed sing-box authenticated TCP/half-close passed",flush=True)
        report["complete"]=len(report["cases"])==report["expected"]
    finally:args.report.write_text(json.dumps(report,indent=2)+"\n")
if __name__=="__main__":main()
