#!/usr/bin/env python3
"""Real Hy2 UDP fragmentation/empty datagrams against the pinned sing-box."""
import argparse
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
from dns_rule_support import proxy_client,udp_client
from tcp_keepalive_network import reserve
from hy2_application_singbox import REVISION,payload
NATIVE_PEER=Path(__file__).resolve().parent/'hy2-peer/hy2-library-peer'

def pair(binary,root,cert,key,scheme,role,family,backend,size,standard):
    host="::1" if family=="6" else "127.0.0.1";af=socket.AF_INET6 if family=="6" else socket.AF_INET
    tls={"enabled":True,"server_name":"localhost","certificate_path":str(root/"cert.pem"),"alpn":["h3"]}
    processes=[]
    if role=="server":
        cpp,port,first=ready([binary,role,family,0,cert,key,scheme,backend,size,"target.example:443","single"]);processes.append(cpp)
        try:
            if size==0:
                # The fixed SOCKS wrapper drops an empty datagram. Exercise
                # the unchanged independent sing-quic Client packet API.
                peer=NATIVE_PEER.resolve(strict=True)
                done=subprocess.run([peer,family,str(port),cert,str(size)],capture_output=True,text=True,timeout=12)
                output,error=cpp.communicate(timeout=12)
                if done.returncode or cpp.returncode:raise RuntimeError(f'native peer={done.returncode} {done.stdout}{done.stderr}; Nexus={first+output}{error}')
                return {'role':role,'family':family,'backend':backend,'size':size,'stdout':first+output,'stderr':error,'exit':cpp.returncode,'peer_api':'fixed sing-quic native Client.ListenPacket','peer_stdout':done.stdout,'peer_sha256':hashlib.sha256(peer.read_bytes()).hexdigest()}
            outbound={"type":"hysteria2","server":host,"server_port":port,"password":"test-password","tls":tls,"disable_chrome_parrot":standard}
            with proxy_client(root,outbound) as front,udp_client(front) as (client,relay):
                raw=b"target.example";header=bytes([0,0,0,3,len(raw)])+raw+bytes([1,187]);data=payload(size,37)
                client.settimeout(.25 if size==0 else 8);client.sendto(header+data,relay)
                missing_empty=False
                try:packet=client.recvfrom(65535)[0]
                except TimeoutError:
                    if size!=0:raise
                    missing_empty=True
                else:
                    if packet!=header+data:raise RuntimeError("Hy2 UDP response address/boundary mismatch")
                client.sendto(header+bytes([0xa5]),relay)
                # Keep the actual peer alive until the application observes the
                # confirmation. Closing this context first cancels queued UDP.
                output,error=cpp.communicate(timeout=12)
            if cpp.returncode:raise RuntimeError(f"Nexus server {cpp.returncode}: {first+output}{error}")
            return {"role":role,"family":family,"backend":backend,"size":size,"stdout":first+output,"stderr":error,"exit":cpp.returncode,"socks_empty_reply_missing":missing_empty}
        except BaseException as failure:
            if cpp.poll() is None:cpp.kill()
            output,error=cpp.communicate();raise RuntimeError(f"exchange {failure!r}; Nexus={first+output!r} stderr={error!r}") from failure
        finally:
            if cpp.poll() is None:cpp.kill();cpp.wait()
    origin=socket.socket(af,socket.SOCK_DGRAM);origin.bind((host,0));origin.settimeout(10);result={}
    def echo():
        try:
            wire,source=origin.recvfrom(65535);result["size"]=len(wire);result["valid"]=wire==payload(size,37);origin.sendto(wire,source)
            confirm,confirmation_source=origin.recvfrom(65535);result["confirmation"]=confirm==bytes([0xa5]) and confirmation_source==source
        except BaseException as error:result["error"]=repr(error)
    thread=threading.Thread(target=echo);thread.start()
    port=reserve();config=root/"udp-server.json";server_tls=dict(tls,key_path=str(root/"key.pem"));server_tls.pop("server_name")
    config.write_text(json.dumps({"log":{"level":"warn"},"inbounds":[{"type":"hysteria2","listen":host,"listen_port":port,"users":[{"name":"test","password":"test-password"}],"tls":server_tls}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}))
    box=subprocess.Popen(["sing-box","run","-c",config],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);cpp=None
    try:
        time.sleep(.15)
        if box.poll() is not None:raise RuntimeError(box.communicate())
        target=origin.getsockname()[1];address=f"[{host}]:{target}" if family=="6" else f"{host}:{target}"
        cpp,_,first=ready([binary,role,family,port,cert,key,scheme,backend,size,address,"single"]);output,error=cpp.communicate(timeout=12);thread.join(timeout=11)
        if cpp.returncode or thread.is_alive() or not result.get("valid") or not result.get("confirmation"):raise RuntimeError(f"Nexus client {cpp.returncode}: {first+output}{error}; origin={result}")
        return {"role":role,"family":family,"backend":backend,"size":size,"stdout":first+output,"stderr":error,"exit":cpp.returncode,"origin":result}
    finally:
        if cpp and cpp.poll() is None:cpp.kill();cpp.wait()
        box.terminate();box.communicate(timeout=5);origin.close();thread.join(timeout=1)

def main():
    global NATIVE_PEER
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("binary",type=Path);parser.add_argument("--report",type=Path,required=True);parser.add_argument("--quick",action="store_true")
    parser.add_argument('--native-peer',type=Path,default=NATIVE_PEER)
    args=parser.parse_args();binary=args.binary.resolve(strict=True)
    NATIVE_PEER=args.native_peer
    version=subprocess.run(["sing-box","version"],capture_output=True,text=True,check=True).stdout
    if f"Revision: {REVISION}" not in version:raise RuntimeError("fixed peer mismatch")
    report={"complete":False,"expected":2 if args.quick else 48,"cases":[],"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"peer_revision":REVISION,
            "peer_limit":"fixed sing-quic WritePacket caps user UDP payload to4096; Nexus pairs separately verify65000. Fixed sing-box SOCKS client empty reply can be lost; native-library peer verifies empty positive separately"}
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-hy2-udp-singbox-") as directory:
            root=Path(directory)
            for name,algorithm,options,scheme in [("p256","EC",["-pkeyopt","ec_paramgen_curve:P-256"],"0x0403")]+([] if args.quick else [("rsa","RSA",["-pkeyopt","rsa_keygen_bits:2048"],"0x0804"),("ed25519","ED25519",[],"0x0807")]):
                cert,key=credential(root,name,algorithm,options);subprocess.run(["openssl","x509","-inform","DER","-in",cert,"-out",root/"cert.pem"],capture_output=True,check=True);subprocess.run(["openssl","pkey","-inform","DER","-in",key,"-out",root/"key.pem"],capture_output=True,check=True)
                for role in ["client","server"]:
                    for family in (["4"] if args.quick else ["4","6"]):
                        for backend in (["0"] if args.quick else ["0","1"]):
                            for size in ([4096] if args.quick else [0,4096]):
                                record=pair(binary,root,cert,key,scheme,role,family,backend,size,name=="ed25519" and role=="server");record["algorithm"]=name;report["cases"].append(record)
                                print(name,role,family,backend,size,"fixed sing-box Hy2 UDP packet passed",flush=True)
        report["complete"]=len(report["cases"])==report["expected"]
    finally:args.report.write_text(json.dumps(report,indent=2)+"\n")
if __name__=="__main__":main()
