"""Verify the same shaped TLS policy authenticates real fixed Reality peers."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

REVISION="824dbcfb4dd0a95921840b1737b950cde590241e"
PAYLOAD=b"Reality VLESS bidirectional payload"

def reserve():
    with socket.socket() as peer:
        peer.bind(("127.0.0.1",0));return peer.getsockname()[1]

def check(*arguments):
    return subprocess.run(arguments,text=True,capture_output=True,check=True).stdout

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("binary",type=Path)
    parser.add_argument("report",type=Path)
    parser.add_argument("--xray",type=Path)
    args=parser.parse_args()
    binary=args.binary.resolve();results=[]
    if args.xray:
        peer=args.xray.resolve()
        version=check("go","version","-m",str(peer))
        if "\tmod\tgithub.com/xtls/xray-core\tv1.260327.0\th1:g4TzxMwyPrxslZh6uD+FiG3lXKTrnNO+b4ky2OhogHE=" not in version: raise RuntimeError("unexpected Xray")
        keys=check(str(peer),"x25519")
    else:
        peer=Path("/usr/bin/sing-box")
        version=check(str(peer),"version")
        if f"Revision: {REVISION}" not in version:raise RuntimeError("unexpected sing-box")
        keys=check(str(peer),"generate","reality-keypair")
    key_values=dict(line.split(": ",1) for line in keys.splitlines() if ": " in line)
    public=key_values["Password (PublicKey)" if args.xray else "PublicKey"]
    public=base64.urlsafe_b64decode(public+"=").hex()
    with tempfile.TemporaryDirectory(prefix="nexus-fingerprint-reality-") as directory:
        root=Path(directory)
        check("openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(root/"key"),"-out",str(root/"cert"),"-subj","/CN=cover.example","-days","1")
        for profile in ("grease","randomized"):
          for mode in ("x25519","hybrid","dual"):
           for group in ("X25519","X25519MLKEM768"):
            front,backend=reserve(),reserve()
            while backend==front:backend=reserve()
            server=None;client=None;observed={};origin_data=[]
            cover=subprocess.Popen(["openssl","s_server","-quiet","-ign_eof","-accept",str(backend),"-cert",str(root/"cert"),"-key",str(root/"key"),"-groups",group],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            if args.xray:
                config={"log":{"loglevel":"error"},"inbounds":[{"listen":"127.0.0.1","port":front,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"target":f"127.0.0.1:{backend}","serverNames":["cover.example"],"privateKey":key_values["PrivateKey"],"shortIds":["0123456789abcdef"]}}}],"outbounds":[{"protocol":"freedom"}]}
            else:
                config={"log":{"level":"error"},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":front,"users":[{"uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f"}],"tls":{"enabled":True,"server_name":"cover.example","reality":{"enabled":True,"handshake":{"server":"127.0.0.1","server_port":backend},"private_key":key_values["PrivateKey"],"short_id":["0123456789abcdef"]}}}],"outbounds":[{"type":"direct"}]}
            path=root/"config.json";path.write_text(json.dumps(config))
            origin=socket.socket();origin.bind(("127.0.0.1",0));origin.listen(1);origin.settimeout(12)
            def echo():
                try:
                    with origin.accept()[0] as connection:
                        connection.settimeout(10);data=b""
                        while len(data)<len(PAYLOAD):
                            part=connection.recv(4096)
                            if not part:break
                            data+=part
                        origin_data.append(data);connection.sendall(data)
                except OSError as error:origin_data.append(repr(error))
            worker=threading.Thread(target=echo,daemon=True);worker.start()
            try:
                time.sleep(.1)
                if cover.poll() is not None:raise RuntimeError("cover exited")
                command=[str(peer),"run","-config",str(path)] if args.xray else [str(peer),"run","-c",str(path)]
                server=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                deadline=time.monotonic()+5
                while True:
                    try:connection=socket.create_connection(("127.0.0.1",front),timeout=5);break
                    except ConnectionRefusedError:
                        if server.poll() is not None or time.monotonic()>deadline:raise
                        time.sleep(.02)
                with connection:
                    connection.settimeout(None)
                    client=subprocess.Popen([str(binary),public,"cover.example","0123456789abcdef",mode,profile,str(origin.getsockname()[1])],stdin=connection,stdout=connection,stderr=subprocess.PIPE,restore_signals=False)
                    _,error=client.communicate(timeout=15)
                    observed={"profile":profile,"shares":mode,"cover_group":group,"exit":client.returncode,"stderr":error.decode(errors="replace")}
                    forced_retry=(mode=="x25519" and group=="X25519MLKEM768") or (mode=="hybrid" and group=="X25519")
                    observed["expected_cover_hrr_rejection"]=forced_retry
                    if forced_retry:
                        if client.returncode!=8 or origin_data:raise RuntimeError(f"forced-HRR rejection differs: {observed} {origin_data}")
                    elif client.returncode:
                        raise RuntimeError(json.dumps(observed))
                if not observed["expected_cover_hrr_rejection"]:
                    worker.join(12)
                    if worker.is_alive() or origin_data!=[PAYLOAD]:raise RuntimeError(f"origin failed {origin_data}")
                results.append(observed)
                args.report.write_text(json.dumps({"complete":len(results)==12,"cases":results,"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"peer_sha256":hashlib.sha256(peer.read_bytes()).hexdigest(),"peer_version":version},indent=2)+"\n")
                print(profile,mode,group,"forced cover HRR rejected" if observed["expected_cover_hrr_rejection"] else "Reality authentication and bidirectional VLESS passed",flush=True)
            finally:
                if client and client.poll() is None:client.kill();client.communicate()
                if server:
                    server.terminate()
                    try:server.communicate(timeout=2)
                    except subprocess.TimeoutExpired:server.kill();server.communicate()
                cover.terminate()
                try:cover.communicate(timeout=2)
                except subprocess.TimeoutExpired:cover.kill();cover.communicate()
                origin.close()
if __name__=="__main__":main()
