#!/usr/bin/env python3
"""Actual production Hy2 application over the joined generic UDP driver."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from quic_udp_network import credential,ready

def pair(binary,cert,key,scheme,family,backend,total):
    processes=[]
    try:
        server,port,server_ready=ready([binary,"server",family,0,cert,key,scheme,backend,total])
        processes.append(server)
        client,_,client_ready=ready([binary,"client",family,port,cert,key,scheme,backend,total])
        processes.append(client)
        output,error=client.communicate(timeout=14)
        server_output,server_error=server.communicate(timeout=14)
        record={"family":family,"backend":backend,"bytes_each":total,"client_exit":client.returncode,"server_exit":server.returncode,
                "client_stdout":client_ready+output,"client_stderr":error,"server_stdout":server_ready+server_output,"server_stderr":server_error}
        if client.returncode or server.returncode: raise RuntimeError(json.dumps(record,indent=2))
        return record
    finally:
        for process in processes:
            if process.poll() is None: process.kill();process.wait()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary",type=Path)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--quick",action="store_true")
    parser.add_argument("--udp",action="store_true")
    args=parser.parse_args()
    binary=args.binary.resolve(strict=True)
    report={"complete":False,"expected":1 if args.quick else 24,"cases":[],"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest()}
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-hy2-app-") as directory:
            for name,algorithm,options,scheme in [("p256","EC",["-pkeyopt","ec_paramgen_curve:P-256"],"0x0403")]+([] if args.quick else [
                    ("rsa","RSA",["-pkeyopt","rsa_keygen_bits:2048"],"0x0804"),("ed25519","ED25519",[],"0x0807")]):
                cert,key=credential(Path(directory),name,algorithm,options)
                for family in (["4"] if args.quick else ["4","6"]):
                    for backend in (["0"] if args.quick else ["0","1"]):
                        for total in ([65000 if args.udp else 65537] if args.quick else [0,65000 if args.udp else 1048577]):
                            record=pair(binary,cert,key,scheme,family,backend,total)
                            record["algorithm"]=name;report["cases"].append(record)
                            print(name,family,backend,total,"actual production Hy2 authenticated "+("UDP/fragments/drain" if args.udp else "TCP/FIN/ACK/drain")+" passed",flush=True)
        report["complete"]=len(report["cases"])==report["expected"]
    finally:
        args.report.write_text(json.dumps(report,indent=2)+"\n")

if __name__=="__main__":main()
