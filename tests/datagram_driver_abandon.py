#!/usr/bin/env python3
"""Natural context abandonment with pending I/O and authenticated QUIC/H3."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from tls_raw_quic import credential

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generic",type=Path);parser.add_argument("native",type=Path);parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args();generic=args.generic.resolve(strict=True);native=args.native.resolve(strict=True)
    report={"complete":False,"expected":16,"cases":[],"binaries":{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [generic,native]}}
    def run(label,command,count):
        result=subprocess.run([str(v) for v in command],capture_output=True,text=True,timeout=10)
        report["cases"].append({"label":label,"count":count,"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr})
        if result.returncode or "driver process-exit tracked ordinary/array/aligned allocations=0" not in result.stdout:raise RuntimeError(str(report["cases"][-1]))
        print(label,result.stdout,end="",flush=True)
    try:
        for backend in [0,1]:run(f"generic-{backend}",[generic,backend],2)
        with tempfile.TemporaryDirectory(prefix="nexus-driver-abandon-") as directory:
            for name,algorithm,options in [("rsa","RSA",["-pkeyopt","rsa_keygen_bits:2048"]),("p256","EC",["-pkeyopt","ec_paramgen_curve:P-256"]),("ed25519","ED25519",[])]:
                cert,key=credential(Path(directory),name,algorithm,options);run(name,[native,cert,key],4)
        report["complete"]=sum(item["count"] for item in report["cases"])==report["expected"]
    finally:args.report.write_text(json.dumps(report,indent=2)+"\n")
if __name__=="__main__":main()
