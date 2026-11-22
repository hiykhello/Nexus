"""Exercise native QUIC auth/fault/KU paths for every implemented CV scheme."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import tls_raw_quic as helper

parser=argparse.ArgumentParser()
parser.add_argument("binary",type=Path)
parser.add_argument("report",type=Path)
parser.add_argument("--wrapped-records",action="store_true")
args=parser.parse_args();binary=args.binary.resolve();records=[]
with tempfile.TemporaryDirectory(prefix="nexus-signature-quic-native-") as directory:
    root=Path(directory)
    wrong,_=helper.credential(root,"wrong","ED25519",[])
    for group in (23,24,25):
      for name,algorithm,options,scheme in (
        ("rsa256","RSA",["-pkeyopt","rsa_keygen_bits:2048"],"0x0804"),
        ("p384","EC",["-pkeyopt","ec_paramgen_curve:P-384"],"0x0503"),
        ("ed25519","ED25519",[],"0x0807")):
        cert,key=helper.credential(root,name,algorithm,options)
        command=[str(binary),str(cert),str(key),str(wrong),"--faults","--signature="+scheme,"--group="+str(group)]
        if args.wrapped_records:command.append("--wrapped-records")
        result=subprocess.run(command,text=True,capture_output=True,timeout=90)
        if result.returncode:
            args.report.with_name(args.report.stem+"-failure.json").write_text(json.dumps({"group":group,"name":name,"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr,"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+"\n")
            raise RuntimeError(f"{name}: {result.returncode} {result.stdout}{result.stderr}")
        if "authenticated in-memory QUIC 38 cases passed" not in result.stdout:raise RuntimeError("missing full matrix")
        if args.wrapped_records and "TCP RecordLayer contexts=0" not in result.stdout:raise RuntimeError("missing wrapper calibration")
        records.append({"group":group,"scheme":scheme,"algorithm":name,"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr})
        args.report.write_text(json.dumps({"complete":len(records)==9,"cases":records,"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"wrapped_records":args.wrapped_records},indent=2)+"\n")
        print(name,scheme,"38 native auth/identity/KU tests plus all cold failures passed",flush=True)
