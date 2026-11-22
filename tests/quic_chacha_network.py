"""Real UDP and authenticated QUIC reuse of the single fingerprint engine."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/"tests"))
import quic_udp_network as net

cpp, peer, report = (Path(value).resolve() for value in sys.argv[1:4])
results = []
def save():
    report.write_text(json.dumps({"complete":len(results)==30,"cases":results,"binaries":{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (cpp,peer)}},indent=2)+"\n")
with tempfile.TemporaryDirectory(prefix="nexus-fingerprint-quic-") as directory:
    root = Path(directory)
    wrong,_ = net.credential(root,"wrong","ED25519",[])
    for name,algorithm,options,scheme in (
        ("rsa","RSA",["-pkeyopt","rsa_keygen_bits:2048"],"0x0804"),
        ("p256","EC",["-pkeyopt","ec_paramgen_curve:P-256"],"0x0403"),
        ("ed25519","ED25519",[],"0x0807")):
        cert,key = net.credential(root,name,algorithm,options)
        for family in ("4","6"):
            for curve in ("x","hybrid","retry"):
                for cipher in ("0x1303",):
                    result = net.pair(cpp,peer,cert,key,scheme,"client",family,curve,cipher=cipher)
                    assert "FINGERPRINT" in result["client_stderr"] and "wire=1600" in result["client_stderr"]
                    if curve == "x": assert "groups=2" in result["client_stderr"]
                    if curve == "retry": assert "hello=2" in result["client_stderr"]
                    result["algorithm"] = name
                    results.append(result);save()
                    print(name,family,curve,cipher,"authenticated and exact shaped QUIC wire passed",flush=True)
        for mode in ("wrong-name","wrong-ca"):
            result = net.pair(cpp,peer,cert,key,scheme,"client","4","x",mode,wrong)
            result["algorithm"] = name
            results.append(result);save()
            print(name,mode,"rejected",flush=True)
    for family in ("4","6"):
        for mode in ("loss","stop"):
            result = net.pair(cpp,peer,cert,key,scheme,"client",family,"x",mode,wrong)
            results.append(result);save()
            print(family,mode,"passed",flush=True)
        result = net.deadline_case(cpp,peer,cert,key,scheme,family,False)
        results.append(result);save()
        print(family,"absolute deadline passed",flush=True)
