"""Run explicit signature offers over real UDP against the fixed Go QUIC peer."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import quic_udp_network as net

cpp,peer,report=(Path(value).resolve() for value in sys.argv[1:4])
version=subprocess.run(["go","version","-m",str(peer)],text=True,capture_output=True,check=True).stdout
if "github.com/sagernet/quic-go\tv0.61.0-sing-box-mod.6\th1:67bgUBU2QKK6jNz46GB5919wwRHcOHSafgmhD2gVf2Y=" not in version:raise RuntimeError("unexpected QUIC peer module")
records=[]
def save():
    report.write_text(json.dumps({"complete":len(records)==128,"expected":128,"cases":records,"binaries":{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (cpp,peer)},"peer_module":version},indent=2)+"\n")

def pair(cert,key,scheme,role,family,curve,cipher="0x1301",mode="normal",wrong=None):
    processes=[]
    cpp_cert,name=(wrong,"localhost") if mode=="wrong-ca" else (cert,"wrong.example") if mode=="wrong-name" else (cert,"localhost")
    selected_mode="reject" if mode.startswith("wrong-") else mode
    try:
        if role=="client":
            server,port,first=net.ready([peer,"server",family,0,cert,key,"localhost",selected_mode,curve]);processes.append(server)
            client,_,second=net.ready([cpp,"client",family,port,cpp_cert,key,scheme,curve,selected_mode,name,cipher,scheme])
        else:
            server,port,first=net.ready([cpp,"server",family,0,cert,key,scheme,curve,selected_mode,"localhost"]);processes.append(server)
            client,_,second=net.ready([peer,"client",family,port,cpp_cert,key,name,selected_mode,curve])
        processes.append(client)
        out,error=client.communicate(timeout=13);server_out,server_error=server.communicate(timeout=13)
        result={"scheme":scheme,"role":role,"family":family,"curve":curve,"cipher":cipher,"mode":mode,
            "client_exit":client.returncode,"server_exit":server.returncode,"client_stdout":second+out,"client_stderr":error,"server_stdout":first+server_out,"server_stderr":server_error}
        if client.returncode or server.returncode:raise RuntimeError(json.dumps(result,indent=2))
        if role=="client" and mode=="normal" and f"cipher={cipher}" not in server_out:raise RuntimeError("peer negotiated unexpected cipher")
        return result
    finally:
        for process in processes:
            if process.poll() is None:process.kill();process.communicate()

with tempfile.TemporaryDirectory(prefix="nexus-signature-quic-") as directory:
    root=Path(directory)
    wrong,_=net.credential(root,"wrong","ED25519",[])
    cases=(
        ("RSA",["-pkeyopt","rsa_keygen_bits:2048"],"rsa256","0x0804"),
        ("RSA",["-pkeyopt","rsa_keygen_bits:2048"],"rsa384","0x0805"),
        ("RSA",["-pkeyopt","rsa_keygen_bits:2048"],"rsa512","0x0806"),
        ("EC",["-pkeyopt","ec_paramgen_curve:P-256"],"p256","0x0403"),
        ("EC",["-pkeyopt","ec_paramgen_curve:P-384"],"p384","0x0503"),
        ("EC",["-pkeyopt","ec_paramgen_curve:P-521"],"p521","0x0603"),
        ("ED25519",[],"ed25519","0x0807"))
    for algorithm,options,name,scheme in cases:
        cert,key=net.credential(root,name,algorithm,options)
        for family in ("4","6"):
            for curve in ("x","hybrid","retry"):
                for cipher in ("0x1301","0x1303"):
                    result=pair(cert,key,scheme,"client",family,curve,cipher);result["algorithm"]=name
                    records.append(result);save()
                if scheme not in ("0x0805","0x0806"):
                    result=pair(cert,key,scheme,"server",family,curve);result["algorithm"]=name
                    records.append(result);save()
        for mode in ("wrong-name","wrong-ca"):
            result=pair(cert,key,scheme,"client","4","x",mode=mode,wrong=wrong);result["algorithm"]=name
            records.append(result);save()
        print(name,scheme,"fixed peer QUIC identity, IPv4/IPv6 X/hybrid/HRR and exact single signature offer passed",flush=True)
