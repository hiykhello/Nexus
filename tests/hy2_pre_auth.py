from pathlib import Path
import argparse,hashlib,json,subprocess,sys,tempfile
sys.path.insert(0,'/home/yk/Code/Nexus/tests')
from quic_udp_network import credential,ready
p=argparse.ArgumentParser();p.add_argument('--quick',action='store_true');p.add_argument('--report',type=Path,required=True);p.add_argument('--server',type=Path);p.add_argument('--peer',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parent;peer=a.peer.resolve() if a.peer else root/'preauth-peer';server=a.server.resolve() if a.server else root.parent/'frozen-v1/bins/hy2_application_fixture'
report={'complete':False,'server_sha256':hashlib.sha256(server.read_bytes()).hexdigest(),'peer_sha256':hashlib.sha256(peer.read_bytes()).hexdigest(),'cases':[]}
try:
 with tempfile.TemporaryDirectory(prefix='hy2-preauth-go-') as tmp:
  algorithms=[('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'],'0x0403')]
  if not a.quick:algorithms+=[('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048'],'0x0804'),('ed25519','ED25519',[],'0x0807')]
  for name,kind,options,scheme in algorithms:
   cert,key=credential(Path(tmp),name,kind,options)
   for family in (['4'] if a.quick else ['4','6']):
    for backend in (['0'] if a.quick else ['0','1']):
     for mode in ('split','full','full-flood','truncated-fin'):
      cpp,port,first=ready([server,'server',family,0,cert,key,scheme,backend,65537,'target.example:443','single'])
      try:
       done=subprocess.run([peer,family,str(port),cert,mode,'65537'],capture_output=True,text=True,timeout=15)
       if done.returncode and cpp.poll() is None:cpp.kill()
       stdout,stderr=cpp.communicate(timeout=12)
       row={'certificate':name,'family':family,'backend':backend,'mode':mode,'peer_exit':done.returncode,'peer_stdout':done.stdout,'peer_stderr':done.stderr,'server_exit':cpp.returncode,'server_stdout':first+stdout,'server_stderr':stderr};report['cases'].append(row);print(json.dumps(row),flush=True)
       if done.returncode or cpp.returncode:raise SystemExit(1)
      finally:
       if cpp.poll() is None:cpp.kill();cpp.wait()
 report['complete']=True
finally:a.report.write_text(json.dumps(report,indent=2)+'\n')
