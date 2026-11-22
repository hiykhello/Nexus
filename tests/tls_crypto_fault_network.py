import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('binary',type=Path);parser.add_argument('report',type=Path)
args=parser.parse_args();binary=args.binary.resolve();records=[]
def run(command):return subprocess.run([str(x) for x in command],check=True,capture_output=True,text=True,timeout=45)
with tempfile.TemporaryDirectory(prefix='nexus-crypto-fault-') as directory:
 root=Path(directory)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key','-out',root/'ca.pem','-days','1','-subj','/CN=Crypto fault CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign'])
 run(['openssl','x509','-in',root/'ca.pem','-outform','DER','-out',root/'ca.der'])
 (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n')
 for name,algorithm,options,scheme in [('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048'],'0x0804'),('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'],'0x0403'),('ed25519','ED25519',[],'0x0807')]:
  run(['openssl','genpkey','-algorithm',algorithm,*options,'-out',root/'key.pem'])
  run(['openssl','pkey','-in',root/'key.pem','-outform','DER','-out',root/'key.der'])
  run(['openssl','req','-new','-key',root/'key.pem','-out',root/'csr','-subj','/CN=server.example'])
  run(['openssl','x509','-req','-in',root/'csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial','2','-days','1','-extfile',root/'ext','-out',root/'cert.pem'])
  run(['openssl','x509','-in',root/'cert.pem','-outform','DER','-out',root/'cert.der'])
  if name=='rsa':
   oracle=binary.parent/'tls-spki-error'
   if not oracle.is_file():oracle=binary.parent/'tls_spki_error'
   r=run([oracle,root/'cert.der']);print(r.stdout,flush=True)
  command=[str(binary),str(root/'cert.der'),str(root/'key.der'),str(root/'ca.der'),scheme,str(root/'ca.pem')]
  r=subprocess.run(command,text=True,capture_output=True,timeout=60)
  record={'name':name,'scheme':scheme,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'command':command}
  records.append(record);args.report.write_text(json.dumps({'complete':len(records)==3 and all(v['exit']==0 for v in records),'cases':records,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+'\n')
  print(name,r.returncode,r.stdout,r.stderr,flush=True)
  if r.returncode:raise RuntimeError('native crypto classification failure')
