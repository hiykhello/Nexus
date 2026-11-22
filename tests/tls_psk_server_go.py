import argparse,hashlib,json,selectors,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('client',type=Path);p.add_argument('report',type=Path);a=p.parse_args();binary=a.binary.resolve();records=[]
def run(command):return subprocess.run([str(x) for x in command],check=True,capture_output=True,text=True,timeout=60)
with tempfile.TemporaryDirectory(prefix='nexus-psk-server-openssl-') as directory:
 root=Path(directory)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key','-out',root/'ca.pem','-days','1','-subj','/CN=PSK CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign'])
 run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',root/'key.pem','-out',root/'csr','-subj','/CN=server.example'])
 (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n')
 run(['openssl','x509','-req','-in',root/'csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial','2','-days','1','-extfile',root/'ext','-out',root/'cert.pem'])
 run(['openssl','x509','-in',root/'cert.pem','-outform','DER','-out',root/'cert.der'])
 run(['openssl','pkey','-in',root/'key.pem','-outform','DER','-out',root/'key.der'])
 for curve in [29,23,24,25,4588]:
  for clear in [False,True]:
   command=[str(binary),str(root/'cert.der'),str(root/'key.der'),'3',*(['clear'] if clear else [])]
   server=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
   try:
    selector=selectors.DefaultSelector();selector.register(server.stdout,selectors.EVENT_READ)
    if not selector.select(15):raise RuntimeError('fixture readiness timeout')
    ready=server.stdout.readline().strip();selector.close()
    if not ready.startswith('READY '):raise RuntimeError('fixture startup failed: '+ready+server.stderr.read())
    port=int(ready.split()[1]);client_command=[str(a.client.resolve()),str(port),str(root/'ca.pem'),str(curve),str(clear).lower()]
    done=subprocess.run(client_command,capture_output=True,text=True,timeout=60)
    output,error=server.communicate(timeout=10)
   except Exception:
    server.terminate()
    try:output,error=server.communicate(timeout=5)
    except subprocess.TimeoutExpired:server.kill();output,error=server.communicate()
    a.report.with_name(a.report.stem+'-failure.json').write_text(json.dumps({'curve':curve,'clear':clear,'server_command':command,'server_output':output,'server_error':error},indent=2)+'\n');raise
   expected=['round=0 resumed=false','round=1 resumed=false' if clear else 'round=1 resumed=true','round=2 resumed=true']
   record={'curve':curve,'clear':clear,'client_command':client_command,'client_exit':done.returncode,'client_output':done.stdout,'client_error':done.stderr,'server_command':command,'server_exit':server.returncode,'server_output':output,'server_error':error}
   records.append(record);a.report.write_text(json.dumps({'complete':len(records)==10 and all(x['client_exit']==0 and x['server_exit']==0 for x in records),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'client_sha256':hashlib.sha256(a.client.read_bytes()).hexdigest(),'go_version':run(['go','version']).stdout,'cases':records},indent=2)+'\n')
   if server.returncode or done.returncode or any(item not in output or item not in done.stdout for item in expected):raise RuntimeError('missing authenticated Go resume/fallback: '+output+error+done.stdout+done.stderr)
   print('Go curve',curve,'clear',clear,'3 authenticated connections passed',flush=True)
