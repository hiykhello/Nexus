import argparse,hashlib,json,os,socket,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('report',type=Path);a=p.parse_args();binary=a.binary.resolve();records=[]
def run(command):return subprocess.run([str(x) for x in command],check=True,capture_output=True,text=True,timeout=60)
with tempfile.TemporaryDirectory(prefix='nexus-psk-openssl-') as directory:
 root=Path(directory)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key','-out',root/'ca.pem','-days','1','-subj','/CN=PSK CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign'])
 run(['openssl','x509','-in',root/'ca.pem','-outform','DER','-out',root/'ca.der'])
 run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',root/'key.pem','-out',root/'csr','-subj','/CN=server.example'])
 (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n')
 run(['openssl','x509','-req','-in',root/'csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial','2','-days','1','-extfile',root/'ext','-out',root/'cert.pem'])
 for suite,cipher in [(0x1301,'TLS_AES_128_GCM_SHA256'),(0x1303,'TLS_CHACHA20_POLY1305_SHA256')]:
  for mode in ['direct-external','hrr-external']:
   with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
   server_command=['openssl','s_server','-accept',f'127.0.0.1:{port}','-cert',str(root/'cert.pem'),'-key',str(root/'key.pem'),'-tls1_3','-ciphersuites',cipher,'-groups','X25519','-alpn','http/1.1','-num_tickets','2','-psk','00112233445566778899aabbccddeeff','-psk_identity','nexus-external','-www','-state']
   log=root/(f'{suite}-{mode}-server.log')
   with log.open('wb') as output:
    server=subprocess.Popen(server_command,stdout=output,stderr=subprocess.STDOUT)
    try:
     for _ in range(200):
      if server.poll() is not None:raise RuntimeError('server terminated: '+log.read_text())
      try:
       with socket.create_connection(('127.0.0.1',port),timeout=.1):break
      except OSError:time.sleep(.01)
     command=[str(binary),str(port),str(root/'ca.der'),hex(suite),mode,'3',str(port),'00112233445566778899aabbccddeeff','nexus-external']
     start=time.monotonic();done=subprocess.run(command,capture_output=True,text=True,timeout=120)
    finally:
     server.terminate()
     try:server.wait(timeout=5)
     except subprocess.TimeoutExpired:server.kill();server.wait()
   text=log.read_text();record={'suite':suite,'mode':mode,'exit':done.returncode,'stdout':done.stdout,'stderr':done.stderr,'seconds':time.monotonic()-start,'server_command':server_command,'server_log':text}
   records.append(record);a.report.write_text(json.dumps({'complete':len(records)==4 and all(x['exit']==0 for x in records),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'openssl_version':run(['openssl','version','-a']).stdout,'cases':records},indent=2)+'\n');print(hex(suite),mode,done.returncode,done.stdout,done.stderr,flush=True)
   if done.returncode:raise RuntimeError('PSK production handshake failed')
