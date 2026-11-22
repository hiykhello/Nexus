import argparse,hashlib,json,selectors,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('report',type=Path);a=p.parse_args();binary=a.binary.resolve();records=[]
def run(command):return subprocess.run([str(x) for x in command],check=True,capture_output=True,text=True,timeout=60)
with tempfile.TemporaryDirectory(prefix='nexus-psk-server-openssl-') as directory:
 root=Path(directory)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key','-out',root/'ca.pem','-days','1','-subj','/CN=PSK CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign'])
 run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',root/'key.pem','-out',root/'csr','-subj','/CN=server.example'])
 (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n')
 run(['openssl','x509','-req','-in',root/'csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial','2','-days','1','-extfile',root/'ext','-out',root/'cert.pem'])
 run(['openssl','x509','-in',root/'cert.pem','-outform','DER','-out',root/'cert.der'])
 run(['openssl','pkey','-in',root/'key.pem','-outform','DER','-out',root/'key.der'])
 for suite,cipher in [(0x1301,'TLS_AES_128_GCM_SHA256'),(0x1302,'TLS_AES_256_GCM_SHA384'),(0x1303,'TLS_CHACHA20_POLY1305_SHA256')]:
  for hrr in [False,True]:
   for clear in [False,True]:
    command=[str(binary),str(root/'cert.der'),str(root/'key.der'),'3',*(['clear'] if clear else [])]
    server=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    clients=[];session=root/f'{suite}-{hrr}-{clear}.pem'
    try:
     selector=selectors.DefaultSelector();selector.register(server.stdout,selectors.EVENT_READ)
     if not selector.select(15):raise RuntimeError('fixture readiness timeout')
     ready=server.stdout.readline().strip();selector.close()
     if not ready.startswith('READY '):raise RuntimeError('fixture startup failed: '+ready+server.stderr.read())
     port=int(ready.split()[1])
     for i in range(3):
      client_command=['openssl','s_client','-connect',f'127.0.0.1:{port}','-CAfile',str(root/'ca.pem'),'-verify_hostname','server.example','-verify_return_error','-servername','server.example','-tls1_3','-ciphersuites',cipher,'-groups','X448:X25519' if hrr else 'X25519','-alpn','http/1.1','-quiet','-state','-ign_eof','-sess_out',str(session)]
      if i:client_command+=['-sess_in',str(session)]
      done=subprocess.run(client_command,input='GET / HTTP/1.1\r\nHost: server.example\r\nConnection: close\r\n\r\n',capture_output=True,text=True,timeout=30)
      if done.returncode or not done.stdout.startswith('HTTP/1.1 200 OK') or 'Nexus PSK OK' not in done.stdout:raise RuntimeError(f'OpenSSL client {i} exited {done.returncode}: {done.stdout}{done.stderr}')
      if not session.exists():raise RuntimeError('client did not receive authenticated NewSessionTicket')
      parsed=run(['openssl','sess_id','-in',session,'-text','-noout']).stdout
      if 'TLSv1.3' not in parsed or cipher not in parsed:raise RuntimeError('wrong ticket session version/cipher')
      clients.append({'round':i,'command':client_command,'exit':done.returncode,'stdout':done.stdout,'stderr':done.stderr,'session_text':parsed})
     output,error=server.communicate(timeout=10)
    except Exception:
     server.terminate()
     try:output,error=server.communicate(timeout=5)
     except subprocess.TimeoutExpired:server.kill();output,error=server.communicate()
     a.report.with_name(a.report.stem+'-failure.json').write_text(json.dumps({'suite':suite,'hrr':hrr,'clear':clear,'clients':clients,'server_command':command,'server_output':output,'server_error':error},indent=2)+'\n');raise
    expected=['round=0 resumed=false','round=1 resumed=false' if clear else 'round=1 resumed=true','round=2 resumed=true']
    if server.returncode or any(item not in output for item in expected):raise RuntimeError('server did not observe authenticated recovery/fallback: '+output+error)
    if hrr and any(client['stderr'].count('SSL_connect:SSLv3/TLS write client hello')<2 for client in clients):raise RuntimeError('missing actual HelloRetryRequest')
    records.append({'suite':suite,'hrr':hrr,'clear':clear,'clients':clients,'server_command':command,'server_exit':server.returncode,'server_output':output,'server_error':error})
    a.report.write_text(json.dumps({'complete':len(records)==12,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'openssl_version':run(['openssl','version','-a']).stdout,'cases':records},indent=2)+'\n');print(hex(suite),'hrr',hrr,'clear',clear,'3 authentic connections and ticket renewal passed',flush=True)
