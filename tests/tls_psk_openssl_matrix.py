import argparse,hashlib,json,socket,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('report',type=Path);a=p.parse_args();binary=a.binary.resolve();records=[]
def run(command):return subprocess.run([str(x) for x in command],check=True,capture_output=True,text=True,timeout=60)
with tempfile.TemporaryDirectory(prefix='nexus-psk-openssl-matrix-') as directory:
 root=Path(directory)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key','-out',root/'ca.pem','-days','1','-subj','/CN=PSK CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign'])
 run(['openssl','x509','-in',root/'ca.pem','-outform','DER','-out',root/'ca.der'])
 run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',root/'key.pem','-out',root/'csr','-subj','/CN=server.example'])
 (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n')
 run(['openssl','x509','-req','-in',root/'csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial','2','-days','1','-extfile',root/'ext','-out',root/'cert.pem'])
 for suite,cipher in [(0x1301,'TLS_AES_128_GCM_SHA256'),(0x1302,'TLS_AES_256_GCM_SHA384'),(0x1303,'TLS_CHACHA20_POLY1305_SHA256')]:
  for mode in ['direct','hrr','direct-fallback','hrr-fallback','direct-corrupt','hrr-corrupt']:
   servers=[];logs=[];commands=[];ports=[];streams=[]
   try:
    for index in range(2 if mode.endswith('fallback') else 1):
     with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
     ports.append(port)
     command=['openssl','s_server','-accept',f'127.0.0.1:{port}','-cert',str(root/'cert.pem'),'-key',str(root/'key.pem'),'-tls1_3','-ciphersuites',cipher,'-groups','X25519','-alpn','http/1.1','-num_tickets','2','-www','-state']
     commands.append(command);log=root/f'{suite}-{mode}-{index}.log';logs.append(log);output=log.open('wb');streams.append(output)
     server=subprocess.Popen(command,stdout=output,stderr=subprocess.STDOUT);servers.append(server)
     for attempt in range(200):
      if server.poll() is not None:raise RuntimeError('server terminated: '+log.read_text())
      try:
       with socket.create_connection(('127.0.0.1',port),timeout=.1):break
      except OSError:time.sleep(.01)
     else:raise RuntimeError('server did not listen')
    command=[str(binary),str(ports[0]),str(root/'ca.der'),hex(suite),mode,'3',str(ports[-1])]
    start=time.monotonic();done=subprocess.run(command,capture_output=True,text=True,timeout=120)
   finally:
    for server in servers:
     server.terminate()
     try:server.wait(timeout=5)
     except subprocess.TimeoutExpired:server.kill();server.wait()
    for stream in streams:stream.close()
   server_logs=[p.read_text() for p in logs]
   if done.returncode==0:
    if mode.endswith('corrupt'):
     if 'corrupt binder rejected without application release' not in done.stdout or not any('binder does not verify' in text for text in server_logs):raise RuntimeError('missing independent bad-binder rejection')
    elif mode.endswith('fallback'):
     if 'authenticated full=2 resumed=1' not in done.stdout:raise RuntimeError('missing rejected-ticket full authentication fallback and renewed recovery')
    elif 'authenticated full=1 resumed=2' not in done.stdout:raise RuntimeError('missing recovery matrix')
   record={'suite':suite,'mode':mode,'command':command,'exit':done.returncode,'stdout':done.stdout,'stderr':done.stderr,'seconds':time.monotonic()-start,'server_commands':commands,'server_logs':server_logs}
   records.append(record);a.report.write_text(json.dumps({'complete':len(records)==18 and all(x['exit']==0 for x in records),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'openssl_version':run(['openssl','version','-a']).stdout,'cases':records},indent=2)+'\n');print(hex(suite),mode,done.returncode,done.stdout,done.stderr,flush=True)
   if done.returncode:raise RuntimeError('PSK production handshake failed')
