import argparse,hashlib,json,selectors,socket,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('peer',type=Path);p.add_argument('report',type=Path);p.add_argument('--quick',action='store_true');a=p.parse_args();binary=a.binary.resolve();peer=a.peer.resolve();records=[]
def run(args):return subprocess.run([str(x) for x in args],capture_output=True,text=True,check=True,timeout=60)
def line(process):
 selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
 if not selector.select(12):raise RuntimeError('readiness timeout')
 result=process.stdout.readline();selector.close()
 if not result.startswith('READY '):raise RuntimeError('startup failed: '+result+process.stderr.read())
 return result
version=run(['go','version','-m',peer]).stdout
if 'github.com/sagernet/quic-go\tv0.61.0-sing-box-mod.6\th1:67bgUBU2QKK6jNz46GB5919wwRHcOHSafgmhD2gVf2Y=' not in version:raise RuntimeError('peer not fixed module')
with tempfile.TemporaryDirectory(prefix='nexus-quic-psk-udp-') as directory:
 root=Path(directory)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key','-out',root/'ca.pem','-days','1','-subj','/CN=QUIC PSK CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign'])
 run(['openssl','x509','-in',root/'ca.pem','-outform','DER','-out',root/'ca.der'])
 (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
 families=[('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048']),('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256']),('ed25519','ED25519',[])]
 for name,algorithm,options in families[:1] if a.quick else families:
  run(['openssl','genpkey','-algorithm',algorithm,*options,'-out',root/'key.pem']);run(['openssl','pkey','-in',root/'key.pem','-outform','DER','-out',root/'key.der']);run(['openssl','req','-new','-key',root/'key.pem','-out',root/'csr','-subj','/CN=localhost']);run(['openssl','x509','-req','-in',root/'csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial','2','-days','1','-extfile',root/'ext','-out',root/'cert.pem']);run(['openssl','x509','-in',root/'cert.pem','-outform','DER','-out',root/'cert.der'])
  for role in ['client','server']:
   for family in [4] if a.quick else [4,6]:
    for group in [29] if a.quick else [23,24,25,29,4588]:
     for cipher in ([0x1301] if a.quick or role=='server' else [0x1301,0x1302,0x1303]):
      for mode in ['direct','hrr','direct-fallback','hrr-fallback']:
       cpp_cert=root/'ca.der' if role=='client' else root/'cert.der'
       with socket.socket(socket.AF_INET6 if family==6 else socket.AF_INET,socket.SOCK_DGRAM) as probe:probe.bind(('::1' if family==6 else '127.0.0.1',0));port=probe.getsockname()[1]
       cpp_command=[binary,role,str(family),str(port),cpp_cert,root/'key.der',str(group),hex(cipher),mode,'localhost']
       go_command=[peer,'server' if role=='client' else 'client',str(family),str(port),root/'cert.der' if role=='client' else root/'ca.der',root/'key.der',str(group),mode]
       server_command=go_command if role=='client' else cpp_command;client_command=cpp_command if role=='client' else go_command
       processes=[];start=time.monotonic()
       try:
        server=subprocess.Popen([str(x) for x in server_command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1);processes.append(server);server_ready=line(server)
        client=subprocess.Popen([str(x) for x in client_command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1);processes.append(client)
        client_out,client_error=client.communicate(timeout=45);server_out,server_error=server.communicate(timeout=45)
        record={'name':name,'role':role,'family':family,'group':group,'cipher':cipher,'mode':mode,'commands':[[str(x) for x in server_command],[str(x) for x in client_command]],'client_exit':client.returncode,'server_exit':server.returncode,'client_stdout':client_out,'server_stdout':server_ready+server_out,'client_stderr':client_error,'server_stderr':server_error,'seconds':time.monotonic()-start}
        expected=['round=0 resumed=false','round=1 resumed=false' if mode.endswith('fallback') else 'round=1 resumed=true','round=2 resumed=true']
        if client.returncode or server.returncode or any(value not in client_out or value not in server_ready+server_out for value in expected):
         a.report.with_name(a.report.stem+'-failure.json').write_text(json.dumps(record,indent=2)+'\n');raise RuntimeError(json.dumps(record,indent=2))
        records.append(record);a.report.write_text(json.dumps({'complete':False,'quick':a.quick,'cases':records,'binaries':{str(binary):hashlib.sha256(binary.read_bytes()).hexdigest(),str(peer):hashlib.sha256(peer.read_bytes()).hexdigest()},'peer_module':version},indent=2)+'\n');print(name,role,family,group,hex(cipher),mode,'3 authenticated/resumed connections passed',flush=True)
       finally:
        for process in processes:
         if process.poll() is None:process.kill();process.communicate()
 x=json.loads(a.report.read_text());x['complete']=True;a.report.write_text(json.dumps(x,indent=2)+'\n')
