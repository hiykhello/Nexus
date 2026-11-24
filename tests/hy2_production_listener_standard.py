import argparse,hashlib,json,socket,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from quic_udp_network import credential,ready
from dns_rule_support import proxy_client
from hy2_production_listener_network import Origin

def main():
    p=argparse.ArgumentParser();p.add_argument('server',type=Path);p.add_argument('--retry-drivers',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--quick',action='store_true');p.add_argument('--mutations',action='store_true');p.add_argument('--backend',choices=('0','1','both'),default='both');p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    sys.path.insert(0,str(a.retry_drivers.resolve(strict=True)))
    from retry_standard_network import Tap,payload,socks,REVISION
    server=a.server.resolve(strict=True);version=subprocess.run(['sing-box','version'],capture_output=True,text=True,check=True).stdout
    if 'Revision: '+REVISION not in version:raise RuntimeError('fixed peer revision differs')
    r={'complete':False,'server_sha256':hashlib.sha256(server.read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'retry_drivers':str(a.retry_drivers.resolve()),'peer_revision':REVISION,'cases':[]}
    try:
        with tempfile.TemporaryDirectory(prefix='hy2-production-standard-') as tmp:
            root=Path(tmp);algorithms=[('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'])]
            if not a.quick:algorithms += [('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048']),('ed25519','ED25519',[])]
            for name,kind,options in algorithms:
                cert,key=credential(root,name,kind,options);subprocess.run(['openssl','x509','-inform','DER','-in',cert,'-out',root/'cert.pem'],check=True,capture_output=True)
                for family in (['4'] if a.quick else ['4','6']):
                    for backend in ([a.backend] if a.backend!='both' else ['0'] if a.quick else ['0','1']):
                        for mutation in (['tag','token','source'] if a.mutations else ['plain']):
                            total=65537;origin=Origin(total,1,request_first=False);process,port,first=ready([server,cert,key,family,backend,1,total,origin.port,'standard']);host='::1' if family=='6' else '127.0.0.1';tap=Tap(host,port,family,mutation)
                            try:
                                outbound={'type':'hysteria2','server':host,'server_port':tap.port,'password':'test-password','disable_chrome_parrot':name=='ed25519','tls':{'enabled':True,'server_name':'localhost','certificate_path':str(root/'cert.pem'),'alpn':['h3']}}
                                with proxy_client(root,outbound) as front:
                                    with socks(front,'target.example',443) as client:
                                        sent=payload(total,37);prefix=total//2;client.sendall(sent[:prefix]);got=bytearray()
                                        while wire:=client.recv(65536):got.extend(wire)
                                        if got!=payload(total,19):raise RuntimeError('actual origin response differs')
                                        client.sendall(sent[prefix:]);client.shutdown(socket.SHUT_WR)
                                    origin.finish()
                                # The fixture can stop after the actual client
                                # observed response FIN then uploaded EOF. A
                                # production listener otherwise preserves this
                                # healthy connection for subsequent streams.
                                output,error=process.communicate(timeout=20)
                                item={'certificate':name,'family':family,'backend':backend,'mutation':mutation,'server_exit':process.returncode,'server_stdout':first+output,'server_stderr':error,'real_origins':origin.records,'tap':tap.stats,'peer_limit':'Fixed SOCKS wrapper lacks CloseWrite; actual origin response FIN precedes remaining upload. Native Go test independently proves upload FIN first.'};r['cases'].append(item)
                                print(name,family,backend,mutation,process.returncode,flush=True)
                                if process.returncode or not tap.stats['retry_packets'] or not tap.stats['token_initials'] or max(tap.stats['retry_sizes'])>146 or min(tap.stats['client_initial_sizes'])<1200:raise RuntimeError(json.dumps(item,indent=2))
                                if mutation!='plain' and tap.stats['injected']!=1:raise RuntimeError('mutation was not observed')
                            finally:
                                if process.poll() is None:process.kill();process.wait()
                                tap.close()
        r['complete']=True
    finally:a.report.write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
