import argparse,hashlib,json,re,socket,subprocess,sys,tempfile,threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from quic_udp_network import credential,ready
from dns_rule_support import proxy_client
from hy2_application_singbox import socks,payload,REVISION

def token_offset(wire):
    if len(wire)<7 or wire[0]&0xf0!=0xc0 or wire[1:5]!=b'\0\0\0\1':return None
    at=5;at+=1+wire[at]
    if at>=len(wire):return None
    at+=1+wire[at]
    if at>=len(wire):return None
    width=1<<(wire[at]>>6)
    if at+width>len(wire):return None
    value=wire[at]&0x3f
    for byte in wire[at+1:at+width]:value=(value<<8)|byte
    at+=width
    return (at,value) if at+value<=len(wire) else None

class Tap:
    def __init__(self,host,server,family,mutation):
        af=socket.AF_INET6 if family=='6' else socket.AF_INET
        self.socket=socket.socket(af,socket.SOCK_DGRAM);self.socket.bind((host,0));self.socket.settimeout(.1)
        self.alt=socket.socket(af,socket.SOCK_DGRAM);self.alt.bind((host,0));self.port=self.socket.getsockname()[1]
        self.destination=(host,server);self.client=None;self.mutation=mutation;self.changed=False;self.finished=threading.Event();self.errors=[]
        self.stats={'retry_packets':0,'retry_sizes':[],'client_initial_sizes':[],'token_initials':0,'injected':0,'wrong_source_port':self.alt.getsockname()[1]}
        self.thread=threading.Thread(target=self.run);self.thread.start()
    def run(self):
        try:
            while not self.finished.is_set():
                try:wire,source=self.socket.recvfrom(65536)
                except TimeoutError:continue
                if source[0]==self.destination[0] and source[1]==self.destination[1]:
                    if not self.client:raise RuntimeError('server response before any peer Initial')
                    if len(wire)>=5 and wire[0]&0xf0==0xf0 and wire[1:5]==b'\0\0\0\1':
                        self.stats['retry_packets']+=1;self.stats['retry_sizes'].append(len(wire))
                        if self.mutation=='tag' and not self.changed:
                            raw=bytearray(wire);raw[-1]^=1;wire=bytes(raw);self.changed=True;self.stats['injected']+=1
                    self.socket.sendto(wire,self.client)
                else:
                    if self.client is None:self.client=source
                    if source!=self.client:raise RuntimeError('unexpected different client socket')
                    parsed=token_offset(wire)
                    if parsed:
                        at,size=parsed;self.stats['client_initial_sizes'].append(len(wire))
                        if size:
                            self.stats['token_initials']+=1
                            if self.mutation in ('token','source') and not self.changed:
                                self.changed=True;self.stats['injected']+=1
                                if self.mutation=='token':
                                    raw=bytearray(wire);raw[at+size-1]^=1;self.socket.sendto(raw,self.destination)
                                else:self.alt.sendto(wire,self.destination)
                                # Wait for the independent peer's real QUIC
                                # retransmission; do not schedule a test sleep.
                                continue
                    self.socket.sendto(wire,self.destination)
        except BaseException as error:
            if not self.finished.is_set():self.errors.append(repr(error))
    def close(self):
        self.finished.set();self.thread.join(2);self.socket.close();self.alt.close()
        if self.thread.is_alive() or self.errors:raise RuntimeError(self.errors)

def run(binary,root,cert,key,scheme,name,family,backend,total,mutation):
    host='::1' if family=='6' else '127.0.0.1';server,port,first=ready([binary,cert,key,family,backend,1,total]);tap=Tap(host,port,family,mutation)
    tls={'enabled':True,'server_name':'localhost','certificate_path':str(root/'cert.pem'),'alpn':['h3']}
    try:
        outbound={'type':'hysteria2','server':host,'server_port':tap.port,'password':'test-password','disable_chrome_parrot':name=='ed25519','tls':tls}
        with proxy_client(root,outbound) as front:
            with socks(front,'target.example',443) as client:
                sent=payload(total,37);prefix=len(sent)//2;client.sendall(sent[:prefix]);received=bytearray()
                while chunk:=client.recv(65536):received.extend(chunk)
                if received!=payload(total,19):raise RuntimeError(f'actual TCP response bytes differ: received={len(received)} expected={total} tap={tap.stats} errors={tap.errors}')
                # The fixed SOCKS Hy2 wrapper lacks CloseWrite. Its ordinary
                # Close cancels unread response data. Observe actual response
                # FIN first, then prove the remaining request still uploads.
                client.sendall(sent[prefix:]);client.shutdown(socket.SHUT_WR)
            output,error=server.communicate(timeout=15)
            if server.returncode:raise RuntimeError(f'Nexus exit{server.returncode}: {first+output}{error}')
        stdout=first+output
        match=re.search(r'Retry queued=(\d+) actually_transmitted=(\d+) validated=(\d+) invalid=(\d+)',stdout)
        if not match:raise RuntimeError('missing actual Retry metrics')
        metrics={name:int(value) for name,value in zip(('queued','committed','validated','invalid'),match.groups())}
        if metrics['committed']<1 or metrics['validated']!=1 or tap.stats['retry_packets']<1 or not tap.stats['token_initials']:raise RuntimeError('Retry path not actually traversed')
        if max(tap.stats['retry_sizes'])>146 or min(tap.stats['client_initial_sizes'])<1200:raise RuntimeError('Retry amplification/path bound violation')
        if mutation!='plain' and tap.stats['injected']!=1:raise RuntimeError('negative control did not trigger')
        if mutation in ('token','source') and metrics['invalid']<1:raise RuntimeError('actual invalid token path was not observed')
        if mutation=='tag' and tap.stats['retry_packets']<2:raise RuntimeError('corrupt Retry was not followed by actual retry recovery')
        return {'certificate':name,'family':family,'backend':backend,'payload':total,'mutation':mutation,'exit':server.returncode,'stdout':stdout,'stderr':error,'server_retry':metrics,'tap':tap.stats,'response_FIN_before_remaining_request':True,'peer_limit':'Fixed SOCKS wrapper has no CloseWrite; upload EOF before response completion cancels remaining reads. Original negative evidence retained.'}
    except BaseException:
        if server.poll() is None:server.kill()
        output,error=server.communicate();print('failed server:',first+output,error,flush=True);raise
    finally:
        if server.poll() is None:server.kill();server.wait()
        tap.close()

def main():
    p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('--report',type=Path,required=True);p.add_argument('--quick',action='store_true');p.add_argument('--mutations',action='store_true');p.add_argument('--backend',choices=('0','1','both'),default='both');args=p.parse_args()
    binary=args.binary.resolve(strict=True);version=subprocess.run(['sing-box','version'],capture_output=True,text=True,check=True).stdout
    if 'Revision: '+REVISION not in version:raise RuntimeError('fixed standard peer mismatch')
    report={'complete':False,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'peer_revision':REVISION,'cases':[]}
    try:
        with tempfile.TemporaryDirectory(prefix='hy2-real-retry-') as directory:
            root=Path(directory);algorithms=[('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'],'0x0403')]
            if not args.quick:algorithms+=[('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048'],'0x0804'),('ed25519','ED25519',[],'0x0807')]
            for name,algorithm,options,scheme in algorithms:
                cert,key=credential(root,name,algorithm,options)
                subprocess.run(['openssl','x509','-inform','DER','-in',cert,'-out',root/'cert.pem'],check=True,capture_output=True)
                for family in (['4'] if args.quick else ['4','6']):
                    for backend in ([args.backend] if args.backend!='both' else ['0'] if args.quick else ['0','1']):
                        for mutation in (['tag','token','source'] if args.mutations else ['plain']):
                            for total in [65537]:
                                item=run(binary,root,cert,key,scheme,name,family,backend,total,mutation);report['cases'].append(item);print(name,family,backend,total,mutation,'actual Retry/token/Hy2 auth+TCP+FIN passed',flush=True)
        report['complete']=True
    finally:args.report.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
