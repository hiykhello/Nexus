import argparse,hashlib,json,socket,subprocess,sys,tempfile,threading,time
from pathlib import Path
sys.path.insert(0,'/home/yk/Code/Nexus/tests')
from quic_udp_network import credential,ready
class Origin:
    def __init__(self,total,count,request_first=True):
        self.socket=socket.socket();self.socket.bind(('127.0.0.1',0));self.socket.listen(32);self.socket.settimeout(12);self.port=self.socket.getsockname()[1]
        self.total=total;self.count=count;self.request_first=request_first;self.records=[];self.errors=[];self.work=[];self.thread=threading.Thread(target=self.run);self.thread.start()
    def serve(self,peer):
        record={};errors=[];event=threading.Event();peer.settimeout(12)
        try:
            def respond():
                try:
                    peer.sendall(bytes((i*71+19)&255 for i in range(self.total)))
                    if self.request_first and not event.wait(10):raise RuntimeError('actual request FIN absent')
                    peer.shutdown(socket.SHUT_WR);record['response_FIN']=time.monotonic()
                except BaseException as error:errors.append(repr(error))
            writer=threading.Thread(target=respond);writer.start();got=bytearray()
            while wire:=peer.recv(16384):got.extend(wire)
            record.update(request_FIN=time.monotonic(),received=len(got),valid=got==bytes((i*71+37)&255 for i in range(self.total)));event.set();writer.join(12)
            if writer.is_alive() or errors or not record['valid']:raise RuntimeError(errors)
            record['independent_FIN']=(record['request_FIN']<=record['response_FIN']) if self.request_first else (record['response_FIN']<=record['request_FIN']);self.records.append(record)
        except BaseException as error:self.errors.append(repr(error))
        finally:peer.close()
    def run(self):
        try:
            for _ in range(self.count):
                peer,_=self.socket.accept();t=threading.Thread(target=self.serve,args=(peer,));self.work.append(t);t.start()
        except BaseException as error:self.errors.append(repr(error))
        finally:self.socket.close()
    def finish(self):
        self.thread.join(15)
        for t in self.work:t.join(15)
        if self.thread.is_alive() or any(t.is_alive() for t in self.work) or self.errors or len(self.records)!=self.count or not all(r['independent_FIN'] for r in self.records):raise RuntimeError({'records':self.records,'errors':self.errors})
def main():
    p=argparse.ArgumentParser();p.add_argument('server',type=Path);p.add_argument('peer',type=Path);p.add_argument('--quick',action='store_true');p.add_argument('--reject',action='store_true');p.add_argument('--backend',choices=('0','1','both'),default='both');p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    server=a.server.resolve(strict=True);peer=a.peer.resolve(strict=True);r={'complete':False,'server_sha256':hashlib.sha256(server.read_bytes()).hexdigest(),'peer_sha256':hashlib.sha256(peer.read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':[]}
    try:
        with tempfile.TemporaryDirectory(prefix='hy2-production-listener-') as tmp:
            algorithms=[('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'])]
            if not a.quick:algorithms += [('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048']),('ed25519','ED25519',[])]
            for name,kind,options in algorithms:
                cert,key=credential(Path(tmp),name,kind,options)
                for family in (['4'] if a.quick else ['4','6']):
                    for backend in ([a.backend] if a.backend!='both' else ['0'] if a.quick else ['0','1']):
                        for mode,count in ([('reject',1)] if a.reject else [('multiplex',4),('reuse',20)]):
                            for total in ([65537] if a.quick else [0,65537]):
                                origin=Origin(total,count);process,port,first=ready([server,cert,key,family,backend,count,total,origin.port])
                                try:
                                    done=subprocess.run([peer,family,str(port),cert,mode,str(total)],capture_output=True,text=True,timeout=15)
                                    if done.returncode and process.poll() is None:process.kill()
                                    output,error=process.communicate(timeout=20)
                                    item={'certificate':name,'family':family,'backend':backend,'mode':mode,'payload':total,'streams':count,'peer_exit':done.returncode,'peer_stdout':done.stdout,'peer_stderr':done.stderr,'server_exit':process.returncode,'server_stdout':first+output,'server_stderr':error,'real_origins':origin.records};r['cases'].append(item)
                                    try:origin.finish()
                                    except BaseException as failure:item['origin_error']=repr(failure);raise RuntimeError(json.dumps(item,indent=2)) from failure
                                    print(name,family,backend,mode,total,'peer',done.returncode,'server',process.returncode,flush=True)
                                    if done.returncode or process.returncode:raise RuntimeError(json.dumps(item,indent=2))
                                finally:
                                    if process.poll() is None:process.kill();process.wait()
        r['complete']=True
    finally:a.report.write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
