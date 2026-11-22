import argparse,hashlib,json,socket,subprocess,sys,tempfile,threading,time
from pathlib import Path
sys.path.insert(0,'/home/yk/Code/Nexus/tests')
from quic_udp_network import credential,ready

class Origin:
    def __init__(self,total):
        self.socket=socket.socket();self.socket.bind(('127.0.0.1',0));self.socket.listen(1);self.socket.settimeout(12);self.port=self.socket.getsockname()[1];self.total=total;self.record={};self.thread=threading.Thread(target=self.run);self.thread.start()
    def run(self):
        try:
            peer,_=self.socket.accept();peer.settimeout(12);request_fin=threading.Event();errors=[]
            def respond():
                try:
                    peer.sendall(bytes((i*71+19)&255 for i in range(self.total)))
                    if not request_fin.wait(10):raise RuntimeError('request FIN did not reach actual origin')
                    peer.shutdown(socket.SHUT_WR);self.record['response_FIN']=time.monotonic()
                except BaseException as error:errors.append(repr(error))
            writer=threading.Thread(target=respond);writer.start();received=bytearray()
            while chunk:=peer.recv(16384):received.extend(chunk)
            self.record.update(request_FIN=time.monotonic(),received=len(received),valid=received==bytes((i*71+37)&255 for i in range(self.total)));request_fin.set();writer.join(12);peer.close()
            if writer.is_alive() or errors or not self.record['valid']:raise RuntimeError(errors)
            self.record['request_FIN_before_response_FIN']=self.record['request_FIN']<=self.record['response_FIN']
            if not self.record['request_FIN_before_response_FIN']:raise RuntimeError('independent FIN ordering was not observed')
        except BaseException as error:self.record['error']=repr(error)
        finally:self.socket.close()
    def finish(self):
        self.thread.join(15)
        if self.thread.is_alive() or self.record.get('error') or not self.record.get('valid'):raise RuntimeError(self.record)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('server',type=Path);parser.add_argument('peer',type=Path);parser.add_argument('--report',type=Path,required=True);parser.add_argument('--quick',action='store_true');parser.add_argument('--preauth',action='store_true');parser.add_argument('--backend',choices=('0','1','both'),default='both');args=parser.parse_args()
    server=args.server.resolve(strict=True);peer=args.peer.resolve(strict=True)
    report={'complete':False,'server_sha256':hashlib.sha256(server.read_bytes()).hexdigest(),'peer_sha256':hashlib.sha256(peer.read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':[]}
    try:
        with tempfile.TemporaryDirectory(prefix='hy2-native-retry-') as tmp:
            algorithms=[('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'])]
            if not args.quick:algorithms+=[('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048']),('ed25519','ED25519',[])]
            for name,kind,options in algorithms:
                cert,key=credential(Path(tmp),name,kind,options)
                for family in (['4'] if args.quick else ['4','6']):
                    for backend in ([args.backend] if args.backend!='both' else ['0'] if args.quick else ['0','1']):
                        for mode in (['split','full','full-flood','truncated-fin'] if args.preauth else ['tcp']):
                            for total in ([65537] if args.preauth or args.quick else [0,65537]):
                                origin=Origin(total);process,port,first=ready([server,cert,key,family,backend,1,total,origin.port])
                                try:
                                    done=subprocess.run([peer,family,str(port),cert,mode,str(total)],capture_output=True,text=True,timeout=15)
                                    if done.returncode and process.poll() is None:process.kill()
                                    output,error=process.communicate(timeout=15);origin.finish()
                                    item={'certificate':name,'family':family,'backend':backend,'mode':mode,'payload':total,'peer_exit':done.returncode,'peer_stdout':done.stdout,'peer_stderr':done.stderr,'server_exit':process.returncode,'server_stdout':first+output,'server_stderr':error,'actual_origin':origin.record};report['cases'].append(item)
                                    print(name,family,backend,mode,total,'peer',done.returncode,'server',process.returncode,flush=True)
                                    if done.returncode or process.returncode:raise RuntimeError(json.dumps(item,indent=2))
                                finally:
                                    if process.poll() is None:process.kill();process.wait()
        report['complete']=True
    finally:args.report.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
