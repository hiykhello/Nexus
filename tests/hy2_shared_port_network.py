import argparse,hashlib,json,subprocess,sys,tempfile,socket,threading,time
from pathlib import Path
sys.path.insert(0,'/home/yk/Code/Nexus/tests')
from quic_udp_network import credential,ready

class Origin:
    def __init__(self,count,total):
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(16);self.listener.settimeout(16);self.port=self.listener.getsockname()[1]
        self.errors=[];self.threads=[];self.count=count;self.total=total;self.completed=0
        self.root=threading.Thread(target=self.run);self.root.start()
    def serve(self,peer):
        try:
            peer.settimeout(16);outgoing=bytes((i*71+19)&255 for i in range(self.total));incoming=bytes((i*71+37)&255 for i in range(self.total))
            def send():
                try:
                    if outgoing:peer.sendall(outgoing)
                    time.sleep(.02);peer.shutdown(socket.SHUT_WR)
                except Exception as error:self.errors.append(repr(error))
            writer=threading.Thread(target=send);writer.start();data=bytearray()
            while True:
                part=peer.recv(16384)
                if not part:break
                data.extend(part)
            writer.join()
            if data!=incoming:raise RuntimeError(f'origin expected {len(incoming)} bytes, received {len(data)} bytes')
            self.completed+=1
        except Exception as error:self.errors.append(repr(error))
        finally:peer.close()
    def run(self):
        try:
            for _ in range(self.count):
                peer,_=self.listener.accept();thread=threading.Thread(target=self.serve,args=(peer,));thread.start();self.threads.append(thread)
        except Exception as error:self.errors.append(repr(error))
        finally:self.listener.close()
    def finish(self):
        self.root.join(18)
        for thread in self.threads:thread.join(18)
        if self.root.is_alive() or any(t.is_alive() for t in self.threads) or self.errors or self.completed!=self.count:raise RuntimeError(f'origin completed={self.completed} expected={self.count} errors={self.errors}')

def case(server_binary,client_binary,cert,key,scheme,family,backend,rounds,parallel,total,relay=False,same_source=False):
    origin=Origin(rounds*parallel,total) if relay else None
    processes=[];record={'family':family,'backend':backend,'rounds':rounds,'parallel':parallel,'bytes_each':total,'clients':[]}
    try:
        server,port,prefix=ready([server_binary,cert,key,family,backend,rounds*parallel,total,*([origin.port] if origin else [])]);processes.append(server)
        if same_source:
            client,source_port,first=ready([client_binary,cert,scheme,family,backend,port,total,rounds]);processes.append(client)
            output,error=client.communicate(timeout=22);record['same_source_port']=source_port;record['clients'].append({'exit':client.returncode,'stdout':first+output,'stderr':error})
            if client.returncode:raise RuntimeError(json.dumps(record,indent=2))
        else:
            for generation in range(rounds):
                batch=[]
                for index in range(parallel):
                    client,_,first=ready([client_binary,'client',family,port,cert,key,scheme,backend,total,'target.example:443','single']);processes.append(client);batch.append((client,first))
                for client,first in batch:
                    output,error=client.communicate(timeout=14);item={'round':generation,'exit':client.returncode,'stdout':first+output,'stderr':error};record['clients'].append(item)
                    if client.returncode:raise RuntimeError(json.dumps(record,indent=2))
        output,error=server.communicate(timeout=24);record.update(server_exit=server.returncode,server_stdout=prefix+output,server_stderr=error)
        if server.returncode:raise RuntimeError(json.dumps(record,indent=2))
        if origin:origin.finish();record["origin_verified"]=origin.completed
        return record
    finally:
        for p in processes:
            if p.poll() is None:p.kill();p.wait()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('server',type=Path);parser.add_argument('client',type=Path);parser.add_argument('--report',type=Path,required=True);parser.add_argument('--quick',action='store_true');parser.add_argument('--relay',action='store_true');parser.add_argument('--same-source',action='store_true');args=parser.parse_args()
    server=args.server.resolve();client=args.client.resolve();report={'complete':False,'server_sha256':hashlib.sha256(server.read_bytes()).hexdigest(),'client_sha256':hashlib.sha256(client.read_bytes()).hexdigest(),'cases':[]}
    try:
        with tempfile.TemporaryDirectory(prefix='hy2-shared-') as directory:
            algorithms=[('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'],'0x0403')]
            if not args.quick:algorithms += [('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048'],'0x0804'),('ed25519','ED25519',[],'0x0807')]
            for name,algorithm,options,scheme in algorithms:
                cert,key=credential(Path(directory),name,algorithm,options)
                for family in (['4'] if args.quick else ['4','6']):
                    for backend in (['0'] if args.quick else ['0','1']):
                        for total in ([65537] if args.quick else [0,1048577]):
                            item=case(server,client,cert,key,scheme,family,backend,3,2,total,args.relay,args.same_source);item['algorithm']=name;report['cases'].append(item);print(name,family,backend,total,'shared port6 native lifetimes passed',flush=True)
        report['complete']=True
    finally:args.report.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
