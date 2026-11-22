"""Local resolver: hosts/literals, DNS transport, retries and cancellation."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT = pathlib.Path(sys.argv[1]).resolve()


def read_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count-len(data))
        if not part: raise RuntimeError('short DNS TCP frame')
        data.extend(part)
    return bytes(data)


def response(query):
    if query[12:-4] != b'\x06remote\x04test\x00' or query[-4:] != b'\x00\x01\x00\x01':
        raise RuntimeError(f'unexpected query {query!r}')
    return query[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+query[12:]+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x2a'


def scenario(mode, guard):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second, socket.socket() as tcp:
        first.bind(('127.0.0.1', 0)); second.bind(('127.0.0.1', 0)); first.settimeout(3); second.settimeout(3)
        tcp.bind(('127.0.0.1',first.getsockname()[1])); tcp.listen(2); tcp.settimeout(3)
        events=[]; errors=[]
        def serve():
            try:
                if mode in ('hosts','hosts-v6','literal'): return
                if mode=='tcp':
                    peer,_=tcp.accept()
                    with peer:
                        peer.settimeout(3); size=int.from_bytes(read_exact(peer,2),'big'); wire=read_exact(peer,size)
                        result=response(wire); peer.sendall(len(result).to_bytes(2,'big')+result)
                    events.append('tcp'); return
                if mode=='rotate':
                    wire,peer=second.recvfrom(512); events.append('second'); second.sendto(response(wire),peer); return
                wire,peer=first.recvfrom(512); events.append('first')
                if mode=='cancel': return
                if mode=='retry':
                    wire,peer=second.recvfrom(512); events.append('second'); second.sendto(response(wire),peer)
                else: first.sendto(response(wire),peer)
            except Exception as exc: errors.append(exc)
        thread=threading.Thread(target=serve); thread.start()
        env=__import__('os').environ.copy(); env['LD_PRELOAD']=str(guard)
        result=subprocess.run([CLIENT,mode,str(first.getsockname()[1]),str(second.getsockname()[1])],env=env,capture_output=True,timeout=7)
        thread.join(4)
        expected={'udp':['first'],'retry':['first','second'],'rotate':['second'],'cancel':['first'],'tcp':['tcp']}.get(mode,[])
        if result.returncode or thread.is_alive() or errors or events!=expected or b'unexpected-system-resolver' in result.stderr:
            raise RuntimeError(f'{mode}: code={result.returncode} events={events} errors={errors} stderr={result.stderr!r}')


def search_scenario(mode, expected, guard):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1',0)); server.settimeout(3)
        events=[]; errors=[]
        def serve():
            try:
                for index,want in enumerate(expected):
                    query,peer=server.recvfrom(512)
                    name=query[12:-4]; events.append(name)
                    if name!=want or query[-4:]!=b'\x00\x01\x00\x01': raise RuntimeError(f'wrong question: {query!r}')
                    if mode=='search-cancel': return
                    if mode=='search-timeout':
                        server.settimeout(1.5)
                        try: raise RuntimeError(f'timeout triggered another candidate: {server.recvfrom(512)!r}')
                        except TimeoutError: return
                    nodata=mode=='search-nodata' and index==0
                    code=2 if mode=='search-failure' else 3 if index+1<len(expected) and not nodata else 0
                    answer=query[:2]+bytes((0x81,0x80|code))+b'\x00\x01'+(b'\x00\x01' if code==0 and not nodata else b'\x00\x00')+(b'\x00\x01' if nodata else b'\x00\x00')+b'\x00\x00'+query[12:]
                    if nodata: answer+=b'\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c'+bytes(20)
                    elif code==0: answer+=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x2a'
                    server.sendto(answer,peer)
                server.settimeout(.25)
                try: raise RuntimeError(f'unexpected additional query: {server.recvfrom(512)!r}')
                except TimeoutError: pass
            except Exception as exc: errors.append(exc)
        thread=threading.Thread(target=serve); thread.start()
        env=__import__('os').environ.copy(); env['LD_PRELOAD']=str(guard)
        result=subprocess.run([CLIENT,mode,str(server.getsockname()[1]),'0'],env=env,capture_output=True,timeout=7)
        thread.join(4)
        if result.returncode or thread.is_alive() or errors or events!=expected or b'unexpected-system-resolver' in result.stderr:
            raise RuntimeError(f'{mode}: code={result.returncode} events={events} errors={errors} stderr={result.stderr!r}')


with tempfile.TemporaryDirectory(prefix='nexus-local-dns-') as directory:
    guard=pathlib.Path(directory)/'guard.so'
    subprocess.run(['cc','-shared','-fPIC',ROOT/'tests/proxy_dns_system_guard.c','-o',guard],check=True)
    for mode in ('hosts','hosts-v6','literal','udp','tcp','retry','rotate','cancel'): scenario(mode,guard)
    short=b'\x06remote\x05first\x04test\x00'; second=b'\x06remote\x06second\x04test\x00'; bare=b'\x06remote\x00'
    dotted=b'\x06remote\x04test\x00'; qualified=b'\x06remote\x04test\x05first\x04test\x00'
    for mode,expected in (('search',[short]),('search-fallback',[short,second,bare]),('search-nodata',[short,second]),('search-zero',[bare,short]),('search-root',[bare,short]),
                          ('search-absolute-first',[dotted,qualified]),('ndots',[qualified]),
                          ('absolute',[dotted]),('search-cancel',[short]),('search-failure',[short]),('search-timeout',[short])):
        search_scenario(mode,expected,guard)
print('Local asynchronous DNS hosts, numeric addresses, UDP/TCP, retry, rotation and cancellation passed')
