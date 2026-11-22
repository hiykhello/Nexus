#!/usr/bin/env python3
import argparse
import selectors
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def run(args, backend):
    upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.bind(('127.0.0.1',53));upstream.settimeout(.1)
    seen=threading.Event();quit=threading.Event();queries=[]
    def dns():
        while not quit.is_set():
            try:
                data,peer=upstream.recvfrom(65535);queries.append((data,peer));seen.set()
            except TimeoutError:pass
    worker=threading.Thread(target=dns,daemon=True);worker.start()
    echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind(('127.0.0.1',0))
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);(root/'resolv').write_text('nameserver 127.0.0.1\noptions timeout:5 attempts:2\n');(root/'hosts').write_text('127.0.0.1 localhost\n')
        server=subprocess.Popen([args.server,backend,'4',args.cert,args.key,str(root/'resolv'),str(root/'hosts')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        client=None
        try:
            sel=selectors.DefaultSelector();sel.register(server.stdout,selectors.EVENT_READ)
            if not sel.select(10):raise RuntimeError('listener startup timeout')
            ready=server.stdout.readline().strip()
            if not ready.startswith('READY '):raise RuntimeError(ready)
            client=subprocess.Popen([args.client,'4',ready.split()[1],str(echo.getsockname()[1]),args.cert,'0x0403','blocked.example'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            if not seen.wait(8):raise RuntimeError('no actual DNS query observed')
            start=time.monotonic();output,_=server.communicate(timeout=15);elapsed=time.monotonic()-start
            client.terminate();client_output,_=client.communicate(timeout=4)
            print(f'{backend} queries={len(queries)} server={server.returncode} wait={elapsed:.3f}s {output.strip()} client={client.returncode} {client_output.strip()}')
            if server.returncode or 'drained=true clean=true failed=false sessions=0' not in output:raise RuntimeError('server did not drain')
        finally:
            if client and client.poll() is None:client.kill();client.wait()
            if server.poll() is None:server.kill();server.wait()
            quit.set();worker.join(timeout=2);upstream.close();echo.close()


def main():
    p=argparse.ArgumentParser();p.add_argument('server');p.add_argument('client');p.add_argument('cert');p.add_argument('key');p.add_argument('--backend',choices=['epoll','uring','both'],default='both');args=p.parse_args()
    for backend in (['epoll','uring'] if args.backend=='both' else [args.backend]):run(args,backend)
if __name__=='__main__':main()
