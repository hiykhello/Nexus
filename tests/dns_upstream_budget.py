#!/usr/bin/env python3
import socket
import subprocess
import sys
import threading

for backend in ('epoll','uring'):
    for mode in ('udp','tcp'):
        listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if mode=='udp' else socket.SOCK_STREAM)
        listener.bind(('127.0.0.1',0));listener.settimeout(1)
        if mode=='tcp':listener.listen(8)
        stop=threading.Event();seen=[];connections=[]
        def serve():
            while not stop.is_set():
                try:
                    if mode=='udp':
                        data,_=listener.recvfrom(4096);seen.append(len(data))
                    else:
                        conn,_=listener.accept();conn.settimeout(1);connections.append(conn)
                        prefix=conn.recv(2)
                        if len(prefix)!=2:continue
                        remaining=int.from_bytes(prefix,'big')
                        while remaining:
                            part=conn.recv(remaining)
                            if not part:break
                            remaining-=len(part)
                        seen.append(1);conn.sendall((60000).to_bytes(2,'big'))
                except OSError:pass
        worker=threading.Thread(target=serve);worker.start()
        result=subprocess.run([sys.argv[1],backend,str(listener.getsockname()[1]),mode],capture_output=True,text=True,timeout=8)
        stop.set();listener.close();worker.join(timeout=2)
        for conn in connections:conn.close()
        if result.returncode==77: print(f'{backend}: unavailable');break
        if result.returncode or len(seen)!=3:
            raise RuntimeError(f'{backend}/{mode}: exit={result.returncode}, seen={seen}, out={result.stdout!r}, err={result.stderr!r}')
        print(f'{backend}/{mode}: {result.stdout.strip()}')
