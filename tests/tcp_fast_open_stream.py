#!/usr/bin/env python3
"""Real peer checks for delayed connect, concurrent I/O and half-close."""
import socket
import subprocess
import sys
import threading
import time

for backend in ('epoll','uring'):
    for family,label,host in ((socket.AF_INET,'v4','127.0.0.1'),(socket.AF_INET6,'v6','::1')):
        for mode in ('write-first','read-first','half','later','abandon'):
            with socket.socket(family,socket.SOCK_STREAM) as listener:
                listener.bind((host,0));listener.setsockopt(socket.IPPROTO_TCP,socket.TCP_FASTOPEN,8);listener.listen(1);listener.settimeout(4)
                errors=[]
                def serve():
                    try:
                        with listener.accept()[0] as peer:
                            peer.settimeout(4)
                            if mode=='abandon':
                                time.sleep(0.6)
                                received=0
                                try:
                                    while True:
                                        chunk=peer.recv(65536)
                                        if not chunk:break
                                        received+=len(chunk)
                                except ConnectionResetError:
                                    pass
                                if not received:raise RuntimeError('abandoned connection sent no data')
                                return
                            if mode=='read-first':peer.sendall(b'\x5a')
                            data=bytearray()
                            while True:
                                chunk=peer.recv(65536)
                                if not chunk:break
                                data.extend(chunk)
                            expected=b'' if mode=='half' else bytes(i%251 for i in range(200000))
                            if data!=expected:raise RuntimeError('payload mismatch or duplicated')
                            if mode!='read-first':peer.sendall(b'\x5a')
                    except Exception as error:errors.append(error)
                thread=threading.Thread(target=serve);thread.start()
                result=subprocess.run([sys.argv[1],backend,str(listener.getsockname()[1]),label,mode],capture_output=True,text=True,timeout=7)
                thread.join(timeout=5)
                if result.returncode==77:print(f'{backend}: unavailable');break
                if result.returncode or thread.is_alive() or errors:
                    raise RuntimeError(f'{backend}/{label}/{mode}: exit={result.returncode} out={result.stdout!r} err={result.stderr!r} errors={errors!r}')
                print(f'{backend}/{label}/{mode}: passed')
