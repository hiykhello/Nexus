#!/usr/bin/env python3
import socket
import subprocess
import sys
import threading
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as upstream:
    upstream.bind(('127.0.0.1',0))
    upstream.settimeout(.1);stop=threading.Event();failures=[]
    def serve():
        try:
            while not stop.is_set():
                try: request,peer=upstream.recvfrom(65535)
                except TimeoutError:continue
                response=bytearray(request);response[2:4]=b'\x81\x80';response[7]=1
                response.extend(bytes.fromhex('c00c000100010000003c0004c0000201'))
                upstream.sendto(response,peer)
        except OSError as error: failures.append(error)
    worker=threading.Thread(target=serve);worker.start()
    try:
        for backend in ('epoll','uring'):
            result=subprocess.run([sys.argv[1],backend,str(upstream.getsockname()[1])],capture_output=True,text=True,timeout=10)
            if result.returncode==77:print(f'{backend}: unavailable');continue
            if result.returncode:raise RuntimeError(f'{backend}: exit={result.returncode}, out={result.stdout!r}, err={result.stderr!r}')
            print(f'{backend}: {result.stdout.strip()}')
    finally:
        stop.set();worker.join(timeout=2)
    if worker.is_alive() or failures:raise RuntimeError(f'upstream: {failures}')
