#!/usr/bin/env python3
"""Verify ordinary-connect fallback with TFO disabled inside a network namespace."""
import socket
import subprocess
import sys
import threading

with open('/proc/sys/net/ipv4/tcp_fastopen','w') as control:control.write('0')
subprocess.run(['ip','link','set','lo','up'],check=True)
for backend in ('epoll','uring'):
    for family,label,host in ((socket.AF_INET,'v4','127.0.0.1'),(socket.AF_INET6,'v6','::1')):
        with socket.socket(family,socket.SOCK_STREAM) as server:
            server.bind((host,0));server.listen(1);server.settimeout(4);errors=[]
            def serve():
                try:
                    with server.accept()[0] as client:
                        client.settimeout(3)
                        if client.recv(1)!=b'\x42':raise RuntimeError('missing fallback payload')
                        client.sendall(b'\x5a')
                except Exception as error:errors.append(error)
            thread=threading.Thread(target=serve);thread.start()
            result=subprocess.run([sys.argv[1],backend,str(server.getsockname()[1]),label,'unsupported'],capture_output=True,text=True,timeout=6)
            thread.join(timeout=5)
            if result.returncode==77:print(f'{backend}: unavailable');break
            if result.returncode or thread.is_alive() or errors:
                raise RuntimeError(f'{backend}/{label}: exit={result.returncode} out={result.stdout!r} err={result.stderr!r} errors={errors!r}')
            print(f'{backend}/{label}: unsupported TFO fell back and delivered payload')
