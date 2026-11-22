#!/usr/bin/env python3
"""Exercise the single-candidate Fast Open foundation with real sockets."""
import socket
import subprocess
import sys
import threading

binary = sys.argv[1]
for backend in ('epoll', 'uring'):
    for family, label, host in ((socket.AF_INET, 'v4', '127.0.0.1'), (socket.AF_INET6, 'v6', '::1')):
        for mode in ('send', 'empty', 'refused'):
            with socket.socket(family, socket.SOCK_STREAM) as server:
                server.bind((host, 0)); port = server.getsockname()[1]
                if mode != 'refused':
                    server.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 8)
                    server.listen(1);server.settimeout(5)
                else:
                    server.close()
                failures = []
                def serve():
                    try:
                        with server.accept()[0] as client:
                            client.settimeout(4)
                            if mode == 'send':
                                expected=bytes(i%251 for i in range(200000));data=bytearray()
                                while len(data)<len(expected):
                                    part=client.recv(min(65536,len(expected)-len(data)))
                                    if not part: raise RuntimeError('truncated payload')
                                    data.extend(part)
                                if data!=expected:raise RuntimeError('payload changed or duplicated')
                            client.sendall(b'\x5a')
                    except Exception as error:failures.append(error)
                thread = threading.Thread(target=serve) if mode != 'refused' else None
                if thread:thread.start()
                result=subprocess.run([binary,backend,str(port),label,mode],capture_output=True,text=True,timeout=7)
                if thread:thread.join(timeout=6)
                if result.returncode==77:
                    if thread and thread.is_alive():server.close();thread.join(timeout=6)
                    print(f'{backend}: unavailable');break
                if result.returncode or (thread and thread.is_alive()) or failures:
                    raise RuntimeError(f'{backend}/{label}/{mode}: exit={result.returncode} out={result.stdout!r} err={result.stderr!r} failures={failures!r}')
                print(f'{backend}/{label}/{mode}: {result.stdout.strip() or "refused"}')
        for mode in ('candidates-empty','candidates-commit'):
            server=dead=None
            for _ in range(100):
                server=socket.socket(family,socket.SOCK_STREAM);dead=socket.socket(family,socket.SOCK_STREAM)
                server.bind((host,0));port=server.getsockname()[1]
                try:
                    if port==65535:raise OSError('maximum port')
                    dead.bind((host,port+1));break
                except OSError:server.close();dead.close()
            else:raise RuntimeError('adjacent candidate port unavailable')
            with server,dead:
                server.listen(2);server.settimeout(1);failures=[];seen=[]
                def accept_candidate():
                    try:
                        with server.accept()[0] as client:
                            seen.append(True);client.settimeout(2)
                            if mode=='candidates-commit' and client.recv(1)!=b'\x42':raise RuntimeError('wrong candidate payload')
                            client.sendall(b'\x5a')
                    except TimeoutError:pass
                    except Exception as error:failures.append(error)
                thread=threading.Thread(target=accept_candidate);thread.start()
                result=subprocess.run([binary,backend,str(port),label,mode],capture_output=True,text=True,timeout=6)
                thread.join(timeout=3)
                if result.returncode==77:break
                committed='candidate committed=' in result.stdout
                if result.returncode or thread.is_alive() or failures or bool(seen)==committed:
                    raise RuntimeError(f'{backend}/{label}/{mode}: {result.stdout!r} {result.stderr!r} seen={seen!r} failures={failures!r}')
                print(f'{backend}/{label}/{mode}: {result.stdout.strip() or "fallback passed"}')
