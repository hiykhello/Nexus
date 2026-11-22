#!/usr/bin/env python3
"""Keep real upstream UDP or TCP queries pending while measuring allocations."""
import socket
import subprocess
import sys
import threading

for backend in ('epoll', 'uring'):
    for mode in ('udp', 'tcp', 'message-udp', 'message-tcp', 'program-udp', 'program-tcp'):
        tcp=mode.endswith('tcp')
        server=socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0));server.settimeout(3)
        if tcp:server.listen(1)
        seen=[]
        def receive():
            try:
                if not tcp:
                    data,_=server.recvfrom(65535);seen.append(len(data))
                else:
                    client,_=server.accept()
                    with client:
                        client.settimeout(2)
                        data=b''
                        while len(data)<2:
                            chunk=client.recv(2-len(data))
                            if not chunk: return
                            data+=chunk
                        length=int.from_bytes(data,'big');received=0
                        while received<length:
                            chunk=client.recv(length-received)
                            if not chunk: return
                            received+=len(chunk)
                        seen.append(received)
                        client.recv(1)  # Keep the upstream pending until cancellation.
            except OSError: pass
        worker=threading.Thread(target=receive);worker.start()
        run=subprocess.run([sys.argv[1],backend,str(server.getsockname()[1]),mode],capture_output=True,text=True,timeout=5)
        server.close();worker.join(timeout=4)
        if run.returncode==77:
            print(f'{backend}: unavailable');break
        if run.returncode or not seen or seen[0]<60000:
            raise RuntimeError(f'{backend}/{mode}: exit={run.returncode} seen={seen} out={run.stdout!r} err={run.stderr!r}')
        print(f'{backend}/{mode}: {run.stdout.strip()}')
