#!/usr/bin/env python3
import argparse
import selectors
import socket
import subprocess
import tempfile
import threading
from pathlib import Path


def run(args, family, backend):
    af=socket.AF_INET6 if family=="6" else socket.AF_INET
    address="::1" if family=="6" else "127.0.0.1"
    echo=socket.socket(af,socket.SOCK_DGRAM);echo.bind((address,0));echo.settimeout(.1)
    quit=threading.Event();packets=[]
    def serve():
        while not quit.is_set():
            try:
                data,peer=echo.recvfrom(65535);packets.append(data);echo.sendto(data,peer)
            except TimeoutError:pass
    worker=threading.Thread(target=serve,daemon=True);worker.start()
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);(root/"resolv").write_text("nameserver 127.0.0.1\n");(root/"hosts").write_text(f"{address} fixture.example\n")
        server=subprocess.Popen([args.server,backend,family,args.cert,args.key,str(root/"resolv"),str(root/"hosts")],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        try:
            sel=selectors.DefaultSelector();sel.register(server.stdout,selectors.EVENT_READ)
            if not sel.select(10):raise RuntimeError("listener did not become ready")
            line=server.stdout.readline().strip()
            if not line.startswith("READY "):raise RuntimeError(f"listener startup: {line}")
            port=line.split()[1]
            client=subprocess.run([args.client,family,port,str(echo.getsockname()[1]),args.cert,"0x0403","fixture.example"],capture_output=True,text=True,timeout=12)
            output,_=server.communicate(timeout=15)
            print(f"{backend} IPv{family} client={client.returncode} {client.stdout.strip()} server={server.returncode} {output.strip()}")
            if client.returncode or server.returncode or packets!=[bytes([11,22,33]),bytes([44,55,66])]:raise RuntimeError(f"failed packets={packets!r}")
        finally:
            if server.poll() is None:server.kill();server.wait()
            quit.set();worker.join(timeout=2);echo.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument("server");parser.add_argument("client");parser.add_argument("cert");parser.add_argument("key");parser.add_argument("--backend",choices=["epoll","uring","both"],default="both");parser.add_argument("--family",choices=["4","6","both"],default="both");args=parser.parse_args()
    for backend in (["epoll","uring"] if args.backend=="both" else [args.backend]):
        for family in (["4","6"] if args.family=="both" else [args.family]):run(args,family,backend)
if __name__=="__main__":main()
