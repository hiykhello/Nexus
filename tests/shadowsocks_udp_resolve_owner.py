"""Verify concurrent pending DNS operations are canceled and drained."""
import pathlib
import socket
import subprocess
import sys
import threading

fixture=pathlib.Path(sys.argv[1]).resolve()
backend=sys.argv[2] if len(sys.argv)>2 else "uring"
modes=("stop", "expired", "exception") if "--fault" in sys.argv[3:] else ("stop", "expired")
for mode in modes:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
    server.bind(("127.0.0.1",0))
    server.settimeout(3)
    observed=[]
    errors=[]
    def peer():
        try:
            for _ in range(2):
                data,peer=server.recvfrom(512)
                observed.append((data,peer))
            if mode=="exception":
                query,peer=observed[0]
                response=bytearray(query)
                response[2:4]=b"\x81\x80"
                response[7]=1
                response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                server.sendto(response,peer)
        except Exception as exc:
            errors.append(exc)
    worker=threading.Thread(target=peer)
    worker.start()
    result=subprocess.run([fixture,str(server.getsockname()[1]),mode,backend],capture_output=True,timeout=5)
    worker.join(timeout=4)
    if result.returncode or worker.is_alive() or errors or len(observed)!=2:
        raise RuntimeError(f"{backend}/{mode}: exit={result.returncode}, queries={len(observed)}, errors={errors}, stderr={result.stderr!r}")
print(f"SS-2022 UDP concurrent DNS {', '.join(modes)} passed ({backend})")
