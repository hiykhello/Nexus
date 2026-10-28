"""Verify concurrent pending DNS operations are canceled and drained."""
import pathlib
import socket
import subprocess
import sys
import threading

fixture=pathlib.Path(sys.argv[1]).resolve()
for mode in ("stop", "expired"):
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
    server.bind(("127.0.0.1",0))
    server.settimeout(3)
    observed=[]
    errors=[]
    def peer():
        try:
            for _ in range(2):
                data,_=server.recvfrom(512)
                observed.append(data)
        except Exception as exc:
            errors.append(exc)
    worker=threading.Thread(target=peer)
    worker.start()
    result=subprocess.run([fixture,str(server.getsockname()[1]),mode],capture_output=True,timeout=5)
    worker.join(timeout=4)
    if result.returncode or worker.is_alive() or errors or len(observed)!=2:
        raise RuntimeError(f"exit={result.returncode}, queries={len(observed)}, errors={errors}, stderr={result.stderr!r}")
print("SS-2022 UDP concurrent DNS stop and drain passed")
