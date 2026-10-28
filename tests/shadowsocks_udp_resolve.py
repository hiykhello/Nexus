"""Test SS-2022 UDP resolution against a controlled local DNS server."""
import pathlib
import socket
import subprocess
import sys
import threading
import time

client=pathlib.Path(sys.argv[1]).resolve()
for mode in ("success", "nxdomain", "cancel", "chain-cancel", "timeout", "stale", "blocked"):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
        dns.bind(("127.0.0.1",0))
        dns.settimeout(3)
        errors=[]
        def serve():
            try:
                query,peer=dns.recvfrom(512)
                if int.from_bytes(query[-4:-2],"big")!=1:
                    raise RuntimeError("unexpected question")
                if mode in ("cancel","chain-cancel","timeout"):
                    return
                if mode=="stale":
                    time.sleep(.25)
                response=bytearray(query)
                response[2:4]=b"\x81\x83" if mode=="nxdomain" else b"\x81\x80"
                if mode in ("success", "stale", "blocked"):
                    response[7]=1
                    response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                dns.sendto(response,peer)
            except Exception as exc:
                errors.append(exc)
        thread=threading.Thread(target=serve)
        thread.start()
        result=subprocess.run([client,str(dns.getsockname()[1]),mode],capture_output=True,timeout=6)
        thread.join(timeout=4)
        if result.returncode or thread.is_alive() or errors:
            raise RuntimeError(f"{mode}: exit={result.returncode}, errors={errors}, stderr={result.stderr!r}")
print("SS-2022 UDP async DNS success, policy, stale result, timeout and cancellation passed")
