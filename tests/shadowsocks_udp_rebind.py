"""Exercise listener rebinding using authenticated and forged UDP datagrams."""
import pathlib
import subprocess
import sys

listener=pathlib.Path(sys.argv[1]).resolve()
client=pathlib.Path(sys.argv[2]).resolve()
for size in (16,32):
    server=subprocess.Popen([listener,str(size),"53","allow"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        port=int(server.stdout.readline())
        subprocess.run([client,str(port),str(size)],check=True,timeout=3)
        if server.wait(timeout=5)!=0:
            raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()
print("SS-2022 UDP listener rebinding for both AES methods passed")
