"""Replace listener policy while retaining the replay owner."""
import pathlib
import subprocess
import sys

listener = pathlib.Path(sys.argv[1]).resolve()
client = pathlib.Path(sys.argv[2]).resolve()
for size in (16, 32):
    server = subprocess.Popen([listener, str(size), "53", "reconfigure"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peer = None
    try:
        port = int(server.stdout.readline())
        peer = subprocess.Popen([client, str(port), str(size), "reconfigure"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if peer.stdout.readline().strip() != "ready": raise RuntimeError("client did not start")
        replacement = int(server.stdout.readline())
        output, error = peer.communicate(f"{replacement}\n", timeout=3)
        if peer.returncode: raise RuntimeError(f"client failed: {peer.returncode}, {output}, {error}")
        if server.wait(timeout=5): raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
    finally:
        for process in (peer, server):
            if process is not None and process.poll() is None:
                process.kill(); process.communicate()
print("SS-2022 UDP policy replacement and replay retention passed")
