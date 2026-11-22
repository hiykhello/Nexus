"""Compare VLESS Mux headers to the pinned Xray encoder."""
import pathlib
import subprocess
import sys
root=pathlib.Path(__file__).resolve().parents[1]
expected=subprocess.run(['go','run','./vless'],cwd=root/'experiments/xudp-vector',check=True,capture_output=True).stdout
actual=subprocess.run([pathlib.Path(sys.argv[1]).resolve(),'--vectors'],check=True,capture_output=True).stdout
if actual!=expected: raise RuntimeError(f'VLESS Mux mismatch: Xray {expected!r}, Nexus {actual!r}')
print('VLESS Mux and Vision Mux headers match pinned Xray')
