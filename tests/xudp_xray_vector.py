"""Compare actual Xray packet writer with Nexus frame encoding."""
import pathlib
import subprocess
import sys
root=pathlib.Path(__file__).resolve().parents[1]
fixture=pathlib.Path(sys.argv[1]).resolve()
expected=subprocess.run(['go','run','.'],cwd=root/'experiments/xudp-vector',check=True,capture_output=True).stdout
actual=subprocess.run([fixture,'--vectors'],check=True,capture_output=True).stdout
if expected!=actual: raise RuntimeError(f'XUDP frame mismatch: Xray {expected!r}, Nexus {actual!r}')
print('XUDP open and keep frames match pinned Xray PacketWriter')
