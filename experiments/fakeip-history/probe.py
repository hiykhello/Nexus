"""Process crash and failure tests for the experimental FakeIP history fixture."""
import os
import pathlib
import select
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()

def run(directory, mode, expected=0):
    result = subprocess.run([binary, directory, mode], timeout=10, capture_output=True)
    if result.returncode != expected:
        raise RuntimeError(f"{mode}: {result.returncode}, {result.stderr!r}")

def prepare(directory, instance=b'I' * 16, key=bytes(range(32))):
    (directory / "instance.id").write_bytes(instance)
    (directory / "history.key").write_bytes(key)
    (directory / "instance.id").chmod(0o600)
    (directory / "history.key").chmod(0o600)

with tempfile.TemporaryDirectory(prefix="nexus-fakeip-history-") as temp:
    root = pathlib.Path(temp)
    injector = root / "fault.so"
    source = pathlib.Path(__file__).resolve().parent.parent / "beve-state" / "fault_inject.c"
    subprocess.run(["cc", "-shared", "-fPIC", '-DNEXUS_FAULT_TEMP_NAME="next"', str(source), "-o", str(injector)],
                   check=True, timeout=10)
    for stage in ("before-rename", "after-rename", "after-sync"):
        directory = root / stage; directory.mkdir(mode=0o700); prepare(directory)
        run(directory, "init")
        process = subprocess.Popen([binary, directory, stage], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 10)[0] or process.stdout.readline().strip() != "ready":
                raise RuntimeError(f"writer did not reach {stage}")
            run(directory, "verify-old", 3)
            process.kill(); process.wait(timeout=5)
        finally:
            if process.poll() is None: process.kill(); process.wait()
        run(directory, "verify-old" if stage == "before-rename" else "verify-new")
        if stage == "before-rename":
            run(directory, "update"); run(directory, "verify-new")
    for stage in ("write", "file-sync", "rename", "dir-sync"):
        directory = root / stage; directory.mkdir(mode=0o700); prepare(directory)
        run(directory, "init"); run(directory, "fail-" + stage)
        run(directory, "verify-new" if stage == "dir-sync" else "verify-old")
        injected = root / ("syscall-" + stage); injected.mkdir(mode=0o700); prepare(injected)
        run(injected, "init")
        env = os.environ.copy()
        env.update(LD_PRELOAD=str(injector), NEXUS_FAULT_SAVE="1", NEXUS_FAULT_STAGE=stage)
        result = subprocess.run([binary, injected, "update"], env=env, timeout=10, capture_output=True)
        if result.returncode != 10 or b"nexus injected EIO" not in result.stderr or b"published" in result.stdout:
            raise RuntimeError(f"{stage} syscall failure: {result.returncode}, {result.stdout!r}, {result.stderr!r}")
        run(injected, "verify-new" if stage == "dir-sync" else "verify-old")
        run(injected, "update"); run(injected, "verify-new")
    directory = root / "bad"; directory.mkdir(mode=0o700); prepare(directory)
    run(directory, "init")
    old_snapshot = (directory / "history").read_bytes()
    run(directory, "update")
    new_snapshot = (directory / "history").read_bytes()
    if old_snapshot == new_snapshot: raise RuntimeError("generation did not advance")
    (directory / "history").write_bytes(old_snapshot)
    run(directory, "verify-new", 5)
    (directory / "history").write_bytes(new_snapshot)
    highwater = directory / "highwater"
    high = highwater.read_bytes()
    highwater.chmod(0o644)
    run(directory, "verify-new", 5)
    highwater.chmod(0o600)
    highwater.unlink(); highwater.symlink_to(root / "before-rename" / "highwater")
    run(directory, "verify-new", 5)
    highwater.unlink(); highwater.write_bytes(high); highwater.chmod(0o600)
    highwater.write_bytes((3).to_bytes(8, "big"))
    run(directory, "verify-new", 5)
    highwater.write_bytes(high)
    data = bytearray((directory / "history").read_bytes()); data[25] ^= 1
    (directory / "history").write_bytes(data)
    run(directory, "update", 5)
    (directory / "history").unlink()
    run(directory, "update", 5)
    (directory / "history").symlink_to(root / "before-rename" / "history")
    run(directory, "update", 5)
    for name in ("instance.id", "history.key"):
        saved = (directory / name).read_bytes()
        (directory / name).chmod(0o644)
        run(directory, "verify-new", 4)
        (directory / name).chmod(0o600)
        (directory / name).unlink(); (directory / name).symlink_to(root / "before-rename" / name)
        run(directory, "verify-new", 4)
        (directory / name).unlink(); (directory / name).write_bytes(saved); (directory / name).chmod(0o600)
    wrong = bytearray((directory / "instance.id").read_bytes()); wrong[0] ^= 1
    (directory / "instance.id").write_bytes(wrong)
    run(directory, "verify-new", 5)
print("FakeIP history commit, lock contention, crash and syscall fault recovery passed")
