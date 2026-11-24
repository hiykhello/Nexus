"""Check failed FakeIP startup never listens, then recover visible history."""
import itertools
import os
import pathlib
import selectors
import shutil
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
project = pathlib.Path(__file__).resolve().parents[1]


def start(directory, workers, mode, pool, env=None):
    return subprocess.Popen([binary, directory, "9", str(workers), mode, pool],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env)


def command(process, text):
    process.stdin.write(text + "\n")
    process.stdin.flush()
    return process.stdout.readline().strip()


def stop(process):
    process.stdin.write("stop\n")
    process.stdin.flush()
    if process.wait(timeout=5) != 0:
        raise RuntimeError(f"fixture failed: {process.stderr.read()}")


with tempfile.TemporaryDirectory(prefix="nexus-fakeip-start-fault-") as root_path:
    root = pathlib.Path(root_path)
    inject = root / "inject.so"
    subprocess.run(["cc", "-shared", "-fPIC", project / "tests/proxy_fakeip_fault_inject.c",
                    project / "tests/proxy_fakeip_listen_probe.c", "-o", inject], check=True)
    crash_inject = root / "crash.so"
    subprocess.run(["cc", "-shared", "-fPIC", project / "tests/proxy_fakeip_crash_probe.c",
                    project / "tests/proxy_fakeip_listen_probe.c", "-o", crash_inject], check=True)
    seed = root / "seed"
    seed.mkdir(mode=0o700)
    for name, size in (("instance.id", 16), ("history.key", 32)):
        (seed / name).write_bytes(bytes(range(size)))
        (seed / name).chmod(0o600)
    trace = os.environ.copy()
    trace["LD_PRELOAD"] = str(inject)
    first = start(seed, 1, "new", "old", trace)
    try:
        if not first.stdout.readline().strip().isdigit():
            raise RuntimeError(f"seed startup failed: {first.stderr.read()}")
        time.sleep(2.1)
        if command(first, "publish") != "published":
            raise RuntimeError("seed pool did not publish")
        stop(first)
        if "nexus listen called" not in first.stderr.read():
            raise RuntimeError("listen probe did not observe successful startup")
    finally:
        if first.poll() is None:
            first.kill(); first.wait()

    def verify_recovery(directory, workers, new_visible):
        recovered = start(directory, workers, "existing", "old")
        try:
            if not recovered.stdout.readline().strip().isdigit():
                raise RuntimeError(f"reopen failed: {recovered.stderr.read()}")
            if command(recovered, "old") != "protected" or command(recovered, "publish") != "quarantined":
                raise RuntimeError("old history or quarantine was lost")
            if command(recovered, "new") != ("protected" if new_visible else "unprotected"):
                raise RuntimeError(f"unexpected visible history: {directory.name}")
            stop(recovered)
        finally:
            if recovered.poll() is None:
                recovered.kill(); recovered.wait()

    for workers, stage, save in itertools.product((1, 2), ("write", "file-sync", "rename", "dir-sync"), ("1", "2")):
        directory = root / f"{workers}-{stage}-{save}"
        shutil.copytree(seed, directory)
        env = trace.copy()
        env.update(NEXUS_FAULT_SAVE=save, NEXUS_FAULT_STAGE=stage)
        failed = subprocess.run([binary, directory, "9", str(workers), "existing", "new"],
                                env=env, capture_output=True, text=True, timeout=10)
        if (failed.returncode != 4 or failed.stdout or "nexus injected EIO" not in failed.stderr or
                "nexus listen called" in failed.stderr):
            raise RuntimeError(f"{workers}/{stage}/{save}: {failed.returncode}, {failed.stdout!r}, {failed.stderr!r}")

        # A rename is visible after a directory-fsync error, but that observation
        # does not establish power-loss durability.
        new_visible = save == "2" or stage == "dir-sync"
        verify_recovery(directory, workers, new_visible)

    for workers, stage, save in itertools.product((1, 2), ("file-sync", "rename", "dir-sync"), ("1", "2")):
        directory = root / f"crash-{workers}-{stage}-{save}"
        shutil.copytree(seed, directory)
        env = os.environ.copy()
        env.update(LD_PRELOAD=str(crash_inject), NEXUS_CRASH_SAVE=save, NEXUS_CRASH_STAGE=stage)
        crashed = start(directory, workers, "existing", "new", env)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(crashed.stderr, selectors.EVENT_READ)
                if not selector.select(10):
                    raise RuntimeError(f"crash checkpoint timed out: {directory.name}")
                marker = crashed.stderr.readline()
            if marker != "nexus crash checkpoint\n":
                raise RuntimeError(f"unexpected checkpoint: {directory.name}: {marker!r}")
            crashed.kill()
            stdout, stderr = crashed.communicate(timeout=5)
            if crashed.returncode != -9 or stdout or "nexus listen called" in stderr:
                raise RuntimeError(f"unexpected crash result: {directory.name}: {stdout!r}, {stderr!r}")
        finally:
            if crashed.poll() is None:
                crashed.kill(); crashed.wait()
        verify_recovery(directory, workers, save == "2" or stage != "file-sync")
print("FakeIP proxy startup EIO and SIGKILL prevent listen and preserve visible history")
