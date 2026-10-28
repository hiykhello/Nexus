"""Inject EIO into each FakeIpHistoryStore commit phase and reopen it."""
import os
import itertools
import pathlib
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="nexus-history-store-fault-") as root:
    root = pathlib.Path(root)
    injector = root / "fault.so"
    source = pathlib.Path(__file__).resolve().parents[1] / "beve-state" / "fault_inject.c"
    subprocess.run(["cc", "-shared", "-fPIC", str(source), "-o", str(injector)], check=True)
    for stage, save, mode in itertools.product(
        ("write", "file-sync", "rename", "dir-sync"), ("1", "2"), ("update", "update-start")
    ):
        directory = root / f"{stage}-{save}-{mode}"
        directory.mkdir(mode=0o700)
        subprocess.run([binary, directory, "init"], check=True, timeout=10)
        env = os.environ.copy()
        env.update(LD_PRELOAD=str(injector), NEXUS_FAULT_SAVE=save,
                   NEXUS_FAULT_STAGE=stage, NEXUS_EXPECT_FAULT="1")
        result = subprocess.run([binary, directory, mode], env=env, timeout=10, capture_output=True)
        if result.returncode != 0 or b"nexus injected EIO" not in result.stderr:
            raise RuntimeError(f"{stage}/{save}/{mode}: {result.returncode}, {result.stderr!r}")
        # After a failed directory fsync, rename is visible but persistence
        # across power loss is not established. All high-water-stage errors
        # happen after the history file has been committed.
        visible = "new" if save == "2" or stage == "dir-sync" else "old"
        subprocess.run([binary, directory, "verify-" + visible], check=True, timeout=10)
print("FakeIP history store injected EIO and independent reopen passed")
