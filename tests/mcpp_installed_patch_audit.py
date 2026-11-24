#!/usr/bin/env python3
"""Exercise the installed-source audit on ordered patches and hostile variants."""
import io
import json
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = runpy.run_path(str(ROOT / "scripts/mcpp-verify-installed.py"))


class PatchAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nexus-patch-audit-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.archive = self.path / "source.tar"
        with tarfile.open(self.archive, "w") as tar:
            for name in ("pkg", "pkg/lib"):
                item = tarfile.TarInfo(name)
                item.type = tarfile.DIRTYPE
                item.mode = 0o755
                tar.addfile(item)
            item = tarfile.TarInfo("pkg/lib/data.c")
            item.mode = 0o644
            item.size = 4
            tar.addfile(item, io.BytesIO(b"one\n"))
        self.first = self.path / "first.patch"
        self.first.write_text("--- a/pkg/lib/data.c\n+++ b/pkg/lib/data.c\n@@ -1 +1 @@\n-one\n+two\n")
        self.second = self.path / "second.patch"
        self.second.write_text("--- a/pkg/lib/data.c\n+++ b/pkg/lib/data.c\n@@ -1 +1 @@\n-two\n+three\n"
                               "--- /dev/null\n+++ b/pkg/lib/new.h\n@@ -0,0 +1 @@\n+added\n")
        self.pin = {"source_root": "pkg", "mcpp_patches": [{"path": str(self.first)}, {"path": str(self.second)}]}
        self.base = self.path / "variant"
        (self.base / "pkg/lib").mkdir(parents=True)
        (self.base / "pkg/lib/data.c").write_bytes(b"three\n")
        (self.base / "pkg/lib/new.h").write_bytes(b"added\n")

    def test_ordered_patches_and_tampering(self):
        changed, additions = AUDIT["patched_files"](self.archive, self.pin)
        self.assertEqual(additions, {"lib/new.h"})
        AUDIT["compare_archive"](self.archive, self.base, "pkg", changed, additions)
        for name in ("data.c", "new.h"):
            path = self.base / "pkg/lib" / name
            original = path.read_bytes()
            path.write_bytes(original + b"tampered\n")
            with self.assertRaises(ValueError):
                AUDIT["compare_archive"](self.archive, self.base, "pkg", changed, additions)
            path.write_bytes(original)
        extra = self.base / "pkg/lib/extra"
        extra.write_text("untracked")
        with self.assertRaises(ValueError):
            AUDIT["compare_archive"](self.archive, self.base, "pkg", changed, additions)
        extra.unlink()
        path = self.base / "pkg/lib/new.h"
        path.unlink()
        path.symlink_to("data.c")
        with self.assertRaises(ValueError):
            AUDIT["compare_archive"](self.archive, self.base, "pkg", changed, additions)

    def test_reversed_and_unsafe_patches_rejected(self):
        self.pin["mcpp_patches"].reverse()
        with self.assertRaises(subprocess.CalledProcessError):
            AUDIT["patched_files"](self.archive, self.pin)
        unsafe = self.path / "unsafe.patch"
        unsafe.write_text("--- /dev/null\n+++ b/pkg/../escape\n@@ -0,0 +1 @@\n+bad\n")
        with self.assertRaises(ValueError):
            AUDIT["patch_paths"](unsafe, "pkg")

    def test_locked_variant_requires_exact_order_and_marker(self):
        digest = "a" * 64
        package = "nexus.ngtcp2-source"
        pin = {"descriptor": package + ".lua", "version": "1",
               "mcpp_patches": [{"path": "first", "sha256": "1" * 64},
                                {"path": "second", "sha256": "2" * 64}]}
        key = package + "+p" + digest[:12]
        lock = {"package": {key: {"version": "1", "variant": digest,
                                  "patches": ["first#sha256:" + "1" * 64,
                                              "second#sha256:" + "2" * 64]}}}
        variant = self.path / package / ("1+p" + digest[:12])
        variant.mkdir(parents=True)
        (variant / ".mcpp-variant").write_text(digest + "\n")
        self.assertEqual(AUDIT["variant_path"]("test", pin, self.path, lock), variant)
        pin["mcpp_patches"].reverse()
        with self.assertRaises(ValueError):
            AUDIT["variant_path"]("test", pin, self.path, lock)
        pin["mcpp_patches"].reverse()
        (variant / ".mcpp-variant").write_text("bad\n")
        with self.assertRaises(ValueError):
            AUDIT["variant_path"]("test", pin, self.path, lock)

    def test_hunk_offsets_are_rejected(self):
        archive = self.path / "offset.tar"
        with tarfile.open(archive, "w") as tar:
            item = tarfile.TarInfo("pkg/lib/data.c")
            data = b"header\none\n"
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
        pin = {"source_root": "pkg", "mcpp_patches": [{"path": str(self.first)}]}
        with self.assertRaisesRegex(ValueError, "offset"):
            AUDIT["patched_files"](archive, pin)

    def test_manifest_must_select_ordered_pins(self):
        pin = {"version": "1", "mcpp_patches": [{"path": "3rdparty/a.patch"},
                                                 {"path": "3rdparty/b.patch"}]}
        manifest = self.path / "mcpp.toml"
        def write(patches, version="=1", embed=True, key="nexus.ngtcp2-source"):
            manifest.write_text("[feature-deps.quic-native]\n" + key + " = { version = "
                                + json.dumps(version) + ", embed = " + str(embed).lower()
                                + ", patches = " + json.dumps(patches) + " }\n")
        verify = AUDIT["VERIFY"]["verify_ngtcp2_manifest"]
        good = ["../3rdparty/a.patch", "../3rdparty/b.patch"]
        write(good)
        verify(manifest, pin)
        write(good, key='"nexus.ngtcp2-source"')
        verify(manifest, pin)
        for paths, version, embed in ((good[:1], "=1", True), (list(reversed(good)), "=1", True),
                                      ([good[0], good[0]], "=1", True),
                                      (["../3rdparty/./a.patch", good[1]], "=1", True),
                                      (["../../3rdparty/a.patch", good[1]], "=1", True),
                                      (good + [good[0]], "=1", True),
                                      (good, "1", True), (good, "=1", False)):
            write(paths, version, embed)
            with self.assertRaises(ValueError):
                verify(manifest, pin)




if __name__ == "__main__":
    unittest.main()
