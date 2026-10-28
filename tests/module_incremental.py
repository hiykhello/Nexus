"""Regression for separate module/consumer incremental builds."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(root, *args):
    env = {**os.environ, "XMAKE_GLOBALDIR": str(root / "global"), "XMAKE_CONFIGDIR": str(root / "config")}
    return subprocess.run(args, cwd=root, env=env, check=True, text=True, capture_output=True)


with tempfile.TemporaryDirectory(prefix="nexus-module-incremental-") as tmp:
    root = Path(tmp)
    rule = (ROOT / "build_config/module_tracking.lua").read_text()
    (root / "rule.lua").write_text(rule)
    (root / "xmake.lua").write_text('''set_project("module-incremental")
set_languages("c++26")
set_policy("build.c++.modules", true)
includes("rule.lua")
add_rules("mode.debug", "nexus.module_tracking")
target("mod")
    set_kind("static")
    add_files("model.cppm", {public=true})
    add_files("model.cpp")
target("client")
    set_kind("binary")
    add_files("client.cpp")
    add_deps("mod")
''')
    interface = root / "model.cppm"
    implementation = root / "model.cpp"
    client = root / "client.cpp"
    interface.write_text("export module model;\nexport struct Value { int a; };\nexport auto value() -> Value;\n")
    implementation.write_text("module model;\nauto value() -> Value { return {42}; }\n")
    client.write_text("import model;\nauto main() -> int { return value().a == 42 ? 0 : 1; }\n")
    run(root, "xmake", "f", "-y", "-m", "debug", "--toolchain=gcc")
    run(root, "xmake", "build", "-j", "1", "client")
    binary = root / "build/linux/x86_64/debug/client"
    run(root, str(binary))
    interface.write_text("export module model;\nexport struct Value { int padding; int a; };\nexport auto value() -> Value;\n")
    implementation.write_text("module model;\nauto value() -> Value { return {7,42}; }\n")
    run(root, "xmake", "build", "-j", "1", "mod")
    output = run(root, "xmake", "build", "-j", "1", "client").stdout
    if "compiling.debug client.cpp" not in output:
        raise RuntimeError("consumer was not recompiled after separately building its changed module")
    run(root, str(binary))
    output = run(root, "xmake", "build", "-j", "1", "client").stdout
    if "compiling.debug client.cpp" in output:
        raise RuntimeError("unchanged consumer was unnecessarily rebuilt")
print("Isolated module interface incremental rebuild passed")
