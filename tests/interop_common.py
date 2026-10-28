"""Helpers for local Nexus interoperability tests."""
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "build/linux/x86_64/debug/nexus-tls-openssl-client-test"
ASYNC_CLIENT = ROOT / "build/linux/x86_64/debug/nexus-tls-corosio-openssl-test"
VLESS_CLIENT = ROOT / "build/linux/x86_64/debug/nexus-vless-tls-test"
NEXUS = Path(os.environ.get("NEXUS_TEST_BINARY", ROOT / "build/linux/x86_64/debug/nexus")).resolve()
PROXY_WORKERS = int(os.environ.get("NEXUS_TEST_WORKERS", "1"))
