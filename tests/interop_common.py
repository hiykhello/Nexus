"""Helpers for local Nexus interoperability tests."""
from pathlib import Path
import os
from test_paths import require_fixture, require_nexus

ROOT = Path(__file__).resolve().parents[1]
PROXY_WORKERS = int(os.environ.get("NEXUS_TEST_WORKERS", "1"))


def __getattr__(name):
    if name == "NEXUS":
        return require_nexus()
    if name == "FIXTURE_DIR":
        return require_fixture(".")
    if name == "ASYNC_CLIENT" and os.environ.get("NEXUS_TEST_HTTPS_CLIENT"):
        return Path(os.environ["NEXUS_TEST_HTTPS_CLIENT"]).resolve()
    fixtures = {
        "CLIENT": "nexus-tls-openssl-client-test",
        "ASYNC_CLIENT": "nexus-tls-corosio-openssl-test",
        "VLESS_CLIENT": "nexus-vless-tls-test",
    }
    if name in fixtures:
        return require_fixture(fixtures[name])
    raise AttributeError(name)
