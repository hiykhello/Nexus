"""Resolve explicitly selected binaries for integration drivers.

Build configurations produce different output directories and may contain
different feature sets. Explicit selections take precedence over mcpp's
MCPP_BIN_<NAME> paths, which name programs from the active test configuration.
"""

import os
from pathlib import Path
import re


def mcpp_binary(name: str) -> Path | None:
    variable = "MCPP_BIN_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()
    value = os.environ.get(variable)
    return Path(value).resolve() if value else None


def optional_nexus() -> Path | None:
    value = os.environ.get("NEXUS_TEST_BINARY")
    return Path(value).resolve() if value else mcpp_binary("nexus")


def require_nexus() -> Path:
    result = optional_nexus()
    if result is None:
        raise SystemExit("Set NEXUS_TEST_BINARY or run under mcpp with MCPP_BIN_NEXUS")
    return result


def optional_fixture(name: str) -> Path | None:
    directory = os.environ.get("NEXUS_TEST_FIXTURE_DIR")
    return (Path(directory) / name).resolve() if directory else mcpp_binary(name)


def require_fixture(name: str) -> Path:
    result = optional_fixture(name)
    if result is None:
        raise SystemExit("Set NEXUS_TEST_FIXTURE_DIR, use mcpp's MCPP_BIN_<NAME>, or pass the fixture executable explicitly")
    return result
