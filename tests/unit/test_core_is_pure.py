"""``alerting.core`` is the trusted computing base, so it stays free of I/O.

Purity is not an aesthetic here. It is what lets the same trust decision run
identically on the server and on a phone, be replayed against a recorded incident, and
be tested without a network, a database, or a real clock. This test fails the build if
someone reaches for ``requests`` inside the verifier.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

CORE = pathlib.Path(__file__).resolve().parents[2] / "src" / "alerting" / "core"

#: Anything that touches the world. ``time`` is separately confined to clock.py.
BANNED = {
    "asyncio",
    "fastapi",
    "http",
    "httpx",
    "os",
    "pathlib",
    # The database driver, both spellings. `sqlite3` was already banned; after the
    # PostgreSQL port that entry no longer guards anything on its own, and a ban that
    # has quietly stopped applying is worse than no ban.
    "psycopg",
    "psycopg_pool",
    "requests",
    "socket",
    "sqlite3",
    "subprocess",
    "urllib",
    "uvicorn",
    "websockets",
}

#: The single sanctioned seam to real time.
CLOCK_MODULE = "clock.py"


def imported_roots(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def core_modules() -> list[pathlib.Path]:
    return sorted(CORE.glob("*.py"))


def test_there_are_core_modules_to_check():
    assert len(core_modules()) >= 10


@pytest.mark.parametrize("module", core_modules(), ids=lambda p: p.name)
def test_no_io_imports(module: pathlib.Path):
    offenders = imported_roots(module) & BANNED
    assert not offenders, f"{module.name} imports {sorted(offenders)}"


@pytest.mark.parametrize("module", core_modules(), ids=lambda p: p.name)
def test_only_clock_reads_real_time(module: pathlib.Path):
    if module.name == CLOCK_MODULE:
        return
    assert "time" not in imported_roots(module), (
        f"{module.name} reads the clock directly; take a Clock argument instead"
    )


@pytest.mark.parametrize("module", core_modules(), ids=lambda p: p.name)
def test_third_party_surface_stays_small(module: pathlib.Path):
    """core depends on cryptography, pydantic and the standard library. Nothing else."""
    allowed = {
        "alerting",
        "cryptography",
        "pydantic",
        # stdlib, pure
        "__future__",
        "ast",
        "base64",
        "collections",
        "dataclasses",
        "enum",
        "hashlib",
        "hmac",
        "secrets",
        "time",
        "typing",
        "unicodedata",
        "uuid",
    }
    unexpected = imported_roots(module) - allowed
    assert not unexpected, f"{module.name} imports {sorted(unexpected)}"
