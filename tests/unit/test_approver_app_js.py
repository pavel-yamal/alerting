"""The decision-makers' app (apps/approver, docs/adr/0016) under its own Node tests.

Run from here so CI needs no separate step: the app's pure rules, the shared review
code in devicekey.js, and what the app must never ship with (a page loaded from a
server, a live-update plugin, a token written to storage). Skipped where Node is not
installed, like test_devicekey_js.py.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

APP = pathlib.Path("apps/approver")
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def test_the_app_tests_pass() -> None:
    assert NODE is not None
    files = sorted(str(p) for p in (APP / "test").glob("*.test.mjs"))
    assert files, "the app's tests are where this expects them"
    result = subprocess.run(
        [NODE, "--test", *files], capture_output=True, text=True, timeout=120, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_page_builds_with_the_panels_signing_code() -> None:
    """www/ carries devicekey.js byte for byte: one implementation for both clients."""
    assert NODE is not None
    result = subprocess.run(
        [NODE, str(APP / "scripts" / "build.mjs")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    shipped = (APP / "www" / "devicekey.js").read_bytes()
    assert shipped == pathlib.Path("src/alerting/clients/panel/static/devicekey.js").read_bytes()
