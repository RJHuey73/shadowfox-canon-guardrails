"""Shared helpers for the hook tests. Nothing here touches the network,
Airtable, or the real marker path: every test points the hook at a marker
file under pytest's tmp_path."""

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / "hooks" / "pre_tool_guard.py"
FIXTURES = json.loads((REPO / "tests" / "fixtures" / "marker_cases.json").read_text())


def render_time(token, offset=None, strip_tz=False):
    """Expand "$NOW", "$NOW+N", "$NOW-N" into the issuer's timestamp format
    (isoformat with microseconds, "+00:00" -> "Z"). Mirrors render in
    tests/js/helpers.mjs."""
    if not isinstance(token, str) or not token.startswith("$NOW"):
        return token
    delta = int(token[4:] or 0)
    t = datetime.now(timezone.utc) + timedelta(seconds=delta)
    if offset:
        sign = 1 if offset[0] == "+" else -1
        hours, minutes = offset[1:].split(":")
        tz = timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))
        return t.astimezone(tz).isoformat(timespec="microseconds")
    text = t.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return text[:-1] if strip_tz else text


def marker_text(case):
    if "raw" in case:
        return case["raw"]
    marker = dict(case["marker"])
    if "issued_at" in marker:
        marker["issued_at"] = render_time(
            marker["issued_at"], case.get("offset"), case.get("strip_tz", False)
        )
    return json.dumps(marker)


def valid_marker(scope, tier=1, **overrides):
    marker = {
        "decision_id": "T0-DEC-TEST",
        "scope": list(scope),
        "tier": tier,
        "issued_at": render_time("$NOW-5"),
        "ttl_seconds": 600,
        "consumed": False,
    }
    marker.update(overrides)
    return marker


@pytest.fixture
def marker_path(tmp_path):
    return tmp_path / "t0-go.json"


@pytest.fixture
def guard(marker_path, monkeypatch):
    """The hook module, imported fresh, pointed at a temp marker path."""
    monkeypatch.setenv("T0_GO_MARKER_PATH", str(marker_path))
    spec = importlib.util.spec_from_file_location("pre_tool_guard_under_test", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def run_hook(marker_path):
    """Run the real hook entrypoint as Claude Code does: JSON on stdin,
    decision in the exit code (2 = block, anything else = allow)."""

    def _run(payload, raw_stdin=None):
        env = {k: v for k, v in os.environ.items() if k != "T0_GO_MARKER_PATH"}
        env["T0_GO_MARKER_PATH"] = str(marker_path)
        stdin = raw_stdin if raw_stdin is not None else json.dumps(payload)
        proc = subprocess.run(
            [sys.executable, str(HOOK)], input=stdin, capture_output=True, text=True,
            env=env, timeout=30,
        )
        return proc

    return _run
