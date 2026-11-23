"""Run the active guard's standalone suite under pytest.

tests/test_github_transition_guard.py is a script, not a pytest module, and it
sits outside `testpaths = tests/python`, so the CI pytest steps never ran it.
This wrapper makes the existing "security acceptance tests" step exercise
.claude/hooks/github_transition_guard.py as well.

GUARD_HOOK is pinned to this checkout's guard: an inherited GUARD_HOOK (the
suite's switch for testing another repo's copy) cannot redirect this test.
The suite's summary line is recorded as a user property, and conftest.py
prints it in the terminal summary so CI logs show the totals.
"""

import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUITE = ROOT / "tests" / "test_github_transition_guard.py"
HOOK = ROOT / ".claude" / "hooks" / "github_transition_guard.py"
SUMMARY = re.compile(r"^(?P<passed>\d+) passed, (?P<failed>\d+) failed \((?P<total>\d+) cases\)$", re.M)


def test_transition_guard_suite_passes(record_property):
    env = {**os.environ, "GUARD_HOOK": str(HOOK)}
    out = subprocess.run(
        [sys.executable, "-I", str(SUITE)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        env=env,
    )
    tail = out.stdout[-4000:] + out.stderr[-2000:]
    assert out.returncode == 0, tail
    summary = SUMMARY.search(out.stdout)
    assert summary, "suite printed no summary line\n" + tail
    passed, failed, total = (int(summary[k]) for k in ("passed", "failed", "total"))
    assert failed == 0 and passed == total > 0, tail
    record_property("transition_guard_suite", f"{summary.group(0)} [guard: {HOOK.relative_to(ROOT)}]")
