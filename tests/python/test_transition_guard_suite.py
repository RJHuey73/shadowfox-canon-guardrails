"""Run the active guard's standalone suite under pytest.

tests/test_github_transition_guard.py is a script, not a pytest module, and it
sits outside `testpaths = tests/python`, so the CI pytest steps never ran it.
This wrapper makes the existing "security acceptance tests" step exercise
.claude/hooks/github_transition_guard.py as well.
"""

import pathlib
import subprocess
import sys

SUITE = pathlib.Path(__file__).resolve().parents[1] / "test_github_transition_guard.py"


def test_transition_guard_suite_passes():
    out = subprocess.run(
        [sys.executable, "-I", str(SUITE)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert out.returncode == 0, out.stdout[-4000:] + out.stderr[-2000:]
