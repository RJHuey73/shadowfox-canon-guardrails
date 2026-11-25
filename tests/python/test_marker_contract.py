"""The shared marker contract, as read by hooks/pre_tool_guard.py.

Same fixture file as tests/js/marker-contract.test.mjs, so a case that the
hook and requireT0Go() decide differently fails in one of the two suites.
"""

import pytest

from conftest import FIXTURES, marker_text


def _outcome(guard, scope, min_tier):
    try:
        guard.check_t0_go(scope, min_tier=min_tier)
    except SystemExit as exc:
        return "deny" if exc.code == 2 else f"exit {exc.code}"
    except Exception as exc:  # a crash exits 1 at runtime: Claude Code allows the call
        return f"crash ({type(exc).__name__}) = fail-open"
    return "allow"


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=[c["id"] for c in FIXTURES["cases"]])
def test_marker_fixture(case, guard, marker_path):
    marker_path.write_text(marker_text(case))
    scope = case.get("scope", FIXTURES["default_scope"])
    assert _outcome(guard, scope, case.get("min_tier", 1)) == case["expect"]


def test_missing_marker_denies(guard):
    assert _outcome(guard, "tblEZ6ctzSoTBsfCW", 1) == "deny"


def test_hook_check_never_consumes(guard, marker_path):
    marker_path.write_text(marker_text(FIXTURES["cases"][0]))
    before = marker_path.read_text()
    assert _outcome(guard, "tblEZ6ctzSoTBsfCW", 1) == "allow"
    assert marker_path.read_text() == before
