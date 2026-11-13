"""KNOWN GAPS: these are not security acceptance tests.

Each test pins current behaviour that is unsafe, or not proven safe, but was
deliberately left unchanged because fixing it is an authorization-model
decision for T0 (see docs/THREAT-MODEL.md and docs/adr/). A passing test here
means "the gap is still exactly as documented", never "this is protected".
When a gap is closed, delete its test here and add an acceptance test in
test_pre_tool_guard.py / test_harness_failures.py that asserts the new,
safe behaviour.

Reconciliation 1c (2026-11-13): the direct T10 forms, the listed T11 tools,
the T11 HTTP-verb case and T12 were closed by the reconciled hook and moved
to test_pre_tool_guard.py as acceptance tests. What remains pinned here is
still open. The proposed design for closing the Canon-route gaps is
ADR-0001 (PR #3, Proposed, not ratified).

Run separately: python -m pytest tests/python -m known_gap
"""

import json

import pytest

from conftest import valid_marker

pytestmark = pytest.mark.known_gap

CANON_BASE = "appVftexD3KJRcdij"
SESSION = "tblEZ6ctzSoTBsfCW"
ALLOW = 0


def mcp(tool_name, **tool_input):
    return {"tool_name": tool_name, "tool_input": tool_input}


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


# --- T9: replay on hook-only write paths ------------------------------------

@pytest.mark.parametrize("tool", ["mcp__github__push_files", "mcp__Supabase__apply_migration"])
def test_gap_t9_hook_only_paths_never_consume_the_marker(run_hook, marker_path, tool):
    scope = "github:write" if "github" in tool else "supabase:apply_migration"
    marker_path.write_text(json.dumps(valid_marker([scope])))
    before = marker_path.read_text()
    assert [run_hook(mcp(tool)).returncode for _ in range(3)] == [ALLOW, ALLOW, ALLOW]
    assert marker_path.read_text() == before


# --- T10 (remaining): obfuscated marker writes ------------------------------
# The reconciled hook denies direct references to the marker file and the
# issuer, but its checks are string matches. Shell obfuscation defeats them,
# and an agent with file-system access can always write the file by a route
# the hook does not see. Nothing here is executed.

@pytest.mark.parametrize(
    "command",
    [
        "echo '{}' > .claude/t0-g*.json",
        "python3 -c \"open('.claude/t0-'+'go.json','w').write('{}')\"",
    ],
)
def test_gap_t10_obfuscated_marker_writes_are_not_detected(run_hook, command):
    assert run_hook(bash(command)).returncode == ALLOW


# --- T11 (remaining): write routes the hook cannot attribute ------------------

@pytest.mark.parametrize(
    "command",
    [
        # Canon table hidden behind a shell variable: no protected identifier
        # appears in the command string.
        'curl -X PATCH "$CANON_URL" -d \'{"fields":{}}\'',
        # GitHub writes through the gh CLI are not classified at all.
        "gh api -X POST repos/RJHuey73/shadowfox-canon-guardrails/pulls -f title=x",
    ],
)
def test_gap_t11_bash_write_routes_without_a_named_protected_surface(run_hook, command):
    assert run_hook(bash(command)).returncode == ALLOW


# --- TTL has no upper bound ---------------------------------------------------

def test_gap_ttl_is_unbounded(guard, marker_path):
    marker_path.write_text(json.dumps(valid_marker([SESSION], ttl_seconds=10 * 365 * 24 * 3600)))
    guard.check_t0_go(SESSION, min_tier=1)  # returns: allowed
