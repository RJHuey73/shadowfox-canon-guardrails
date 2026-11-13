"""
Regression tests for hooks/pre_tool_guard.py (local input/policy hardening).

Run:  python3 -m unittest discover -s tests -v        (stdlib only; no network)

Isolation: every test uses a temporary directory. The hook is exercised as a
subprocess (the way Claude Code runs it) with T0_GO_MARKER_PATH pointing at a
temp path, or in-process for internal-error and size-limit cases. No real
marker, credential, network service or repository state is touched; the
payloads are synthetic strings the hook reads as data and never executes.

These tests demonstrate input/policy hardening of ONE local hook. They do not
demonstrate that G1 (the authorization boundary) is closed.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "pre_tool_guard.py"
FIXTURES = REPO / "tests" / "fixtures"
SETTINGS_EXAMPLE = REPO / "config" / "settings.json.example"

sys.path.insert(0, str(REPO / "hooks"))
import pre_tool_guard as guard  # noqa: E402

PROBES = json.loads((FIXTURES / "probes.json").read_text(encoding="utf-8"))


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def marker_doc(scope, *, tier=1, ttl=600, issued=None, consumed=False, decision="T0-DEC-TEST") -> dict:
    return {
        "decision_id": decision,
        "scope": scope,
        "tier": tier,
        "issued_at": iso(issued or datetime.now(timezone.utc)),
        "ttl_seconds": ttl,
        "consumed": consumed,
    }


class HookCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.marker = self.tmp / "isolated" / "marker.json"  # never created unless a test writes it
        self.marker.parent.mkdir()

    def write_marker(self, doc) -> None:
        self.marker.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")

    def run_hook(self, stdin, *, cwd=None, script=None, marker=True):
        env = {k: v for k, v in os.environ.items() if k != "T0_GO_MARKER_PATH"}
        if marker:
            env["T0_GO_MARKER_PATH"] = str(self.marker)
        data = stdin if isinstance(stdin, bytes) else (stdin if isinstance(stdin, str) else json.dumps(stdin)).encode()
        proc = subprocess.run(
            [sys.executable, str(script or HOOK)],
            input=data, capture_output=True, cwd=str(cwd or self.tmp), env=env, timeout=30,
        )
        return proc.returncode, proc.stderr.decode("utf-8", "replace")

    def assertDenied(self, result, code: str) -> None:
        rc, err = result
        self.assertEqual(rc, 2, f"expected exit 2, got {rc}: {err}")
        self.assertIn(f"[{code}]", err)

    def assertAllowed(self, result) -> None:
        rc, err = result
        self.assertEqual(rc, 0, f"expected exit 0, got {rc}: {err}")


# --------------------------------------------------------------------------
# Probes A-K and the allow / unclassified tables
# --------------------------------------------------------------------------


class TestProbes(HookCase):
    def test_probes_a_to_k_deny_with_expected_code(self) -> None:
        for p in PROBES["probes"]:
            with self.subTest(probe=p["id"]):
                stdin = p["raw_stdin"] if "raw_stdin" in p else p["payload"]
                self.assertFalse(self.marker.exists())
                self.assertDenied(self.run_hook(stdin), p["code"])

    def test_no_marker_denial_names_the_required_scope(self) -> None:
        for p in PROBES["probes"]:
            if p.get("code") == "NO_MARKER":
                with self.subTest(probe=p["id"]):
                    _, err = self.run_hook(p["payload"])
                    self.assertIn(p["scope"], err)

    def test_probes_with_a_scoped_marker_are_allowed_and_marker_is_not_consumed(self) -> None:
        for p in PROBES["probes"]:
            if p.get("code") == "NO_MARKER":
                with self.subTest(probe=p["id"]):
                    self.write_marker(marker_doc([p["scope"]]))
                    before = self.marker.read_bytes()
                    self.assertAllowed(self.run_hook(p["payload"]))
                    self.assertEqual(self.marker.read_bytes(), before, "hook must not consume the marker")

    def test_read_only_operations_are_allowed(self) -> None:
        for p in PROBES["read_only_allowed"]:
            with self.subTest(probe=p["id"]):
                self.assertAllowed(self.run_hook(p["payload"]))

    def test_unclassified_mcp_operations_are_denied(self) -> None:
        for p in PROBES["unclassified_denied"]:
            with self.subTest(probe=p["id"]):
                self.write_marker(marker_doc(["github:write", "supabase:apply_migration"], tier=2))
                self.assertDenied(self.run_hook(p["payload"]), "UNCLASSIFIED_MCP")

    def test_other_builtin_tools_are_outside_the_policy(self) -> None:
        for name in ("Read", "Glob", "Grep", "WebFetch"):
            with self.subTest(tool=name):
                self.assertAllowed(self.run_hook({"tool_name": name, "tool_input": {}}))


# --------------------------------------------------------------------------
# Malformed / structurally invalid input
# --------------------------------------------------------------------------


class TestInputValidation(HookCase):
    def test_invalid_inputs_deny_with_exit_2(self) -> None:
        cases = [
            ("empty", b"", "EMPTY_INPUT"),
            ("whitespace", b"  \n", "EMPTY_INPUT"),
            ("invalid utf8", b"\xff\xfe\x00", "INVALID_ENCODING"),
            ("utf8 bom", b"\xef\xbb\xbf" + b'{"tool_name":"Read","tool_input":{}}', "MALFORMED_JSON"),
            ("truncated json", b'{"tool_name": "Bash"', "MALFORMED_JSON"),
            ("deep nesting", b"[" * 200000, "MALFORMED_JSON"),
            ("null", b"null", "INVALID_STRUCTURE"),
            ("array", b"[]", "INVALID_STRUCTURE"),
            ("number", b"123", "INVALID_STRUCTURE"),
            ("string", b'"x"', "INVALID_STRUCTURE"),
            ("no tool_name", b'{"tool_input":{}}', "INVALID_STRUCTURE"),
            ("tool_name int", b'{"tool_name":5,"tool_input":{}}', "INVALID_STRUCTURE"),
            ("tool_name empty", b'{"tool_name":"  ","tool_input":{}}', "INVALID_STRUCTURE"),
            ("no tool_input", b'{"tool_name":"Read"}', "INVALID_STRUCTURE"),
            ("tool_input null", b'{"tool_name":"Read","tool_input":null}', "INVALID_STRUCTURE"),
            ("tool_input array", b'{"tool_name":"Read","tool_input":[]}', "INVALID_STRUCTURE"),
            ("bash command int", b'{"tool_name":"Bash","tool_input":{"command":5}}', "INVALID_TOOL_INPUT"),
            ("bash no command", b'{"tool_name":"Bash","tool_input":{}}', "INVALID_TOOL_INPUT"),
            ("write no path", b'{"tool_name":"Write","tool_input":{"content":"x"}}', "INVALID_TOOL_INPUT"),
            ("write path int", b'{"tool_name":"Write","tool_input":{"file_path":5}}', "INVALID_TOOL_INPUT"),
        ]
        for label, data, code in cases:
            with self.subTest(case=label):
                self.assertDenied(self.run_hook(data), code)

    def test_diagnostics_are_actionable(self) -> None:
        _, err = self.run_hook(b"not json")
        self.assertIn("pre_tool_guard: DENY", err)
        self.assertIn("expected one JSON object", err)

    def test_oversized_payload_is_denied(self) -> None:
        with self.assertRaises(guard.Deny) as ctx:
            guard.parse_payload(b" " * (guard.MAX_PAYLOAD_BYTES + 1))
        self.assertEqual(ctx.exception.code, "PAYLOAD_TOO_LARGE")

    def test_internal_error_fails_closed_with_exit_2(self) -> None:
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b'{"tool_name":"Read","tool_input":{}}')
        err = io.StringIO()
        with mock.patch.object(sys, "stdin", fake_stdin), \
             mock.patch.object(sys, "stderr", err), \
             mock.patch.object(guard, "decide", side_effect=RuntimeError("boom")):
            rc = guard.main()
        self.assertEqual(rc, 2)
        self.assertIn("[INTERNAL_ERROR]", err.getvalue())

    def test_unreadable_stdin_fails_closed(self) -> None:
        err = io.StringIO()
        with mock.patch.object(sys, "stdin", None), mock.patch.object(sys, "stderr", err):
            self.assertEqual(guard.main(), 2)
        self.assertIn("[INTERNAL_ERROR]", err.getvalue())


# --------------------------------------------------------------------------
# Marker validity (read-only check)
# --------------------------------------------------------------------------

PR = {"tool_name": "mcp__github__create_pull_request", "tool_input": {}}
PR_SCOPE = "github:create_pull_request"
DECISION_LOG = {"tool_name": "mcp__sfx-decisionlog-mcp__decisionlog_create_entry", "tool_input": {}}
DL_SCOPE = "tblX88U1VOwmK2fF5"


class TestMarker(HookCase):
    def test_valid_marker_allows(self) -> None:
        self.write_marker(marker_doc([PR_SCOPE]))
        self.assertAllowed(self.run_hook(PR))

    def test_wrong_scope_denied(self) -> None:
        self.write_marker(marker_doc(["github:write"]))
        self.assertDenied(self.run_hook(PR), "MARKER_SCOPE")

    def test_consumed_denied(self) -> None:
        self.write_marker(marker_doc([PR_SCOPE], consumed=True))
        self.assertDenied(self.run_hook(PR), "MARKER_CONSUMED")

    def test_expired_denied(self) -> None:
        self.write_marker(marker_doc([PR_SCOPE], ttl=60, issued=datetime.now(timezone.utc) - timedelta(hours=1)))
        self.assertDenied(self.run_hook(PR), "MARKER_EXPIRED")

    def test_future_dated_denied(self) -> None:
        self.write_marker(marker_doc([PR_SCOPE], issued=datetime.now(timezone.utc) + timedelta(days=30)))
        self.assertDenied(self.run_hook(PR), "MARKER_FUTURE_DATED")

    def test_tier1_never_satisfies_tier2(self) -> None:
        self.write_marker(marker_doc([DL_SCOPE], tier=1))
        self.assertDenied(self.run_hook(DECISION_LOG), "MARKER_TIER")
        self.write_marker(marker_doc([DL_SCOPE], tier=2))
        self.assertAllowed(self.run_hook(DECISION_LOG))

    def test_malformed_markers_deny_and_never_crash(self) -> None:
        good = marker_doc([PR_SCOPE])
        bad = {
            "tier as string": {**good, "tier": "2"},
            "tier bool": {**good, "tier": True},
            "tier out of range": {**good, "tier": 3},
            "scope as string": {**good, "scope": PR_SCOPE},
            "scope with non-string": {**good, "scope": [PR_SCOPE, 5]},
            "ttl negative": {**good, "ttl_seconds": -1},
            "ttl string": {**good, "ttl_seconds": "600"},
            "consumed non-bool": {**good, "consumed": "no"},
            "issued_at int": {**good, "issued_at": 5},
            "issued_at garbage": {**good, "issued_at": "yesterday"},
            "issued_at naive": {**good, "issued_at": "2026-11-13T00:00:00"},
            "decision_id empty": {**good, "decision_id": ""},
            "marker is a list": [good],
        }
        for label, doc in bad.items():
            with self.subTest(case=label):
                self.write_marker(doc)
                self.assertDenied(self.run_hook(PR), "MARKER_MALFORMED")

    def test_marker_not_json_and_marker_unreadable(self) -> None:
        self.write_marker("{not json")
        self.assertDenied(self.run_hook(PR), "MARKER_MALFORMED")
        self.marker.unlink()
        self.marker.mkdir()  # a directory where a file is expected
        self.assertDenied(self.run_hook(PR), "MARKER_UNREADABLE")


# --------------------------------------------------------------------------
# Airtable generic tools
# --------------------------------------------------------------------------


class TestAirtable(HookCase):
    def test_canon_base_write_needs_marker_for_its_table(self) -> None:
        p = {"tool_name": "mcp__Airtable__update_records_for_table",
             "tool_input": {"baseId": guard.CANON_BASE_ID, "tableId": "tblEZ6ctzSoTBsfCW"}}
        self.assertDenied(self.run_hook(p), "NO_MARKER")
        self.write_marker(marker_doc(["tblEZ6ctzSoTBsfCW"]))
        self.assertAllowed(self.run_hook(p))

    def test_decision_log_via_generic_tool_needs_tier2(self) -> None:
        p = {"tool_name": "mcp__Airtable__create_records_for_table",
             "tool_input": {"baseId": guard.CANON_BASE_ID, "tableId": DL_SCOPE}}
        self.write_marker(marker_doc([DL_SCOPE], tier=1))
        self.assertDenied(self.run_hook(p), "MARKER_TIER")

    def test_write_without_identifiable_base_is_denied(self) -> None:
        for inp in ({}, {"baseId": 5}, {"baseId": ""}, {"base_id": guard.CANON_BASE_ID}):
            with self.subTest(inp=inp):
                p = {"tool_name": "mcp__Airtable__create_records_for_table", "tool_input": inp}
                self.assertDenied(self.run_hook(p), "INVALID_TOOL_INPUT")

    def test_non_canon_base_write_is_outside_this_guardrail(self) -> None:
        p = {"tool_name": "mcp__Airtable__create_records_for_table",
             "tool_input": {"baseId": "appOTHERBASE00000", "tableId": "tblx"}}
        self.assertAllowed(self.run_hook(p))


# --------------------------------------------------------------------------
# Bash
# --------------------------------------------------------------------------


def bash(cmd: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


class TestBash(HookCase):
    def test_destructive_patterns_denied(self) -> None:
        for cmd in ("rm -rf /tmp/x", "sudo rm file", "chmod 777 f", "echo x > /etc/hosts", "psql -c 'DROP TABLE t'"):
            with self.subTest(cmd=cmd):
                self.assertDenied(self.run_hook(bash(cmd)), "DESTRUCTIVE_BASH")

    def test_supabase_ref_with_write_keyword_needs_marker(self) -> None:
        cmd = "psql postgres://x/mksmwqmphdkwwiyfesad -c 'DELETE FROM t'"
        self.assertDenied(self.run_hook(bash(cmd)), "NO_MARKER")
        self.write_marker(marker_doc(["supabase:mksmwqmphdkwwiyfesad"]))
        self.assertAllowed(self.run_hook(bash(cmd)))

    def test_marker_and_issuer_references_denied(self) -> None:
        cmds = [
            "cat .claude/t0-go.json",
            "cp /tmp/x .claude/t0-go.json",
            "T0_GO_MARKER_PATH=/tmp/m python3 -c pass",
            "python3 hooks/issue_t0_go.py --decision-id X --scope s",
            "./hooks/issue_t0_go.py --decision-id X --scope s",
            "ls && python3 /abs/hooks/issue_t0_go.py --scope s",
        ]
        for cmd in cmds:
            with self.subTest(cmd=cmd):
                self.assertDenied(self.run_hook(bash(cmd)), "AUTH_MATERIAL")

    def test_configured_marker_path_mention_denied(self) -> None:
        self.assertDenied(self.run_hook(bash(f"echo x > {self.marker}")), "AUTH_MATERIAL")

    def test_benign_commands_not_blocked(self) -> None:
        for cmd in ("ls -la", "git add hooks/issue_t0_go.py", "git log --oneline",
                    "python3 -m unittest discover -s tests"):
            with self.subTest(cmd=cmd):
                self.assertAllowed(self.run_hook(bash(cmd)))

    def test_http_write_to_non_canon_surface_not_this_guardrails_concern(self) -> None:
        self.assertAllowed(self.run_hook(bash("curl -X POST https://api.example.com/v1/x -d '{}'")))

    def test_http_read_of_canon_table_not_treated_as_write(self) -> None:
        cmd = "curl https://api.airtable.com/v0/appVftexD3KJRcdij/tbltw4Jy0LHWWz5DL"
        self.assertAllowed(self.run_hook(bash(cmd)))

    def test_canon_base_write_without_table_uses_base_scope(self) -> None:
        cmd = "curl -X POST https://api.airtable.com/v0/appVftexD3KJRcdij/Something -d x"
        self.assertDenied(self.run_hook(bash(cmd)), "NO_MARKER")
        self.write_marker(marker_doc([guard.CANON_BASE_ID]))
        self.assertAllowed(self.run_hook(bash(cmd)))


# --------------------------------------------------------------------------
# File-write tools
# --------------------------------------------------------------------------


class TestFileWrite(HookCase):
    def test_marker_targets_denied(self) -> None:
        targets = [".claude/t0-go.json", "/anywhere/else/T0-GO.JSON", str(self.marker)]
        for tool, field in (("Write", "file_path"), ("Edit", "file_path"), ("MultiEdit", "file_path"),
                            ("NotebookEdit", "notebook_path")):
            for t in targets:
                with self.subTest(tool=tool, target=t):
                    self.assertDenied(self.run_hook({"tool_name": tool, "tool_input": {field: t}}), "AUTH_MATERIAL")

    def test_symlink_to_marker_denied(self) -> None:
        self.write_marker({})
        link = self.tmp / "innocent.txt"
        link.symlink_to(self.marker)
        self.assertDenied(self.run_hook({"tool_name": "Write", "tool_input": {"file_path": str(link)}}), "AUTH_MATERIAL")

    def test_ordinary_files_allowed(self) -> None:
        self.assertAllowed(self.run_hook({"tool_name": "Edit", "tool_input": {"file_path": "src/app.py"}}))


# --------------------------------------------------------------------------
# Invocation from a changed working directory (probe L)
# --------------------------------------------------------------------------


class TestChangedWorkingDirectory(HookCase):
    def test_absolute_script_path_from_other_cwd_is_deterministic(self) -> None:
        elsewhere = self.tmp / "some" / "other" / "project"
        elsewhere.mkdir(parents=True)
        self.assertAllowed(self.run_hook(bash("ls"), cwd=elsewhere, script=HOOK))
        self.assertDenied(self.run_hook(PR, cwd=elsewhere, script=HOOK), "NO_MARKER")

    def test_default_marker_is_cwd_relative_so_other_cwd_finds_no_marker(self) -> None:
        # No T0_GO_MARKER_PATH: the default is ".claude/t0-go.json" under the cwd.
        proj = self.tmp / "proj"
        (proj / ".claude").mkdir(parents=True)
        (proj / ".claude" / "t0-go.json").write_text(json.dumps(marker_doc([PR_SCOPE])), encoding="utf-8")
        self.assertAllowed(self.run_hook(PR, cwd=proj, marker=False))
        other = self.tmp / "other"
        other.mkdir()
        self.assertDenied(self.run_hook(PR, cwd=other, marker=False), "NO_MARKER")

    def test_relative_script_path_from_wrong_cwd_exits_2_at_interpreter_level(self) -> None:
        # Documents why the settings example must use an absolute path: with a
        # relative path the interpreter cannot find the file and exits 2. That
        # fails closed, but by accident rather than by policy.
        proc = subprocess.run([sys.executable, "hooks/pre_tool_guard.py"], input=b"{}",
                              capture_output=True, cwd=str(self.tmp), timeout=30)
        self.assertEqual(proc.returncode, 2)


# --------------------------------------------------------------------------
# Settings example
# --------------------------------------------------------------------------


class TestSettingsExample(unittest.TestCase):
    def test_example_routes_every_policy_surface_through_an_absolute_hook_path(self) -> None:
        doc = json.loads(SETTINGS_EXAMPLE.read_text(encoding="utf-8"))
        entries = doc["hooks"]["PreToolUse"]
        matchers = {e["matcher"] for e in entries}
        self.assertEqual(matchers, {"Bash", "Write|Edit|MultiEdit|NotebookEdit", "mcp__.*"})
        for e in entries:
            for h in e["hooks"]:
                self.assertEqual(h["type"], "command")
                cmd = h["command"]
                self.assertIn("/pre_tool_guard.py", cmd)
                self.assertIn('"/', cmd, "hook path must be absolute (placeholder), not relative")
                self.assertNotIn(" hooks/pre_tool_guard.py", cmd)


# --------------------------------------------------------------------------
# Known gaps, recorded as expected failures so they stay visible
# --------------------------------------------------------------------------


class TestKnownUncoveredRoutes(HookCase):
    """Shell obfuscation defeats the string-based Bash checks. These are NOT
    claimed as covered; they are expected failures that become failures of
    the suite (unexpected success) the day someone closes the gap."""

    @unittest.expectedFailure
    def test_glob_obfuscated_marker_write_is_not_detected(self) -> None:
        self.assertDenied(self.run_hook(bash("echo '{}' > .claude/t0-g*.json")), "AUTH_MATERIAL")

    @unittest.expectedFailure
    def test_concatenated_marker_name_is_not_detected(self) -> None:
        self.assertDenied(self.run_hook(bash("python3 -c \"open('.claude/t0-'+'go.json','w').write('{}')\"")),
                          "AUTH_MATERIAL")


if __name__ == "__main__":
    unittest.main()
