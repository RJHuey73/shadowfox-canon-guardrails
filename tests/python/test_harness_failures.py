"""Security acceptance tests at the harness boundary: the hook is invoked the
way config/settings.json.example tells Claude Code to invoke it (a shell
command, JSON on stdin, decision by exit code), under conditions a real
harness can produce. Nothing here runs a privileged command, touches the
network, or uses a real marker: every command string is inspected by the
hook, never executed."""

import json
import os
import subprocess
import sys
import time

import pytest

from conftest import HOOK, REPO, valid_marker

BLOCK = 2
GATED = {"tool_name": "mcp__sfx-session-mcp__session_open", "tool_input": {}}
SESSION = "tblEZ6ctzSoTBsfCW"


def settings_commands():
    settings = json.loads((REPO / "config" / "settings.json.example").read_text())
    return {e["matcher"]: e["hooks"][0]["command"] for e in settings["hooks"]["PreToolUse"]}


def run_shell(command, stdin, env_extra, cwd=REPO):
    env = {k: v for k, v in os.environ.items() if k != "T0_GO_MARKER_PATH"}
    env.update(env_extra)
    # Claude Code runs a hook's "command" through a shell. python3 may not be
    # first on PATH in a test venv, so point it at this interpreter.
    command = command.replace("python3 ", f"{sys.executable} ", 1)
    return subprocess.run(command, shell=True, input=stdin, capture_output=True, cwd=cwd, env=env, timeout=30)


def test_every_configured_hook_command_blocks_a_gated_call_without_a_marker(tmp_path):
    marker = tmp_path / "absent.json"
    for matcher, command in settings_commands().items():
        payload = GATED if matcher != "Bash" else {
            "tool_name": "Bash", "tool_input": {"command": f"psql -c 'DELETE FROM x' {SESSION}"},
        }
        proc = run_shell(command, json.dumps(payload).encode(), {"T0_GO_MARKER_PATH": str(marker)})
        assert proc.returncode == BLOCK, (matcher, proc.stderr)


def test_default_marker_path_is_relative_to_the_session_cwd(tmp_path):
    # T0_GO_MARKER_PATH unset: the hook looks for .claude/t0-go.json in the
    # directory the harness runs it from, and blocks when it is not there.
    env = {k: v for k, v in os.environ.items() if k != "T0_GO_MARKER_PATH"}
    proc = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(GATED).encode(),
                          capture_output=True, cwd=tmp_path, env=env, timeout=30)
    assert proc.returncode == BLOCK
    assert b".claude/t0-go.json" in proc.stderr


@pytest.mark.parametrize("io_encoding", ["utf-8:strict", "utf-8:surrogateescape"])
def test_invalid_utf8_in_a_gated_command_blocks_under_either_decoding(tmp_path, io_encoding):
    # Strict decoding raises inside json.load (blocked by the hook's
    # top-level handler); surrogateescape decodes, and the write keyword +
    # protected table still gate it. Either way: block, never a crash.
    stdin = b'{"tool_name": "Bash", "tool_input": {"command": "DELETE FROM tblEZ6ctzSoTBsfCW \xff\xfe"}}'
    proc = run_shell(f"python3 {HOOK}", stdin,
                     {"T0_GO_MARKER_PATH": str(tmp_path / "m.json"), "PYTHONIOENCODING": io_encoding})
    assert proc.returncode == BLOCK, proc.stderr
    assert b"Traceback" not in proc.stderr


def test_marker_path_that_is_a_directory_blocks(tmp_path):
    marker = tmp_path / "t0-go.json"
    marker.mkdir()
    proc = run_shell(f"python3 {HOOK}", json.dumps(GATED).encode(), {"T0_GO_MARKER_PATH": str(marker)})
    assert proc.returncode == BLOCK and b"Traceback" not in proc.stderr


def test_marker_that_is_not_utf8_blocks(tmp_path):
    marker = tmp_path / "t0-go.json"
    marker.write_bytes(b"\xff\xfe\x00{")
    proc = run_shell(f"python3 {HOOK}", json.dumps(GATED).encode(), {"T0_GO_MARKER_PATH": str(marker)})
    assert proc.returncode == BLOCK and b"Traceback" not in proc.stderr


def test_large_payload_is_decided_well_inside_the_harness_timeout(tmp_path):
    # Claude Code kills a hook that exceeds its timeout and lets the call
    # through, so the decision must not be slow on large input.
    payload = {"tool_name": "Bash", "tool_input": {"command": "echo " + "a" * 2_000_000 + f" DELETE {SESSION}"}}
    start = time.monotonic()
    proc = run_shell(f"python3 {HOOK}", json.dumps(payload).encode(), {"T0_GO_MARKER_PATH": str(tmp_path / "m.json")})
    assert proc.returncode == BLOCK
    assert time.monotonic() - start < 10


def test_valid_marker_through_the_configured_command_allows_and_does_not_consume(tmp_path):
    marker = tmp_path / "t0-go.json"
    marker.write_text(json.dumps(valid_marker([SESSION])))
    before = marker.read_text()
    command = settings_commands()["mcp__sfx-session-mcp__(session_open|session_close)"]
    proc = run_shell(command, json.dumps(GATED).encode(), {"T0_GO_MARKER_PATH": str(marker)})
    assert proc.returncode == 0, proc.stderr
    assert marker.read_text() == before  # the MCP server, not the hook, consumes
