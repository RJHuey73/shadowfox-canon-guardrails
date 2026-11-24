#!/usr/bin/env python3
"""Offline proof for github_transition_guard.py. Runs the hook as Claude Code
does (JSON on stdin) and checks each decision. No network, no GitHub calls.

Usage: python3 -I tests/test_github_transition_guard.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("GUARD_HOOK") or os.path.join(HERE, "..", ".claude", "hooks", "github_transition_guard.py")
R = "repos/RJHuey73/tridecagon-agents"


def make_repo(branch: str, origin: str | None = None, origin_head: str | None = None) -> str:
    d = tempfile.mkdtemp(prefix=f"guard-{branch.replace('/', '-')}-")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    cmds = [["init", "-q", "-b", branch], ["commit", "-q", "--allow-empty", "-m", "x"]]
    if origin:
        cmds.append(["remote", "add", "origin", origin])
    if origin_head:
        cmds.append(["symbolic-ref", "refs/remotes/origin/HEAD", f"refs/remotes/origin/{origin_head}"])
    for cmd in cmds:
        subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t", *cmd],
                       check=True, env=env)
    return d


def decide(payload: dict) -> str:
    out = subprocess.run([sys.executable, "-I", HOOK], input=json.dumps(payload),
                         capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    if not out.stdout.strip():
        return "allow"
    return json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"]


def bash(cmd: str, cwd: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}


def mcp(name: str, args: dict, cwd: str) -> dict:
    return {"tool_name": name, "tool_input": args, "cwd": cwd}


def main() -> int:
    on_main = make_repo("main")
    on_feature = make_repo("claude/universal-agent-contract-tlz938")
    F = on_feature
    # A clone whose origin is RJHuey73/smse-engine (proxy-style URL, as in cloud
    # sessions), and one whose origin default branch is `develop`.
    S = make_repo("claude/x", origin="http://local_proxy@127.0.0.1:9/git/RJHuey73/smse-engine")
    D = make_repo("claude/x", origin="git@github.com:RJHuey73/maxun.git", origin_head="develop")
    # Origin RJHuey73/tridecagon-agents, for same-repository MCP write cases.
    O = make_repo("claude/x", origin="https://github.com/RJHuey73/tridecagon-agents.git")
    ID = {"owner": "RJHuey73", "repo": "tridecagon-agents"}
    py_merge = "import os; os.system('gh pr merge 5 --squash')"
    py_list = "import subprocess; subprocess.run(['gh', 'pr', 'merge', '5'])"
    py_var = "import subprocess as s; c = 'gh pr merge 5'; s.run(c, shell=True)"
    cases = [
        # ---- deny: gaps found in the 2026-11-22 review (each allowed before the fix)
        ("deny", mcp("mcp__github__create_or_update_file", {"branch": "refs/heads/main", "path": "x"}, F)),
        ("deny", mcp("mcp__github__push_files", {"branch": "refs/heads/master", "files": []}, F)),
        ("deny", bash(f"gh api -X PUT {R}/contents/x.md -f message=m -f content=eA== -f branch=refs/heads/main", F)),
        ("deny", mcp("mcp__github__push_files",
                     {"owner": "RJHuey73", "repo": "maxun", "branch": "develop", "files": []}, S)),
        ("deny", mcp("mcp__github__create_or_update_file",
                     {"owner": "RJHuey73", "repo": "other-repo", "branch": "claude/x", "path": "x"}, F)),
        ("deny", bash(f'python3 -c "{py_merge}"', F)),
        ("deny", bash(f'python3 -I -c "{py_list}"', F)),
        ("deny", bash(f'python3 -c "{py_var}"', F)),
        ("deny", bash("python3 -c 'import os; os.system(\"gh pr merge 5\"'", F)),
        # ---- non-regression for the same fixes
        ("deny", mcp("mcp__github__push_files",
                     {"owner": "RJHuey73", "repo": "maxun", "branch": "develop", "files": []}, D)),
        ("allow", mcp("mcp__github__push_files",
                      {"owner": "rjhuey73", "repo": "SMSE-engine", "branch": "claude/x", "files": []}, S)),
        ("allow", mcp("mcp__github__create_or_update_file",
                      {"owner": "RJHuey73", "repo": "maxun", "branch": "claude/x", "path": "x"}, D)),
        ("allow", bash("python3 -c \"print('gh pr merge 5')\"", F)),
        ("allow", bash("python3 -c \"import subprocess; subprocess.run(['git', 'status'])\"", F)),
        ("allow", bash("python3 -c 'import json, sys; print(json.load(sys.stdin))'", F)),
        # ---- R1-R4 regression cases (corrective review 2026-11-23). MCP
        # payloads are SYNTHETIC: names and argument shapes are not taken from
        # a verified connector schema.
        # R1: branch and ref forms normalise before the protected-branch check
        ("deny", mcp("mcp__GitHub__create_or_update_file", {**ID, "branch": "refs/heads/main", "path": "x"}, O)),
        ("deny", mcp("mcp__GitHub__create_file", {**ID, "branch": "heads/main", "path": "x"}, O)),
        ("deny", mcp("mcp__GitHub__update_file", {**ID, "branch": " main ", "path": "x"}, O)),
        ("deny", mcp("mcp__GitHub__create_commit", {**ID, "branch": "refs/heads/master"}, O)),
        ("deny", mcp("mcp__GitHub__create_file", {**ID, "branch": ["main"], "path": "x"}, O)),
        ("deny", mcp("mcp__GitHub__create_file", {**ID, "branch": "refs/tags/v1", "path": "x"}, O)),
        ("allow", mcp("mcp__GitHub__create_file", {**ID, "branch": "refs/heads/claude/x", "path": "x"}, O)),
        ("deny", bash(f"gh api -X PUT {R}/contents/x.md -f message=m -f content=eA== -f branch=heads/main", O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "heads/main", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "main", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__create_ref", {**ID, "ref": "refs/heads/main", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__create_branch", {**ID, "branch": "refs/heads/main"}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "tags/v1", "sha": "a"}, O)),
        # R2: only named tools are recognised; look-alike names ask
        ("ask", mcp("mcp__GitHub__list_and_delete_workflow_runs", {}, F)),
        ("ask", mcp("mcp__GitHub__search_and_replace_files", {}, F)),
        ("ask", mcp("mcp__GitHub__fetch_and_merge_upstream", {}, F)),
        ("ask", mcp("mcp__GitHub__repo_secret_read", {}, F)),
        ("ask", mcp("mcp__GitHub__comment_and_close_issue", {}, F)),
        ("ask", mcp("mcp__GitHub__update_issue_comment", {"body": "x"}, F)),
        ("ask", mcp("mcp__GitHub__dismiss_pull_request_review", {}, F)),
        ("ask", mcp("mcp__GitHub__rerun_and_deploy", {}, F)),
        ("ask", mcp("mcp__GitHub__update_pull_request", {"pullNumber": 1, "draft": False}, F)),
        # Expectation changed deny -> ask: review_event is not add_review_to_pr's
        # mapped event field (action), so the operation is unresolved.
        ("ask", mcp("mcp__GitHub__add_review_to_pr", {"review_event": "APPROVE"}, F)),
        ("deny", mcp("mcp__GitHub__pull_request_review_write", {"method": "create", "event": "approve"}, F)),
        ("allow", mcp("mcp__GitHub__pull_request_review_write", {"method": "create", "event": "COMMENT", "body": "Approved"}, F)),
        # RV: review tools classified by operation; pull_request_review_write by method
        ("deny", mcp("mcp__GitHub__pull_request_review_write", {"method": "delete_pending"}, F)),
        ("deny", mcp("mcp__GitHub__pull_request_review_write", {"method": "submit_pending", "event": "APPROVE"}, F)),
        ("deny", mcp("mcp__GitHub__pull_request_review_write", {"method": "create", "event": "APPROVE"}, F)),
        ("allow", mcp("mcp__GitHub__pull_request_review_write", {"method": "create"}, F)),
        ("allow", mcp("mcp__GitHub__pull_request_review_write", {"method": "create", "event": "REQUEST_CHANGES"}, F)),
        ("allow", mcp("mcp__GitHub__pull_request_review_write", {"method": "submit_pending", "event": "COMMENT"}, F)),
        ("ask", mcp("mcp__GitHub__pull_request_review_write", {"method": "submit_pending"}, F)),
        ("ask", mcp("mcp__GitHub__pull_request_review_write", {"event": "COMMENT"}, F)),
        ("ask", mcp("mcp__GitHub__pull_request_review_write", {"method": "approve_all", "event": "COMMENT"}, F)),
        ("ask", mcp("mcp__GitHub__pull_request_review_write", {"method": ["create"], "event": "COMMENT"}, F)),
        ("ask", mcp("mcp__GitHub__pull_request_review_write", {"method": "create", "event": "LGTM"}, F)),
        ("deny", mcp("mcp__GitHub__delete_pending_pull_request_review", {}, F)),
        ("deny", mcp("mcp__GitHub__submit_pending_pull_request_review", {"event": "APPROVE"}, F)),
        ("ask", mcp("mcp__GitHub__create_pull_request_review", {}, F)),
        ("allow", mcp("mcp__GitHub__create_pending_pull_request_review", {}, F)),
        ("allow", mcp("mcp__GitHub__request_copilot_review", {}, F)),
        ("ask", mcp("mcp__GitHub__add_review_to_pr", {}, F)),
        ("deny", mcp("mcp__GitHub__approve_pull_request_review", {"event": "APPROVE"}, F)),
        # MD: approval is read only from the mapped event field, not from metadata
        ("allow", mcp("mcp__GitHub__pull_request_review_write",
                      {"method": "create", "event": "COMMENT", "label": "APPROVED"}, F)),
        ("allow", mcp("mcp__GitHub__pull_request_review_write",
                      {"method": "create", "event": "COMMENT", "metadata": {"status": "APPROVED"}}, F)),
        ("allow", mcp("mcp__GitHub__add_review_to_pr", {"action": "COMMENT", "state": "APPROVED"}, F)),
        ("ask", mcp("mcp__GitHub__dismiss_pull_request_review", {"previous_state": "APPROVED"}, F)),
        ("allow", mcp("mcp__GitHub__list_pull_requests", {}, F)),
        ("allow", mcp("mcp__GitHub__add_issue_comment", {"body": "thanks"}, F)),
        ("allow", mcp("mcp__GitHub__rerun_failed_jobs", {"run_id": 1}, F)),
        ("allow", mcp("mcp__GitHub__update_pull_request", {"pullNumber": 1, "draft": True}, F)),
        # R3: target repository for MCP file and ref writes
        ("allow", mcp("mcp__GitHub__create_file",
                      {"owner": "rjhuey73", "repo": "Tridecagon-Agents", "branch": "claude/x", "path": "x"}, O)),
        ("deny", mcp("mcp__GitHub__create_file", {"owner": "RJHuey73", "repo": "other", "branch": "claude/x", "path": "x"}, O)),
        ("deny", mcp("mcp__GitHub__update_file", {"owner": "RJHuey73", "branch": "claude/x", "path": "x"}, O)),
        ("deny", mcp("mcp__GitHub__create_commit", {"repo": "tridecagon-agents", "branch": "claude/x"}, O)),
        ("deny", mcp("mcp__GitHub__push_files", {"owner": 123, "repo": "tridecagon-agents", "branch": "claude/x", "files": []}, O)),
        ("deny", mcp("mcp__GitHub__create_file", {**ID, "branch": "claude/x", "path": "x"}, F)),
        ("deny", mcp("mcp__GitHub__update_ref", {"owner": "RJHuey73", "repo": "other", "ref": "refs/heads/claude/x", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__create_file", {"branch": "main", "path": "x"}, O)),
        # FU1: every present ref/branch field is checked; a conflict does not let one win
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "branch": "main", "sha": "a"}, O)),
        ("ask", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "branch": "claude/y", "sha": "a"}, O)),
        ("allow", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "branch": "claude/x", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "", "branch": "claude/x", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": False, "branch": "claude/x", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": None, "branch": "claude/x", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "", "branch": "main", "sha": "a"}, O)),
        ("deny", mcp("mcp__GitHub__create_branch", {**ID, "branch": "claude/x", "ref": "main"}, O)),
        ("deny", mcp("mcp__GitHub__create_ref", {**ID, "ref": "refs/heads/claude/x", "branch": "refs/tags/v1", "sha": "a"}, O)),
        # R4: forced MCP ref updates deny; ambiguous force values ask
        ("allow", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "sha": "a", "force": False}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "sha": "a", "force": True}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "sha": "a", "force": "true"}, O)),
        ("ask", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "sha": "a", "force": "false"}, O)),
        ("ask", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "sha": "a", "force": 1}, O)),
        ("ask", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "sha": "a", "force": None}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/main", "sha": "a", "force": False}, O)),
        ("deny", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/tags/v1", "sha": "a", "force": False}, O)),
        # ---- deny: merge / auto-merge / close / approve
        ("deny", bash("gh pr merge 97 --squash", F)),
        ("deny", bash(f"gh api -X PUT {R}/pulls/97/merge -f merge_method=squash", F)),
        ("deny", bash(f"gh api {R}/pulls/97/merge -X PUT", F)),
        ("deny", bash(f"gh api --method=PUT /{R}/pulls/9/merge", F)),
        ("deny", bash(f"gh api -XPUT {R}/pulls/9/merge", F)),
        ("deny", bash(f"gh api -X PUT {R}/pulls/97/ccr/auto_merge -f merge_method=squash", F)),
        ("deny", bash(f"gh api -X PATCH {R}/pulls/79 -f state=closed", F)),
        ("deny", bash(f"gh api {R}/issues/12 -X PATCH -F state=closed", F)),
        ("deny", bash(f"gh api {R}/pulls/5/reviews -f event=APPROVE", F)),
        ("deny", bash("gh pr review 5 --approve", F)),
        ("deny", bash("gh pr close 79", F)),
        ("deny", bash("gh issue close 3", F)),
        ("deny", bash("cd /tmp && GH_TOKEN=x gh pr merge 1", F)),
        ("deny", bash('bash -c "gh pr merge 1"', F)),
        ("deny", bash("sudo bash -lc 'git push origin main'", F)),
        ("deny", bash("echo start\ngh pr merge 2", F)),
        ("deny", bash("gh api graphql -f query='mutation { mergePullRequest(input:{pullRequestId:\"x\"}) { clientMutationId } }'", F)),
        ("deny", bash(f"gh api {R}/issues/79/comments -f body='@dependabot ignore this major version'", F)),
        ("deny", bash("curl -X PUT https://api.github.com/repos/o/r/pulls/1/merge -H 'Authorization: token x'", F)),
        # ---- deny: pushes
        ("deny", bash("git push origin main", F)),
        ("deny", bash("git push origin HEAD:main", F)),
        ("deny", bash("git push origin feature:refs/heads/master", F)),
        ("deny", bash("git push origin +claude/x", F)),
        ("deny", bash("git push --force origin claude/x", F)),
        ("deny", bash("git push -uf origin claude/x", F)),
        ("deny", bash("git push origin --delete old", F)),
        ("deny", bash("git push origin :old", F)),
        ("deny", bash("git push --mirror", F)),
        ("deny", bash("git push --all origin", F)),
        ("deny", bash(f"git -C {on_main} push", F)),
        ("deny", bash("git push", on_main)),
        ("deny", bash("git push origin HEAD", on_main)),
        ("deny", bash("git status\ngit push origin main", F)),
        ("deny", bash(f"cd {on_main} && git push", F)),
        # ---- deny: refs, contents, settings, secrets, releases
        ("deny", bash(f"gh api -X DELETE {R}/git/refs/heads/claude/x", F)),
        ("deny", bash(f"gh api -X PATCH {R}/git/refs/heads/main -F force=true -f sha=abc", F)),
        ("deny", bash(f"gh api -X PUT {R}/contents/README.md -f message=m -f content=eA==", F)),
        ("deny", bash(f"gh api -X PATCH {R} -f visibility=public", F)),
        ("deny", bash(f"gh api -X DELETE {R}", F)),
        ("deny", bash(f"gh api -X PUT {R}/branches/main/protection --input p.json", F)),
        ("deny", bash(f"gh api -X PUT {R}/actions/secrets/FOO -f encrypted_value=x", F)),
        ("deny", bash(f"gh api -X POST {R}/releases -f tag_name=v1", F)),
        ("deny", bash(f"gh api -X PUT {R}/collaborators/someone", F)),
        ("deny", bash("gh secret set FOO --body x", F)),
        ("deny", bash("gh repo edit --visibility public", F)),
        # ---- deny: guard tamper
        ("deny", bash("echo '{}' > .claude/settings.json", F)),
        ("deny", bash("sed -i 's/deny/allow/' /home/user/x/.claude/settings.json", F)),
        ("deny", bash("rm .claude/hooks/github_transition_guard.py", F)),
        ("deny", bash("cp /tmp/x.json /etc/claude-code/managed-settings.json", F)),
        # ---- deny: MCP
        ("deny", mcp("mcp__github__merge_pull_request", {"pullNumber": 1}, F)),
        ("deny", mcp("mcp__github__update_pull_request", {"state": "closed"}, F)),
        ("deny", mcp("mcp__github__create_pull_request_review", {"event": "APPROVE"}, F)),
        ("deny", mcp("mcp__github__push_files", {"branch": "main", "files": []}, F)),
        ("deny", mcp("mcp__GitHub__delete_file", {"path": "x"}, F)),
        # ---- deny: MCP tool names outside the original list (relay 2026-11-23)
        ("deny", mcp("mcp__GitHub__create_file", {"branch": "main", "path": "x"}, F)),
        ("deny", mcp("mcp__GitHub__update_file", {"branch": "main", "path": "x"}, F)),
        ("deny", mcp("mcp__GitHub__create_commit", {"path": "x"}, F)),
        ("deny", mcp("mcp__GitHub__update_ref", {"ref": "refs/heads/main", "sha": "abc"}, F)),
        ("deny", mcp("mcp__GitHub__create_branch", {"branch": "main"}, F)),
        ("deny", mcp("mcp__GitHub__add_review_to_pr", {"action": "APPROVE"}, F)),
        ("deny", mcp("mcp__github__add_issue_comment", {"body": "@dependabot merge"}, F)),
        # ---- ask: unclassified GitHub MCP tool (synthetic name)
        ("ask", mcp("mcp__GitHub__set_workflow_permissions", {"enabled": False}, F)),
        # ---- ask
        ("ask", bash(f"gh api -X POST {R}/pulls/97/ccr/ready_for_review", F)),
        ("ask", bash("gh pr ready 97", F)),
        ("ask", bash("git push --force-with-lease origin claude/x", F)),
        ("ask", bash("git push origin refs/tags/v1.0.0", F)),
        ("ask", bash("gh workflow run release.yml", F)),
        ("ask", bash(f"gh api -X POST {R}/actions/workflows/x.yml/dispatches -f ref=main", F)),
        ("ask", bash(f"gh api -X PATCH {R}/pulls/5 --input body.json", F)),
        ("ask", bash("curl -X PATCH https://api.github.com/repos/o/r/issues/1 -d '{}'", F)),
        ("ask", bash(f"gh api -X PATCH {R}/dependabot/alerts/4 -f state=dismissed", F)),
        ("ask", mcp("mcp__github__create_repository", {"name": "x"}, F)),
        # ---- allow: normal work
        ("allow", bash("git push -u origin claude/universal-agent-contract-tlz938", F)),
        ("allow", bash("git push -u origin HEAD:claude/x", F)),
        ("allow", bash("git push", F)),
        ("allow", bash("git push origin HEAD", F)),
        ("allow", bash(f"gh api {R}/pulls/97 --jq '{{merged:.merged_at}}'", F)),
        ("allow", bash(f"gh api '{R}/pulls?state=closed&per_page=5'", F)),
        ("allow", bash(f"gh api {R}/pulls/97/merge", F)),
        ("allow", bash(f"gh api -X POST {R}/pulls -f title=t -f head=claude/x -f base=main -F draft=true", F)),
        ("allow", bash(f"gh api {R}/issues/97/comments -f body='@dependabot rebase'", F)),
        ("allow", bash(f"gh api -X POST {R}/actions/runs/123/rerun-failed-jobs", F)),
        ("allow", bash(f"gh api -X DELETE {R}/pulls/97/ccr/auto_merge", F)),
        ("allow", bash(f"gh api -X PUT {R}/contents/x.md -f message=m -f content=eA== -f branch=claude/x", F)),
        ("allow", bash(f"gh api -X PATCH {R}/pulls/5 -f title=new", F)),
        ("allow", bash(f"gh api {R}/pulls/5/reviews -f event=COMMENT -f body=ok", F)),
        ("allow", bash("gh pr review 5 --comment -b ok", F)),
        ("allow", bash('git commit -m "docs: never git push origin main"', F)),
        ("allow", bash("cat .claude/settings.json", F)),
        ("allow", bash('grep -rn "gh pr merge" docs', F)),
        ("allow", bash("git status && git log --oneline -3", F)),
        ("allow", mcp("mcp__github__create_pull_request", {"draft": True}, F)),
        # Expectation changed allow -> ask (R3): a write that omits owner/repo
        # no longer assumes this repository. Same-repository variants follow.
        ("ask", mcp("mcp__github__push_files", {"branch": "claude/x", "files": []}, F)),
        ("ask", mcp("mcp__GitHub__create_file", {"branch": "claude/x", "path": "x"}, F)),
        ("ask", mcp("mcp__GitHub__update_ref", {"ref": "refs/heads/claude/x", "sha": "abc"}, F)),
        ("ask", mcp("mcp__GitHub__create_branch", {"branch": "claude/x"}, F)),
        ("allow", mcp("mcp__github__push_files", {**ID, "branch": "claude/x", "files": []}, O)),
        ("allow", mcp("mcp__GitHub__create_file", {**ID, "branch": "claude/x", "path": "x"}, O)),
        ("allow", mcp("mcp__GitHub__update_ref", {**ID, "ref": "refs/heads/claude/x", "sha": "abc"}, O)),
        ("allow", mcp("mcp__GitHub__create_branch", {**ID, "branch": "claude/x"}, O)),
        ("allow", mcp("mcp__GitHub__add_review_to_pr", {"action": "COMMENT", "body": "ok"}, F)),
        ("allow", mcp("mcp__github__add_issue_comment", {"body": "@dependabot rebase"}, F)),
        ("allow", mcp("mcp__github__get_file_contents", {"path": "x"}, F)),
        ("allow", mcp("mcp__github__pull_request_read", {"method": "get"}, F)),
        ("allow", mcp("mcp__GitHub__rerun_workflow_job", {"job_id": 1}, F)),
        ("allow", mcp("mcp__Airtable__list_bases", {}, F)),
        ("allow", {"tool_name": "Read", "tool_input": {"file_path": "/x"}, "cwd": F}),
    ]
    failed = 0
    for expected, payload in cases:
        got = decide(payload)
        label = payload["tool_input"].get("command") or payload["tool_name"]
        if got != expected:
            failed += 1
            print(f"  FAIL expected={expected} got={got}: {label!r}")
    # Malformed hook input must fail closed.
    out = subprocess.run([sys.executable, "-I", HOOK], input="not json",
                         capture_output=True, text=True, timeout=20)
    if json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"] != "deny":
        failed += 1
        print("  FAIL malformed input did not deny")
    total = len(cases) + 1
    print(f"{total - failed} passed, {failed} failed ({total} cases)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
