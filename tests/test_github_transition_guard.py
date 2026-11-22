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
        ("allow", mcp("mcp__github__push_files", {"branch": "claude/x", "files": []}, F)),
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
