"""github_transition_guard.py: Claude Code PreToolUse hook. DRAFT, T1, ratified: false.

Stops consequential GitHub transitions from an agent session: merge, close,
approve, auto-merge, pushes to protected branches, force pushes, ref and
branch deletion, default-branch content writes, repository settings, access
control, secrets, releases, and edits to this guard's own configuration.
Draft-to-ready, reopen, workflow dispatch, force-with-lease and tag pushes
ask instead of deny.

UAC mapping: capability is not authority (UAC-K-002). An agent session may
hold a credential that can merge; the merge still belongs to T0, done
outside the session.

Enforcement class: client. This runs inside the agent's own harness. It
stops the model's tool calls, including reordered flags, compound commands,
`bash -c` strings, inline `python -c` code that spawns a process, and raw
HTTP calls it can parse. It does not stop a process that edits this file, a
tool outside Claude Code, or a write hidden where it cannot read: a script
file, a heredoc, inline code for other interpreters, or a command string
that is computed rather than written out. Platform controls (branch
protection, an agent identity without merge rights) are the durable fix.

MCP file and ref writes aimed at a repository other than this session's
origin, or naming it incompletely, are denied: that repository's protected
branches cannot be known here. Writes that omit the repository ask. Forced
MCP ref updates are denied.

Output: a PreToolUse permissionDecision of deny or ask, or nothing (allow).
Any internal error denies (fail closed). A GitHub MCP tool the guard does not
recognise asks; it is never silently allowed.

Config: SFX_PROTECTED_BRANCHES, a comma list (default "main,master"). The
repository's origin default branch is added when it can be read.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import subprocess
import sys

DENY, ASK = "deny", "ask"
RANK = {DENY: 2, ASK: 1}
MAX_DEPTH = 3
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
OPERATOR_CHARS = set("();<>|&")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
REPO = r"^repos/[^/]+/[^/]+"

_branch_cache: dict[str, set[str]] = {}


# ---------------------------------------------------------------- helpers


def finding(decision: str, label: str, detail: str = "") -> tuple[str, str]:
    reason = (
        f"github_transition_guard: {label}"
        + (f" ({detail})" if detail else "")
        + ". Consequential GitHub transition: T0 performs it outside the agent "
        "session (UAC-K-002, capability is not authority)."
    )
    return decision, reason


def strongest(findings):
    best = None
    for f in findings:
        if f and (best is None or RANK[f[0]] > RANK[best[0]]):
            best = f
    return best


def run_git(repo_dir: str, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", repo_dir, *args],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = out.stdout.strip()
    return value if out.returncode == 0 and value else None


def protected_branches(repo_dir: str) -> set[str]:
    if repo_dir in _branch_cache:
        return _branch_cache[repo_dir]
    env = os.environ.get("SFX_PROTECTED_BRANCHES", "main,master")
    branches = {b.strip() for b in env.split(",") if b.strip()}
    default = run_git(
        repo_dir,
        "symbolic-ref",
        "--short",
        "-q",
        "refs/remotes/origin/HEAD",
    )
    if default:
        branches.add(default.split("/", 1)[1] if "/" in default else default)
    _branch_cache[repo_dir] = branches
    return branches


def current_branch(repo_dir: str) -> str | None:
    return run_git(repo_dir, "symbolic-ref", "--short", "-q", "HEAD")


def ref_target(value) -> tuple[str, str] | None:
    """(kind, name) for a branch or ref value, kind "branch" or "tag".

    Accepts name, heads/name, refs/heads/name, tags/name and refs/tags/name.
    None when the value is not a string or names nothing, so a caller can
    treat it as unresolved rather than as a safe branch.
    """
    if not isinstance(value, str):
        return None
    v = value.strip().removeprefix("refs/")
    if v.startswith("tags/"):
        kind, name = "tag", v[len("tags/"):]
    else:
        kind, name = "branch", v.removeprefix("heads/")
    return (kind, name) if name else None


def branch_name(value) -> str:
    """Bare branch name, or "" when the value is not a usable branch.
    GitHub accepts refs/heads/<name> wherever it takes a branch."""
    target = ref_target(value)
    return target[1] if target and target[0] == "branch" else ""


REMOTE_SLUG = re.compile(r"[:/](?P<owner>[^/:]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")


def origin_slug(repo_dir: str) -> str | None:
    """owner/repo of this checkout's origin, lowercased, or None."""
    m = REMOTE_SLUG.search(run_git(repo_dir, "remote", "get-url", "origin") or "")
    return f"{m['owner']}/{m['repo']}".lower() if m else None


def tokenize(command: str) -> list[str] | None:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return None


def is_operator(token: str) -> bool:
    return bool(token) and all(c in OPERATOR_CHARS for c in token)


def command_args(tokens: list[str], start: int) -> list[str]:
    """Arguments of the command at tokens[start], up to the next operator."""
    args = []
    for tok in tokens[start + 1 :]:
        if is_operator(tok):
            break
        args.append(tok)
    return args


# ------------------------------------------------------------------ gh api

GH_API_VALUE_FLAGS = {
    "-X",
    "--method",
    "-f",
    "--raw-field",
    "-F",
    "--field",
    "-H",
    "--header",
    "--input",
    "-q",
    "--jq",
    "-t",
    "--template",
    "--hostname",
    "--cache",
    "-p",
    "--preview",
}
LONG_EQ = re.compile(
    r"^(--method|--field|--raw-field|--input|--jq|--header|--template|"
    r"--hostname|--cache|--preview)=(.*)$"
)
SHORT_ATTACHED = re.compile(r"^-([XfFHqtp])(.+)$")


def add_field(fields: dict[str, str], raw: str) -> None:
    key, _, value = raw.partition("=")
    fields[key.strip().lower()] = value


def normalize_path(path: str) -> str:
    path = re.sub(r"^https?://[^/]+/", "", path)
    path = path.lstrip("/")
    path = re.sub(r"^api/v3/", "", path)
    return path.split("?", 1)[0].rstrip("/")


def parse_gh_api(args: list[str]):
    method, fields, has_input, positional = None, {}, False, []
    i = 0
    while i < len(args):
        a = args[i]
        if a in GH_API_VALUE_FLAGS:
            value = args[i + 1] if i + 1 < len(args) else ""
            if a in ("-X", "--method"):
                method = value.upper()
            elif a in ("-f", "-F", "--field", "--raw-field"):
                add_field(fields, value)
            elif a == "--input":
                has_input = True
            i += 2
            continue
        m = LONG_EQ.match(a)
        if m:
            key, value = m.groups()
            if key == "--method":
                method = value.upper()
            elif key in ("--field", "--raw-field"):
                add_field(fields, value)
            elif key == "--input":
                has_input = True
            i += 1
            continue
        m = SHORT_ATTACHED.match(a)
        if m:
            key, value = m.groups()
            if key == "X":
                method = value.upper()
            elif key in "fF":
                add_field(fields, value)
            i += 1
            continue
        if not a.startswith("-"):
            positional.append(a)
        i += 1
    if not positional:
        return None
    if method is None:
        method = "POST" if (fields or has_input) else "GET"
    return method, normalize_path(positional[0]), fields, has_input


DEPENDABOT_CMD = re.compile(
    r"@dependabot\s+(merge|squash and merge|close|ignore|cancel merge)\b",
    re.IGNORECASE,
)
GRAPHQL_DENY = re.compile(
    r"\b(mergePullRequest|enablePullRequestAutoMerge|closePullRequest|closeIssue|"
    r"deleteIssue|transferIssue|deleteRef|updateRef|updateRefs|mergeBranch|"
    r"deleteRepository|updateRepository|archiveRepository|"
    r"(create|update|delete)BranchProtectionRule|"
    r"(create|update|delete)RepositoryRuleset)\b"
)
GRAPHQL_ASK = re.compile(
    r"\b(markPullRequestReadyForReview|reopenPullRequest|reopenIssue|createRef|"
    r"createRepository|createCommitOnBranch)\b"
)
GRAPHQL_REVIEW = re.compile(r"\b(submitPullRequestReview|addPullRequestReview)\b")


def check_graphql(fields, has_input):
    query = fields.get("query", "")
    if not query:
        if has_input:
            return finding(ASK, "GRAPHQL_OPAQUE_BODY", "query not readable")
        return None
    if "APPROVE" in query and GRAPHQL_REVIEW.search(query):
        return finding(DENY, "APPROVE_PR", "graphql")
    m = GRAPHQL_DENY.search(query)
    if m:
        return finding(DENY, "GRAPHQL_MUTATION", m.group(0))
    m = GRAPHQL_ASK.search(query)
    if m:
        return finding(ASK, "GRAPHQL_MUTATION", m.group(0))
    return None


def check_gh_api(args: list[str], repo_dir: str):
    parsed = parse_gh_api(args)
    if parsed is None:
        return None
    method, path, fields, has_input = parsed
    if path == "graphql":
        return check_graphql(fields, has_input)
    write = method in WRITE_METHODS
    protected = protected_branches(repo_dir)

    def at(pattern: str):
        return re.match(REPO + pattern + "$", path)

    if method == "PUT" and at(r"/pulls/\d+/merge"):
        return finding(DENY, "MERGE_PR", path)
    if method in ("PUT", "POST", "PATCH") and at(r"/pulls/\d+/ccr/auto_merge"):
        return finding(DENY, "ENABLE_AUTO_MERGE", path)
    if method == "POST" and at(r"/merges"):
        return finding(DENY, "MERGE_BRANCH", path)
    if method == "PATCH" and at(r"/(pulls|issues)/\d+"):
        state = fields.get("state", "").lower()
        if state == "closed":
            return finding(DENY, "CLOSE_PR_OR_ISSUE", path)
        if state == "open":
            return finding(ASK, "REOPEN_PR_OR_ISSUE", path)
        if has_input:
            return finding(ASK, "UPDATE_PR_OR_ISSUE", "body not readable")
        return None
    if method == "POST" and at(r"/pulls/\d+/reviews(/\d+/events)?"):
        if fields.get("event", "").upper() == "APPROVE":
            return finding(DENY, "APPROVE_PR", path)
        if has_input:
            return finding(ASK, "SUBMIT_REVIEW", "body not readable")
        return None
    if method == "POST" and at(r"/pulls/\d+/ccr/ready_for_review"):
        return finding(ASK, "MARK_READY_FOR_REVIEW", path)
    m = at(r"/git/refs/(?P<ref>.+)")
    if m and method in ("PATCH", "DELETE"):
        ref = m.group("ref")
        if method == "DELETE":
            return finding(DENY, "DELETE_REF", ref)
        branch = ref.removeprefix("heads/")
        if ref.startswith("tags/") or branch in protected:
            return finding(DENY, "UPDATE_PROTECTED_REF", ref)
        return None
    if method == "POST" and at(r"/git/refs"):
        ref = fields.get("ref", "")
        if ref.startswith("refs/tags/"):
            return finding(ASK, "CREATE_TAG", ref)
        if ref.removeprefix("refs/heads/") in protected:
            return finding(DENY, "CREATE_PROTECTED_REF", ref)
        return None
    if method == "POST" and at(r"/git/tags"):
        return finding(ASK, "CREATE_TAG", path)
    if method in ("PUT", "DELETE") and at(r"/contents/.+"):
        branch = branch_name(fields.get("branch", ""))
        if not branch or branch in protected:
            return finding(
                DENY,
                "WRITE_TO_DEFAULT_OR_PROTECTED_BRANCH",
                f"branch={branch or 'default'}",
            )
        return None
    if method in ("PATCH", "DELETE") and at(""):
        return finding(DENY, "REPOSITORY_SETTINGS_OR_DELETE", path)
    if method == "POST" and at(r"/transfer"):
        return finding(DENY, "TRANSFER_REPOSITORY", path)
    if write and (at(r"/branches/[^/]+/(protection|rename).*") or at(r"/rulesets.*")):
        return finding(DENY, "BRANCH_PROTECTION_OR_RULESET", path)
    if write and at(r"/(collaborators|keys|hooks|invitations).*"):
        return finding(DENY, "ACCESS_CONTROL", path)
    if write and (
        at(r"/(actions|dependabot|codespaces)/(secrets|variables).*")
        or at(r"/environments/[^/]+(/(secrets|variables).*)?")
        or at(r"/actions/permissions.*")
    ):
        return finding(DENY, "SECRETS_OR_ACTIONS_SETTINGS", path)
    if write and at(r"/releases.*"):
        return finding(DENY, "RELEASE", path)
    dispatch = at(r"/actions/workflows/[^/]+/dispatches") or at(r"/dispatches")
    if method == "POST" and dispatch:
        return finding(ASK, "WORKFLOW_DISPATCH", path)
    if method == "PUT" and at(r"/actions/workflows/[^/]+/(enable|disable)"):
        return finding(ASK, "WORKFLOW_TOGGLE", path)
    if method == "PATCH" and at(r"/dependabot/alerts/\d+"):
        return finding(ASK, "DISMISS_DEPENDABOT_ALERT", path)
    if method == "POST" and at(r"/(issues|pulls)/\d+/comments"):
        if DEPENDABOT_CMD.search(fields.get("body", "")):
            return finding(DENY, "DEPENDABOT_COMMAND", "merge/close/ignore")
        return None
    if method == "POST" and re.match(r"^(user|orgs/[^/]+)/repos$", path):
        return finding(ASK, "CREATE_REPOSITORY", path)
    return None


# -------------------------------------------------------------- gh porcelain

GH_PORCELAIN = {
    ("pr", "merge"): (DENY, "MERGE_PR"),
    ("pr", "close"): (DENY, "CLOSE_PR"),
    ("pr", "reopen"): (ASK, "REOPEN_PR"),
    ("pr", "ready"): (ASK, "MARK_READY_FOR_REVIEW"),
    ("issue", "close"): (DENY, "CLOSE_ISSUE"),
    ("issue", "delete"): (DENY, "DELETE_ISSUE"),
    ("issue", "transfer"): (DENY, "TRANSFER_ISSUE"),
    ("issue", "reopen"): (ASK, "REOPEN_ISSUE"),
    ("repo", "delete"): (DENY, "DELETE_REPOSITORY"),
    ("repo", "edit"): (DENY, "REPOSITORY_SETTINGS"),
    ("repo", "rename"): (DENY, "RENAME_REPOSITORY"),
    ("repo", "archive"): (DENY, "ARCHIVE_REPOSITORY"),
    ("repo", "unarchive"): (DENY, "UNARCHIVE_REPOSITORY"),
    ("repo", "create"): (ASK, "CREATE_REPOSITORY"),
    ("release", "create"): (DENY, "RELEASE"),
    ("release", "delete"): (DENY, "RELEASE"),
    ("release", "edit"): (DENY, "RELEASE"),
    ("release", "upload"): (DENY, "RELEASE"),
    ("release", "delete-asset"): (DENY, "RELEASE"),
    ("secret", "set"): (DENY, "SECRETS"),
    ("secret", "delete"): (DENY, "SECRETS"),
    ("secret", "remove"): (DENY, "SECRETS"),
    ("variable", "set"): (DENY, "SECRETS"),
    ("variable", "delete"): (DENY, "SECRETS"),
    ("workflow", "run"): (ASK, "WORKFLOW_DISPATCH"),
    ("workflow", "enable"): (ASK, "WORKFLOW_TOGGLE"),
    ("workflow", "disable"): (ASK, "WORKFLOW_TOGGLE"),
}
SHORT_APPROVE = re.compile(r"-[a-zA-Z]*a[a-zA-Z]*")


def check_gh(args: list[str], repo_dir: str):
    rest, i = [], 0
    while i < len(args):
        if args[i] in ("-R", "--repo"):
            i += 2
            continue
        if not args[i].startswith("--repo="):
            rest.append(args[i])
        i += 1
    if not rest:
        return None
    if rest[0] == "api":
        return check_gh_api(rest[1:], repo_dir)
    sub = rest[1] if len(rest) > 1 else ""
    approve = "--approve" in rest or any(SHORT_APPROVE.fullmatch(t) for t in rest[2:])
    if (rest[0], sub) == ("pr", "review") and approve:
        return finding(DENY, "APPROVE_PR", "gh pr review")
    hit = GH_PORCELAIN.get((rest[0], sub))
    return finding(hit[0], hit[1], f"gh {rest[0]} {sub}") if hit else None


# ---------------------------------------------------------------- git push

GIT_VALUE_OPTS = {
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--config-env",
}
PUSH_VALUE_OPTS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}


def check_git(args: list[str], repo_dir: str):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            repo_dir = os.path.join(repo_dir, args[i + 1])
            i += 2
            continue
        i += 2 if args[i] in GIT_VALUE_OPTS else 1
    if i >= len(args) or args[i] != "push":
        return None
    return check_push(args[i + 1 :], repo_dir)


def check_push(args: list[str], repo_dir: str):
    force = lease = delete = everything = tags = False
    positional, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-f", "--force"):
            force = True
        elif a.startswith("--force-with-lease") or a == "--force-if-includes":
            lease = True
        elif a in ("-d", "--delete"):
            delete = True
        elif a in ("--mirror", "--all", "--branches"):
            everything = True
        elif a in ("--tags", "--follow-tags"):
            tags = True
        elif a in PUSH_VALUE_OPTS:
            i += 1
        elif re.fullmatch(r"-[a-zA-Z]{2,}", a):
            force |= "f" in a
            delete |= "d" in a
        elif not a.startswith("-"):
            positional.append(a)
        i += 1

    if everything:
        return finding(DENY, "PUSH_ALL_OR_MIRROR")
    if delete:
        return finding(DENY, "DELETE_REMOTE_BRANCH")
    if force:
        return finding(DENY, "FORCE_PUSH")

    protected = protected_branches(repo_dir)
    findings = []
    refspecs = positional[1:]
    for spec in refspecs:
        if spec.startswith("+"):
            return finding(DENY, "FORCE_PUSH", spec)
        if spec.startswith(":"):
            return finding(DENY, "DELETE_REMOTE_BRANCH", spec)
        src, _, dst = spec.partition(":")
        dst = dst or src
        if dst in ("HEAD", "@"):
            dst = current_branch(repo_dir) or ""
        if not dst:
            findings.append(finding(ASK, "PUSH_UNRESOLVED_BRANCH", spec))
            continue
        if dst.startswith("refs/tags/"):
            findings.append(finding(ASK, "PUSH_TAG", dst))
            continue
        if dst.removeprefix("refs/heads/") in protected:
            return finding(DENY, "PUSH_TO_PROTECTED_BRANCH", dst)
    if not refspecs:
        branch = current_branch(repo_dir)
        if branch is None:
            unresolved = "no refspec, HEAD unknown"
            findings.append(finding(ASK, "PUSH_UNRESOLVED_BRANCH", unresolved))
        elif branch in protected:
            return finding(DENY, "PUSH_TO_PROTECTED_BRANCH", f"current branch {branch}")
    if lease:
        findings.append(finding(ASK, "FORCE_WITH_LEASE"))
    if tags:
        findings.append(finding(ASK, "PUSH_TAGS"))
    return strongest(findings)


# --------------------------------------------------- raw HTTP and tampering

RAW_MERGE = re.compile(r"api\.github\.com/repos/\S+/pulls/\d+/(merge|ccr/auto_merge)\b")
RAW_WRITE = re.compile(
    r"(-X|--request)\s*['\"]?(PUT|PATCH|DELETE|POST)\b"
    r"|requests\.(put|patch|delete|post)\s*\("
    r"|method\s*[:=]\s*['\"](PUT|PATCH|DELETE|POST)['\"]",
    re.IGNORECASE,
)
GUARD_PATHS = re.compile(
    r"(\.claude/(settings(\.local)?\.json|hooks/)|/etc/claude-code/|managed-settings\.json)",
)
WRITE_SHAPED = re.compile(
    r"(>|\btee\b|\bsed\s+(-[a-zA-Z]*i|--in-place)|\bperl\s+-[a-zA-Z]*i|"
    r"\b(cp|mv|rm|ln|chmod|chown|truncate|install|dd|rsync|unlink)\b|"
    r"\bgit\s+(checkout|restore|rm|mv|stash)\b)"
)


def check_raw(command: str):
    findings = []
    if "api.github.com" in command:
        if RAW_MERGE.search(command):
            findings.append(finding(DENY, "MERGE_PR", "raw HTTP"))
        elif RAW_WRITE.search(command):
            findings.append(finding(ASK, "RAW_GITHUB_API_WRITE", "non-gh HTTP write"))
    if GUARD_PATHS.search(command) and WRITE_SHAPED.search(command):
        findings.append(finding(DENY, "GUARD_CONFIG_TAMPER", "write to guard config"))
    return strongest(findings)


# ------------------------------------------------------------ inline python

PYTHON = re.compile(r"python(\d+(\.\d+)*)?")
PYTHON_VALUE_OPTS = {"-W", "-X"}
SPAWN_CALLS = {
    "system", "popen", "run", "call", "check_call", "check_output", "Popen",
    "getoutput", "getstatusoutput", "spawnl", "spawnlp", "spawnv", "spawnvp",
    "execl", "execlp", "execv", "execvp", "execve", "execvpe",
}


def inline_python(args: list[str]) -> str | None:
    """The code given to `python -c`, or None (script file, -m, stdin)."""
    i = 0
    while i < len(args):
        a = args[i]
        if re.fullmatch(r"-[a-zA-Z]*c", a):
            return args[i + 1] if i + 1 < len(args) else None
        if a in PYTHON_VALUE_OPTS:
            i += 2
            continue
        if a == "-m" or not a.startswith("-"):
            return None
        i += 1
    return None


def string_literals(tree: ast.AST) -> list[str]:
    """Every string constant, plus every list/tuple of them joined as argv."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
        elif isinstance(n, (ast.List, ast.Tuple)) and n.elts and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in n.elts
        ):
            out.append(shlex.join(e.value for e in n.elts))
    return out


def check_python(code: str, repo_dir: str, depth: int):
    """When inline code can spawn a process, check each of its string literals
    as a shell command. A computed or obfuscated command is not seen."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        if re.search(r"\b(git|gh)\b|api\.github\.com", code):
            return finding(DENY, "UNPARSEABLE_COMMAND", "python -c, fail closed")
        return None
    spawns = any(
        isinstance(n, ast.Call)
        and (getattr(n.func, "attr", None) or getattr(n.func, "id", None))
        in SPAWN_CALLS
        for n in ast.walk(tree)
    )
    if not spawns:
        return None
    return strongest(classify_bash(s, repo_dir, depth) for s in string_literals(tree))


# -------------------------------------------------------------------- Bash


def is_shell_string(tokens: list[str], idx: int) -> bool:
    """True when tokens[idx] is the script of `eval` or `<shell> -c`."""
    if idx == 0:
        return False
    if tokens[idx - 1] == "eval":
        return True
    if not re.fullmatch(r"-[a-zA-Z]*c", tokens[idx - 1]):
        return False
    window = tokens[max(0, idx - 4) : idx - 1]
    return any(os.path.basename(t) in SHELLS for t in window)


def classify_bash(command: str, cwd: str, depth: int = 0):
    findings = [check_raw(command)]
    tokens = tokenize(command)
    if tokens is None:
        if re.search(r"\b(git|gh)\b|api\.github\.com", command):
            return finding(DENY, "UNPARSEABLE_COMMAND", "fail closed")
        return strongest(findings)

    repo_dir = cwd
    for idx, tok in enumerate(tokens):
        name = os.path.basename(tok)
        if name == "cd" and idx + 1 < len(tokens) and not is_operator(tokens[idx + 1]):
            repo_dir = os.path.join(repo_dir, tokens[idx + 1])
        elif name == "git":
            findings.append(check_git(command_args(tokens, idx), repo_dir))
        elif name == "gh":
            findings.append(check_gh(command_args(tokens, idx), repo_dir))
        elif depth < MAX_DEPTH and is_shell_string(tokens, idx):
            findings.append(classify_bash(tok, repo_dir, depth + 1))
        elif depth < MAX_DEPTH and PYTHON.fullmatch(name):
            code = inline_python(command_args(tokens, idx))
            if code is not None:
                findings.append(check_python(code, repo_dir, depth + 1))
    return strongest(findings)


# --------------------------------------------------------------------- MCP

MCP_NAME = re.compile(r"^mcp__(?P<server>.+?)__(?P<tool>.+)$")

# Tools this guard recognises, by exact name. Names follow the GitHub MCP
# server's published tool list as known when this was written; they are not
# checked against a live server. Any other GitHub tool asks, whatever its name
# looks like (a "get_" prefix or a "comment" infix earns nothing).
MCP_READ_TOOLS = frozenset({
    "get_me", "get_file_contents", "get_commit", "list_commits", "list_branches",
    "list_tags", "get_tag", "search_code", "search_repositories", "search_issues",
    "search_pull_requests", "search_users", "get_issue", "list_issues",
    "get_issue_comments", "issue_read", "get_pull_request", "list_pull_requests",
    "get_pull_request_diff", "get_pull_request_files", "get_pull_request_status",
    "get_pull_request_comments", "get_pull_request_reviews", "pull_request_read",
    "list_workflows", "list_workflow_runs", "get_workflow_run", "list_workflow_jobs",
    "get_job_logs", "get_workflow_run_logs", "list_workflow_run_artifacts",
    "download_workflow_run_artifact", "list_releases", "get_latest_release",
    "get_release_by_tag",
})
MCP_FILE_WRITES = frozenset({"push_files", "create_or_update_file", "create_file", "update_file", "create_commit"})
MCP_REF_WRITES = frozenset({"create_branch", "create_ref", "update_ref"})
MCP_COMMENT_TOOLS = frozenset({"add_issue_comment", "add_comment_to_pending_review"})
# Recognised review tools and the one argument that carries each tool's review
# event. "event" follows the GitHub MCP server's published schema as known
# when this was written; "action" for add_review_to_pr is as relayed in the
# 2026-11-23 audit. Neither is checked against a live server. Approval is read
# from this field only, never from other arguments (labels, metadata, state).
REVIEW_EVENT_FIELD = {
    "pull_request_review_write": "event",
    "create_pull_request_review": "event",
    "create_pending_pull_request_review": "event",
    "submit_pending_pull_request_review": "event",
    "add_review_to_pr": "action",
}
MCP_REVIEW_TOOLS = frozenset(REVIEW_EVENT_FIELD) | {"delete_pending_pull_request_review", "request_copilot_review"}
# For a review-named tool the guard does not recognise, the arguments read for
# an approval, so an approval through it still denies.
UNKNOWN_REVIEW_EVENT_FIELDS = ("event", "action")
# pull_request_review_write operations by method.
REVIEW_WRITE_METHODS = {"create", "submit_pending", "delete_pending"}
APPROVE_VALUES = {"APPROVE", "APPROVED"}
NON_APPROVING_EVENTS = {"COMMENT", "REQUEST_CHANGES"}
# Reruns are allowed by policy, as on the Bash path.
MCP_RERUN_TOOLS = frozenset({"rerun_workflow_run", "rerun_failed_jobs", "rerun_workflow_job"})
MCP_PR_ISSUE_WRITES = frozenset({
    "create_pull_request", "update_pull_request", "update_pull_request_branch",
    "create_issue", "update_issue", "issue_write",
})


def review_event(tool_input: dict, field: str) -> str | None:
    """The upper-cased review event, None when the field is absent, "" when
    it is present but not a string."""
    if field not in tool_input:
        return None
    value = tool_input[field]
    return value.strip().upper() if isinstance(value, str) else ""


def review_finding(tool: str, tool_name: str, tool_input: dict):
    """Classify a recognised review tool by operation.

    Approvals and pending-review deletion deny. A comment or request-changes
    event, and creating a pending review with no event, pass. Anything else
    (missing or unknown method, missing or unknown event where one is
    required) asks.
    """
    if tool == "request_copilot_review":
        return None
    if tool == "delete_pending_pull_request_review":
        return finding(DENY, "DELETE_PENDING_REVIEW", tool_name)
    event_optional = tool == "create_pending_pull_request_review"
    if tool == "pull_request_review_write":
        method = tool_input.get("method")
        if method == "delete_pending":
            return finding(DENY, "DELETE_PENDING_REVIEW", tool_name)
        if not isinstance(method, str) or method not in REVIEW_WRITE_METHODS:
            return finding(ASK, "UNKNOWN_REVIEW_METHOD", f"{tool_name} method={method!r}")
        event_optional = method == "create"
    field = REVIEW_EVENT_FIELD[tool]
    event = review_event(tool_input, field)
    if event in APPROVE_VALUES:
        return finding(DENY, "APPROVE_PR", tool_name)
    if event in NON_APPROVING_EVENTS or (event is None and event_optional):
        return None
    return finding(ASK, "UNRESOLVED_REVIEW_EVENT", f"{tool_name} {field}={tool_input.get(field)!r}")


def is_protected(name: str, cwd: str) -> bool:
    return name in protected_branches(cwd)


def target_repo_finding(tool_name: str, tool_input: dict, cwd: str):
    """None when the call names this checkout's origin repository.

    Both owner and repo omitted: ask, because no verified tool schema says
    what they default to. Incomplete or non-string identity, an unreadable
    origin, or a different repository: deny, because that repository's
    protected branches cannot be known from this checkout.
    """
    if "owner" not in tool_input and "repo" not in tool_input:
        return finding(ASK, "UNRESOLVED_TARGET_REPOSITORY", f"{tool_name}: owner/repo omitted")
    owner, repo = tool_input.get("owner"), tool_input.get("repo")
    if not (isinstance(owner, str) and owner.strip() and isinstance(repo, str) and repo.strip()):
        return finding(DENY, "INCOMPLETE_TARGET_REPOSITORY", f"{tool_name}: owner/repo incomplete")
    origin = origin_slug(cwd)
    if origin is None:
        return finding(DENY, "UNRESOLVED_ORIGIN", f"{tool_name}: this checkout's origin is unknown")
    if f"{owner.strip()}/{repo.strip()}".lower() != origin:
        return finding(
            DENY,
            "WRITE_TO_OTHER_REPOSITORY",
            f"{owner}/{repo}: its default branch is unknown from this session",
        )
    return None


def file_write_finding(tool_name: str, tool_input: dict, cwd: str):
    branch = branch_name(tool_input.get("branch", ""))
    if not branch or is_protected(branch, cwd):
        return finding(
            DENY,
            "WRITE_TO_DEFAULT_OR_PROTECTED_BRANCH",
            f"branch={branch or 'default or unresolved'}",
        )
    return None


def force_finding(tool_name: str, tool_input: dict):
    """Forced ref updates deny. Only an absent key or literal false passes;
    any other value is ambiguous and asks rather than being read as false."""
    if "force" not in tool_input or tool_input["force"] is False:
        return None
    value = tool_input["force"]
    if value is True or (isinstance(value, str) and value.strip().lower() == "true"):
        return finding(DENY, "FORCE_UPDATE_REF", tool_name)
    return finding(ASK, "AMBIGUOUS_FORCE_VALUE", f"{tool_name}: force={value!r}")


def ref_write_finding(tool_name: str, tool_input: dict, cwd: str):
    target = ref_target(tool_input.get("ref") or tool_input.get("branch"))
    if target is None or target[0] == "tag" or is_protected(target[1], cwd):
        label = f"{target[0]}={target[1]}" if target else "unresolved"
        return finding(DENY, "PROTECTED_REF", f"{tool_name} {label}")
    return None


def classify_mcp(tool_name: str, tool_input: dict, cwd: str):
    m = MCP_NAME.match(tool_name)
    if not m or "github" not in m.group("server").lower():
        return None
    tool = m.group("tool").lower()
    state = str(tool_input.get("state", "")).lower()
    # Consequential transitions deny by name, recognised or not.
    if "merge_pull_request" in tool or "auto_merge" in tool:
        return finding(DENY, "MERGE_PR", tool_name)
    if state == "closed" and tool in ("update_pull_request", "update_issue", "issue_write"):
        return finding(DENY, "CLOSE_PR_OR_ISSUE", tool_name)
    if tool in ("delete_file", "delete_repository", "delete_branch"):
        return finding(DENY, "DELETE", tool_name)
    if "comment" in tool and DEPENDABOT_CMD.search(str(tool_input.get("body", ""))):
        return finding(DENY, "DEPENDABOT_COMMAND", tool_name)
    # Reviews: recognised tools by operation; any other review-named tool
    # denies on an approval in its event/action argument, otherwise asks below.
    if tool in MCP_REVIEW_TOOLS:
        return review_finding(tool, tool_name, tool_input)
    if "review" in tool and any(review_event(tool_input, f) in APPROVE_VALUES for f in UNKNOWN_REVIEW_EVENT_FIELDS):
        return finding(DENY, "APPROVE_PR", tool_name)
    # Writes to repository contents and refs.
    if tool in MCP_FILE_WRITES:
        return strongest([
            file_write_finding(tool_name, tool_input, cwd),
            target_repo_finding(tool_name, tool_input, cwd),
        ])
    if tool in MCP_REF_WRITES:
        return strongest([
            ref_write_finding(tool_name, tool_input, cwd),
            target_repo_finding(tool_name, tool_input, cwd),
            force_finding(tool_name, tool_input),
        ])
    if tool in ("create_repository", "fork_repository"):
        return finding(ASK, "CREATE_REPOSITORY", tool_name)
    if tool == "update_pull_request" and "draft" in tool_input and tool_input["draft"] is not True:
        return finding(ASK, "MARK_READY_FOR_REVIEW", tool_name)
    # Recognised tools with no consequential effect in the arguments above.
    if tool in MCP_READ_TOOLS | MCP_COMMENT_TOOLS | MCP_RERUN_TOOLS | MCP_PR_ISSUE_WRITES:
        return None
    # Default for a GitHub tool this guard does not recognise: ask, never allow.
    return finding(ASK, "UNCLASSIFIED_GITHUB_MCP_TOOL", tool_name)


# -------------------------------------------------------------------- main


def classify(payload: dict):
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()
    if tool_name == "Bash":
        return classify_bash(str(tool_input.get("command", "")), cwd)
    if tool_name.startswith("mcp__"):
        return classify_mcp(tool_name, tool_input, cwd)
    return None


def emit(decision: str, reason: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def main() -> None:
    try:
        result = classify(json.load(sys.stdin))
    except Exception as exc:  # noqa: BLE001, RUF100 -- fail closed on any internal error
        msg = "github_transition_guard: internal error, failing closed"
        emit(DENY, f"{msg} ({type(exc).__name__}: {exc})")
        return
    if result:
        emit(*result)
    sys.exit(0)


if __name__ == "__main__":
    main()
