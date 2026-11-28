# GGC-001C — GitHub platform enforcement

> **DRAFT rev 3 · T1 · `t0_ratified: false` · no execution authority.** Frame,
> taxonomy (TX-*) and rules (R1–R7) are in [README](README.md). Every
> setting below is a T0 action in the GitHub UI. No agent changes settings
> (TX-09/TX-13 are DENY on every agent surface).

```yaml
provenance_binding:
  binding_id: PB-GGC-001C-20261127          # local label, not a Canon ID
  source_tier: T1
  t2_source: T0 Decision Delta D3; GGC-001 v1.0 G5; A/B/C response (D3/D4 notes), 2026-11-27
  t1_verified: true
  t0_ratified: false
  canon_refs: []
  session_ref: https://claude.ai/code/session_01XUDqLzF4mEWTvnGJk1FhbV
  created_at: "2026-11-27T22:43:33Z"
trust_state:
  current_state: PROVISIONAL
```

## 1. Why this layer comes first

C is the only layer that acts on every surface, every token and every human
slip, including the residual risks that GGC-001A accepts by design (scripts,
heredocs, processes outside the harness) and everything on GGC-001B.

## 2. Baseline (Observed, 2026-11-27 ~22:3x UTC)

Endpoints used, all non-admin reads: `GET repos/{o}/{r}` (visibility, default
branch), `GET repos/{o}/{r}/branches/{b}` (`.protected`),
`GET repos/{o}/{r}/rules/branches/{b}` (active rules, rulesets included).

| Repository | Visibility | Default branch | `protected` | Active rules | Notes |
|---|---|---|---|---|---|
| shadowfox-canon-guardrails | public | main | false | 0 | |
| smse-engine | public | main | false | 0 | |
| shadowfox-docs-compiler-smoke-test | public | main | false | 0 | Deploys from `environment: github-pages` |
| Cathedral-Codex | public | main | false | 0 | |
| agent-codex-os | public | main | false | 0 | PSE: **GATED** |
| NHD | public | main | false | 0 | Separate project (NotHotDog) |
| tridecagon-agents | private | main | false | plan-gated | |
| shadowfox-os- | private | main | false | plan-gated | |
| shadowfox-operator | private | main | false | plan-gated | |
| ske-shadowfox | private | master | false | plan-gated | |
| Shadowfox-OS-Specification-Repository | private | main | false | plan-gated | |
| shadowfox-runtime-kernel | private | main | false | plan-gated | |
| shadowfox-t0-dashboard | private | main | false | plan-gated | |
| shadowfox-compiler | private | master | false | plan-gated | |
| shadowfox-eval-harness | private | main | false | plan-gated | |
| shadowfox-swarm | private | main | false | plan-gated | |
| shadowfox-cloud | private | main | false | plan-gated | |
| shadowfox-dsl | private | main | false | plan-gated | |
| shadowfox-lenovo-agent | private | main | false | plan-gated | |
| shadowfox-platform-audit | private | main | false | plan-gated | |
| temporal-drift-engine | private | main | false | plan-gated | |
| Shadowfox-History | private | main | false | plan-gated | |
| ag-cluster-agents- | private | main | false | plan-gated | |
| promptops-prompt-sdk | private | main | false | plan-gated | |
| Shadowfox-systems | private | `claude/txt-instructions-review-oxjnc5` | false | plan-gated | **Anomaly:** an agent branch is the default |
| shadowfox-sweep | private | `claude/stoic-dirac-doambh` | false | plan-gated | **Anomaly:** an agent branch is the default |
| shadowfox-ai-operating-spec | private | main (declared) | n/a: no branches | plan-gated | **Empty repository** (size 0, 0 branches; re-checked 2026-11-27). The declared default `main` does not exist, and the first push would create it unprotected. |

"Plan-gated" means GitHub answered: *"Upgrade to GitHub Pro or make this
repository public to enable this feature."* (HTTP 403). Re-observed at
2026-11-27T22:39:21Z on tridecagon-agents and shadowfox-os-.

| Control | Status |
|---|---|
| Classic branch protection | **Confirmed absent** on 26 (`protected=false`). **Not applicable** on 1: shadowfox-ai-operating-spec has no branches. A 404 is not counted as confirmation. |
| Rulesets, 6 public | **Confirmed absent** (0 active rules) |
| Rulesets / protection, 21 private | **Unavailable on the current plan** (not merely unread) |
| GitHub Pro upgrade | Decision record (said to be 2026-11-22): **Unverified**. Completion: **Contradicted** at 22:39:21Z. |
| Environment protection (`github-pages`) | **Unavailable** (the cloud proxy blocks the environments endpoint) |
| App installation scope (Claude App, ChatGPT connector) | **Unverified**. The Claude cloud session that produced this draft was scoped to 74 repositories. |

## 3. Identity: the design axis (OPD-C2)

**Finding.** T0, every Claude Code session (through the Claude GitHub App)
and the ChatGPT connector all act as `RJHuey73`. PR #8 shows the consequence:
the ready and merge events carry the right actor and still cannot be
attributed to a human or an agent.

**Supported inference (verify before freezing the design).** Rulesets and
bypass lists are evaluated against the acting user's role. An app acting for
a user inherits that user's role, including any T0 bypass. So with one
identity:

| Option | Model | What the platform can enforce | What it cannot |
|---|---|---|---|
| I | Single identity (today) + rules | No direct pushes to the default branch, no force-push or deletion, no merge without required checks (TX-05, TX-06, and the CI-gated part of TX-01) | Telling an agent merge from a T0 merge. Requiring approvals deadlocks T0, since an author cannot approve their own PR. A T0 bypass is the agent's bypass too. |
| II | A separate agent account with the **Write** role. Claude App and connector sessions connect as that account. T0 keeps **Admin**. | Everything in I, plus: require 1 approval, approval of the most recent push, and dismissal of stale approvals. Bypass is limited to the Repository-admin role (T0). Agents can push branches and open PRs; they cannot merge, and they cannot approve their own PRs. | TX-03/04/08/14/15 (role-level: Write can close, reopen and rerun). Those need the Read role, which cannot push branches. |

**Points to verify under Option II:** bypass evaluation for app tokens acting
for a user (V7); GitHub's terms for machine accounts; re-authorizing both
connectors as the agent account; and that private repos still need OPD-C3.

### 3.1 Option II operating model (required before adoption)

| Element | Requirement |
|---|---|
| Permission | The agent account gets the **Write** role per governed repository: never Maintain or Admin, never account- or org-wide. |
| Ownership | T0 creates and owns it: a T0-controlled email, 2FA on, recovery codes held by T0 offline. |
| Credentials | No personal access token unless T0 decides otherwise. Agents connect through the Claude GitHub App and the ChatGPT connector, authorized while signed in as the agent account. |
| Bypass | Ruleset bypass = the Repository-admin role only. T0 confirms no other collaborator holds Admin. The agent account never appears in a bypass list. |
| Revocation | 1) Remove the agent account as collaborator: immediate, enforced by GitHub, and enough on its own to end repository access. 2) Revoke the Claude and ChatGPT app authorizations in the agent account. 3) Sign out all sessions and reset the password. Rehearsed once in the sandbox (V8). |
| Attribution | Agent actions carry the agent account as actor, which closes the PR #8 class of question. The `RJHuey73` actor then means T0. |
| Review | On every change, T0 records the collaborator list and the bypass lists. The §7.1 re-run adds the collaborator list where the endpoint is readable. |

## 4. Public repositories: rulesets available today (OPD-C1)

T0 applies these in each repository: Settings → Rules → Rulesets → New
branch ruleset. Target: the default branch.

> **0 required approvals is not T0-only merge authority.** Under Option I,
> anyone holding the `RJHuey73` identity, agents included, can still merge,
> with or without checks. This baseline hardens the platform (TX-05, TX-06)
> and nothing more.

**Baseline rules (OPD-C1):** restrict deletions; block force pushes; require a
pull request before merging (required approvals **0** under Option I, **1**
with last-push approval and stale-review dismissal under Option II); bypass
list empty under Option I, Repository-admin only under Option II (§3.1).

**Required status checks are not part of the baseline** until §4.1 marks a
check Suitable. Today none is. T0 may add a Candidate check knowingly, and
must then record its S2/S3 residual.

### 4.1 Required-check suitability

A check is Suitable only if all three properties hold.

| Property | Question | Candidate control | Status |
|---|---|---|---|
| S1 Identity | Did GitHub Actions produce the result, rather than a commit status anyone with write access can post (P26)? | Pin each required check to the source app GitHub Actions (app id 15368) in the ruleset | A documented ruleset option that closes P26 at the platform. Not yet exercised (V9). |
| S2 Execution path | Did the result come from the intended PR-validation run, not another run that emits the same name? | (a) A PR-only check name: a job in a workflow triggered only by `pull_request`, with a name no other workflow emits. (b) "Require branches to be up to date before merging", so a push run on the head tests the same tree as the PR merge run. | Unverified (V10) |
| S3 Definition integrity | Can the workflow that produces the result be weakened without independent review? | A `pull_request` run uses the PR's own copy of the workflow, so a PR can rewrite its own gate. Candidate: CODEOWNERS for `.github/workflows/**` with required code-owner review (needs OPD-C2 Option II and approvals ≥ 1). Not available: org-level required workflows (they need an organization account). **Rejected:** `pull_request_target`, which runs the base definition but with a privileged token next to untrusted PR code. | Unverified (V11). Under Option I no candidate applies, so S3 stays residual. |

S2 depends on S3: without S3, a PR can add a same-name job on any trigger.

| Repository | Candidate check(s) | S1 evidence | S2 | S3 | Disposition |
|---|---|---|---|---|---|
| shadowfox-canon-guardrails | `guard-transition-tests` | Observed: app `github-actions` (15368); a `pull_request` run of `.github/workflows/guard-tests.yml` on PR #8 head `6897e09`, success | Only `pull_request` runs reach non-`main` heads (the push trigger is `main` only). Not tested against an adversarial PR. | Not established | **Candidate**, dependent on S3 |
| smse-engine | `test (py3.11)`, `test (py3.12)`, `test (py3.13)`, `JS oracle reproduces golden`, `canon lint (CANON-360)` | Observed: app `github-actions` (15368), success on PR #4 head `4ec10e4` | **Not established:** each name is produced twice on that head, by `pull_request` suites (122002448922, 122002448934) and by `push` suites (122002315051, 122002315088), because both workflows also run on `push: branches: ["**"]` | Not established | **Observed and successful; suitability pending** |
| shadowfox-docs-compiler-smoke-test | None: `build` and `deploy` run only on push and dispatch | — | — | — | **No suitable check.** Nothing validates its PRs. |
| Cathedral-Codex | None (no workflows) | — | — | — | **No suitable check.** PRs unvalidated. |
| agent-codex-os | None (only the Dependabot job) | — | — | — | **No suitable check.** PSE GATED: T0 applies the baseline personally. |
| NHD | None (only the Dependabot job) | — | — | — | **No suitable check.** Separate project; in scope only if T0 decides. |

An empty check list records an absence of validation. It is not a passing state.

Effect under Option I: the baseline closes TX-05 and TX-06 on every surface,
including GGC-001A's residuals and GGC-001B. It gates no TX-01 by checks
until a check is Suitable. Authority separation for TX-01/02 still needs
Option II.

## 5. Private repositories (OPD-C3)

The 21 private repositories, including the core runtime (tridecagon-agents,
shadowfox-os-, ske-shadowfox, shadowfox-operator, the spec repo and
shadowfox-runtime-kernel), cannot carry rules on the current plan.

**Step 0 (T0):** read the subscription state in GitHub settings (Billing and
plans). The API can't show it from here (`user.plan` unreadable). The
2026-11-22 record is Unverified, and the plan gate was still active at
22:39:21Z. No purchase or visibility change follows from this document.

| Path | Effect | Note |
|---|---|---|
| C3-a GitHub Pro | Enables protection and rulesets on private repos | Price not stated here (Unverified). Resolves the Unverified 2026-11-22 record. |
| C3-b Make public | Rules available free | Exposes private runtime and governance code. Not recommended without review. |
| C3-c Accept the residual | No platform enforcement | Only GGC-001A, client-side, where loaded. Record as accepted risk. |

The default-branch anomalies (Shadowfox-systems, shadowfox-sweep,
shadowfox-ai-operating-spec) must be resolved **before** rules target "the
default branch". Otherwise the rule protects an agent branch, or nothing.

## 6. App installation scope

| Item | Requirement |
|---|---|
| Claude GitHub App | T0 records its repository selection. Narrow it to repositories agents need. |
| ChatGPT connector app | Per GGC-001B B-R4 (OPD-B2) |
| Evidence | The list as recorded by T0 from GitHub settings (Installed GitHub Apps), dated |

## 7. Verification

### 7.1 Read-only re-run (repeatable, no GO needed)

GET requests only. It covers the full governed scope in §2 and fails closed: exit 0 only when every
repository resolves its default branch and has ≥ 1 active rule. FAIL means confirmed no rules or
plan-gated; INCOMPLETE means anything unreadable or unresolved. For rulesets, `protected` may stay
`false`; the active-rules count is the evidence.

```bash
#!/usr/bin/env bash
# GGC-001C §7.1: read-only platform re-run. GET requests only; changes nothing.
# Exit 0 only if EVERY governed repository resolves its default branch AND has
# >= 1 active rule. Exit 1 if any repository FAILs (confirmed no rules, or
# plan-gated). Exit 2 if any result is INCOMPLETE (unreadable or unresolved).
# Anything not positively verified counts as not passing (fail closed).
set -u
OWNER=RJHuey73
# Governed scope: GGC-001C §2. T0 decides whether NHD stays in scope.
REPOS=(shadowfox-canon-guardrails smse-engine shadowfox-docs-compiler-smoke-test
  Cathedral-Codex agent-codex-os NHD tridecagon-agents shadowfox-os- shadowfox-operator
  ske-shadowfox Shadowfox-OS-Specification-Repository shadowfox-runtime-kernel
  shadowfox-t0-dashboard shadowfox-compiler shadowfox-eval-harness shadowfox-swarm
  shadowfox-cloud shadowfox-dsl shadowfox-lenovo-agent shadowfox-platform-audit
  temporal-drift-engine Shadowfox-History ag-cluster-agents- promptops-prompt-sdk
  Shadowfox-systems shadowfox-sweep shadowfox-ai-operating-spec)
pass=0; fail=0; incomplete=0
last() { printf '%s' "${1##*$'\n'}"; }
for r in "${REPOS[@]}"; do
  if ! meta=$(gh api "repos/$OWNER/$r" 2>&1); then
    echo "INCOMPLETE  $r  repo unreadable: $(last "$meta")"; incomplete=$((incomplete+1)); continue; fi
  b=$(jq -r '.default_branch // empty' <<<"$meta" 2>/dev/null)
  if [ -z "$b" ]; then echo "INCOMPLETE  $r  no default branch"; incomplete=$((incomplete+1)); continue; fi
  if br=$(gh api "repos/$OWNER/$r/branches/$b" 2>&1); then prot=$(jq -r .protected <<<"$br")
  else echo "INCOMPLETE  $r@$b  branch unresolved: $(last "$br")"; incomplete=$((incomplete+1)); continue; fi
  if rules=$(gh api "repos/$OWNER/$r/rules/branches/$b" 2>&1); then
    n=$(jq length <<<"$rules" 2>/dev/null)
    if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ]; then echo "PASS        $r@$b  rules=$n protected=$prot"; pass=$((pass+1))
    elif [[ "$n" =~ ^[0-9]+$ ]]; then echo "FAIL        $r@$b  rules=0 protected=$prot"; fail=$((fail+1))
    else echo "INCOMPLETE  $r@$b  rules unparseable"; incomplete=$((incomplete+1)); fi
  elif grep -q 'Upgrade to GitHub Pro' <<<"$rules"; then
    echo "FAIL        $r@$b  rules plan-gated protected=$prot"; fail=$((fail+1))
  else echo "INCOMPLETE  $r@$b  rules unreadable: $(last "$rules")"; incomplete=$((incomplete+1)); fi
done
echo "SUMMARY total=${#REPOS[@]} pass=$pass fail=$fail incomplete=$incomplete at $(date -u +%FT%TZ)"
[ "$incomplete" -gt 0 ] && exit 2; [ "$fail" -gt 0 ] && exit 1; exit 0
```

**Baseline run, 2026-11-27T23:02:31Z:** total 27 · pass 0 · fail 26 · incomplete 1
(shadowfox-ai-operating-spec: branch 404) · exit 2.

### 7.2 Sandbox proof (needs a separate GO; creates a throwaway public repo)

| ID | Test | Expected |
|---|---|---|
| V1 | Direct push to the default branch | Rejected by the ruleset |
| V2 | Force push to the default branch | Rejected |
| V3 | Delete the default branch | Rejected |
| V4 | Merge with required checks failing or absent | Rejected |
| V5 | Option II: the agent account merges its own PR without approval | Rejected |
| V6 | Option II: T0 approves, then merges | Succeeds |
| V7 | A Claude App session as `RJHuey73` merges a bypass-eligible PR | Records whether the T0 bypass carries over to the app. This decides whether Option I can ever separate authority. |
| V8 | Option II revocation drill: remove the agent account in the middle of a session | The next agent write fails with 403/404 |
| V9 | Post a commit status named like a required check (P26 shape), with the check pinned to GitHub Actions | The forged status does not satisfy the requirement (S1) |
| V10 | Satisfy a required check from a `push` run only, with and without "require branches to be up to date" | Records whether S2 candidate (b) holds |
| V11 | Under Option II with CODEOWNERS on `.github/workflows/**`, a PR weakens the required workflow | The merge is blocked until T0's code-owner review (S3) |

Record per test: repo, ruleset JSON, actor, `performed_via_github_app`,
GitHub error text, timestamp.

## 8. Open decisions

OPD-C1 (public baseline), OPD-C2 (identity), OPD-C3 (private path).
See [README §7](README.md#7-open-t0-decisions-consolidated).

={∆§/π}™
