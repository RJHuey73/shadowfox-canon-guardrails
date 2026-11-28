# GGC-001 — GitHub Governance Coverage (frame)

> **DRAFT rev 3 · T1 · `t0_ratified: false` · no execution authority.** Change log: §11.
> `GGC-*`, `TX-*`, `OPD-*`, `P*` and `DD-*` are local instrument labels, not
> Canon IDs. Canon state was not read for this draft (Airtable returned 429,
> monthly quota), so no Canon version, ID or gate status is asserted here.

```yaml
provenance_binding:
  binding_id: PB-GGC-001-20261127          # local label, not a Canon ID
  source_tier: T1
  t2_source: >-
    ChatGPT GitHub connector session, 2026-11-27: Daily GitHub health audit,
    T0 Decision Delta, GGC-001 v1.0, and the A/B/C response to T1 triage.
  t1_verified: true                        # see per-instrument evidence labels
  t0_ratified: false
  canon_refs: []
  session_ref: https://claude.ai/code/session_01XUDqLzF4mEWTvnGJk1FhbV
  created_at: "2026-11-27T22:43:33Z"
  notes: Supersedes GGC-001 v1.0 (T2). Splits it into GGC-001A/B/C.
trust_state:
  current_state: PROVISIONAL
```

## 1. Why three instruments

GitHub transitions reach RJHuey73 repositories through separate execution
surfaces. A control on one surface does not govern another, and a passing
test on one surface proves nothing about the others.

| Instrument | Surface | Execution path | Who can enforce | State on 2026-11-27 |
|---|---|---|---|---|
| [GGC-001A](GGC-001A-claude-code.md) | Claude Code sessions | Bash, `mcp__*` GitHub tools, file edits | PreToolUse hook + `permissions` (client-side) | Loads only when the project root is this repo; confirmed bypasses |
| [GGC-001B](GGC-001B-chatgpt-connector.md) | ChatGPT GitHub connector | The connector's own tool calls | No hook can see these calls. Enforcement only via GitHub app scope and the platform | 41 write tools (T2-reported); no client guard |
| [GGC-001C](GGC-001C-github-platform.md) | GitHub itself | Every token, app, agent and human | Roles, branch protection, rulesets, app installations | 26/27 Shadowfox-scope default branches confirmed unprotected (1 empty repository, no branch); private repos plan-gated |

GGC-001C is the only layer that acts on every surface. Its central open
question is identity: all three surfaces currently act as `RJHuey73`, which
is also T0's identity (GGC-001C §3).

## 2. Transition taxonomy (shared by all three)

Govern the transition, not the tool. Every tool, endpoint or command on every
surface maps to exactly one class, chosen by the requested end state
(fields included) rather than the tool name.

| TX | Transition | Includes | Baseline policy (guard on `main`, Bash) | Proposed required outcome |
|---|---|---|---|---|
| TX-00 | Unclassified write | Any write-capable call not mapped below | Falls through (no decision) | **DENY** |
| TX-01 | Merge | PR merge, enable auto-merge, `POST /merges`, bot merge commands (`@dependabot merge`) | DENY | DENY |
| TX-02 | Approve / alter approval | Review with `APPROVE`, dismissing a review | DENY (approve) | DENY |
| TX-03 | Close / delete / transfer | Close PR or issue, delete or transfer an issue | DENY | DENY |
| TX-04 | Reopen / draft→ready | Reopen PR or issue, mark ready for review | ASK | **OPD-A2** |
| TX-05 | Write to default or protected branch | Push, contents write without a branch or to a protected one, protected ref update, create a ref with a protected name | DENY | DENY |
| TX-06 | History rewrite / ref deletion | Force push, ref or branch delete, `--mirror`, `--all` | DENY | DENY |
| TX-07 | Tags | Create or push tags | ASK | ASK |
| TX-08 | Workflow execution | Dispatch, enable/disable, rerun, cancel | ASK (dispatch, toggle); ALLOW (rerun, pinned by test) | **OPD-A3** for rerun and cancel |
| TX-09 | Repository settings | Edit, visibility, rename, archive, transfer, delete | DENY | DENY |
| TX-10 | Access control | Collaborators, deploy keys, webhooks, invitations | DENY | DENY |
| TX-11 | Secrets and Actions settings | Secrets, variables, Actions permissions | DENY | DENY |
| TX-12 | Releases | Create, edit, delete, upload | DENY | DENY |
| TX-13 | Protection and rulesets | Branch protection, rulesets, branch rename | DENY | DENY |
| TX-14 | Communication | Comments, labels, reactions, assignees, reviewers, review threads, locks | ALLOW | ALLOW (a bot-command comment takes the class of its effect) |
| TX-15 | PR/issue create and edit | Create; edit title or body | ALLOW (opaque body: ASK) | ALLOW (opaque body: R8) |
| TX-16 | Feature-branch work | Push or contents write to a non-protected branch, git objects, create a non-protected branch, update a PR branch | ALLOW | ALLOW |
| TX-17 | Security alert dismissal | Dependabot, code-scanning and secret-scanning alert state | ASK (Dependabot) | ASK |
| TX-18 | Guard tamper | Writes to `.claude/settings*.json`, `.claude/hooks/`, managed settings | DENY | DENY |
| TX-19 | Repository creation / fork | Create or fork a repository | ASK | ASK |
| TX-20 | Audit-evidence destruction | Delete workflow runs, logs, artifacts or caches (REST DELETE, `gh run delete`, `gh cache delete`). Candidate: deleting issue, PR or review comments (**OPD-A5**). | Falls through (P21, P21a–d, P21f–h, P21j–k); raw-URL forms ASK (P21e, P21i) | **DENY** (comments per OPD-A5) |
| TX-21 | Status forgery | Create a commit status (`POST /statuses/{sha}`) or a check result | Falls through (P26) | **DENY** |
| — | Read | GET / read-only calls, decided by the actual HTTP method | ALLOW | ALLOW |

## 3. Decision vocabulary

| Decision | Meaning |
|---|---|
| ALLOW | Normal agent work. |
| ASK | Interactive confirmation. **ASK is not T0 authority** and never stands in for a GO. |
| DENY | Blocked inside the agent session. T0 makes the transition through a controlled path outside the session. |
| UNKNOWN → DENY | Unrecognized tool or route, or unparseable input. |
| OPAQUE → R8 | The route is known, but a value that decides the class (body, query, ref, branch, push destination) cannot be read. |

## 4. Evidence and control labels

- **Evidence:** Observed · Supported inference · Unverified · Contradicted.
- **Controls:** Verified · Unverified · Unavailable · Confirmed absent.
  *Unavailable is never read as absent; absent is never read as unavailable.*

## 5. Binding rules

| Rule | Statement |
|---|---|
| R1 | Classify by transition (TX), not by tool name. |
| R2 | Unknown → DENY on every surface that can decide. |
| R3 | **Parity.** A TX class has one required outcome on every surface where it is reachable. Where a surface cannot enforce it, either GGC-001C must enforce it or the surface loses write access, and the gap is recorded as residual. |
| R4 | A pass on one surface is not evidence for another. |
| R5 | Green CI, mergeability or a successful test is not authority (Correctness ≠ Authority). |
| R6 | Monitoring is not enforcement. An after-the-fact attribution signal (for example `performed_via_github_app`) does not prevent a transition. |
| R7 | Capability is not permission. Holding a credential that can merge does not authorize a merge (UAC-K-002, as cited by the guard). |
| R8 | **Opaque input.** When a deciding value cannot be read, the outcome is the strongest outcome among the classes the call could still be: any DENY candidate → DENY. The guard's current ASK for opaque bodies, opaque GraphQL queries and unresolved pushes stands as an exception only if T0 ratifies it (OPD-A6). Until then those cases are BLOCKED, not PASS. |

## 6. Closure gates

| Gate | Meaning | 001A | 001B | 001C |
|---|---|---|---|---|
| G1 | Inventory complete | Tool and command surface exported from the session | Connector tool export: names, argument schemas, HTTP mapping | Repository and identity inventory |
| G2 | Every item mapped to a TX class | Classifier table | Tool → TX → lever | Rule → TX |
| G3 | Fail-closed verified | TX-00 and parse-failure tests | n/a (no interception point) | Rules apply with no bypass gap |
| G4 | Cross-surface parity (R3) | A vs B vs C table | A vs B vs C table | A vs B vs C table |
| G5 | Independent enforcement | Depends on C | Depends on C | Sandbox verification V1–V11 |
| G6 | Regression evidence | Existing suite + GGC-001A Appendix A (37 cases) | Read-only monitoring still works | §7.1 script exits 0 |
| G7 | T0 acceptance | T0 | T0 | T0 |

### 6.1 Failure response

| Trigger | Response |
|---|---|
| Loading canary (P25) does not DENY | Treat the session as unguarded: no GitHub write of any class; report to T0. |
| A probe or regression case returns a weaker decision than Required | Block that guard change and record the case. No workaround, and no test edit to make it pass. |
| The GGC-001C §7.1 re-run exits non-zero after OPD-C1 | Report each FAIL to T0 as Confirmed absent and each INCOMPLETE as Unverified. No agent re-applies anything. |
| An endpoint becomes Unavailable | Record it as Unavailable (§4). Never downgrade it to absent or upgrade it to verified. |
| Evidence that a DENY-class transition happened (for example the actor and app on a merge) | Stop, preserve the evidence (no deletion: TX-20), report to T0. |

## 7. Open T0 decisions (consolidated)

| ID | Decision | Instrument |
|---|---|---|
| DD-2026-11-27/D1 | Attest that you made the PR #8 ready-for-review (22:34:24Z) and merge (22:40:40Z) transitions | Decision Delta (dependency) |
| DD-2026-11-27/D1-b | The PR #8 body cites GO-1 at creation (22:31:27Z), before the recorded GO-1 time (22:32:19Z). Tracked separately: an attestation does not explain the body's edit history. | Decision Delta |
| OPD-A1 | Hook deployment mechanism | A |
| OPD-A2 | TX-04: ASK or DENY | A (parity → B, C) |
| OPD-A3 | TX-08 rerun and cancel: ALLOW (current, pinned) or ASK | A (parity → B) |
| OPD-A4 | Unknown GitHub MCP tool: DENY or ASK | A |
| OPD-A5 | TX-20 scope: deleting issue, PR or review comments counts as evidence destruction (DENY) or communication (ASK)? | A (parity → B) |
| OPD-A6 | R8 exceptions: keep ASK for opaque bodies, opaque GraphQL queries and unresolved pushes (current guard), or apply strongest-candidate DENY | A (parity → B, C) |
| OPD-B1 | Does the ChatGPT connector need any write access? | B |
| OPD-B2 | Which repositories the connector's GitHub App can reach | B |
| OPD-C1 | Apply the public-repo baseline rulesets (GGC-001C §4). Platform hardening, **not** authority separation. | C |
| OPD-C2 | Identity model: I (single identity) or II (separate agent account, GGC-001C §3) | C |
| OPD-C3 | Private-repo path: verify the subscription state first, then choose GitHub Pro, a visibility change, or accepting the residual | C |

**Decision-label hygiene.** The T2 record uses "D4" for two decisions: a
2026-11-22 GitHub Pro decision and the 2026-11-27 security-telemetry item. Use
dated prefixes (`DD-<date>/Dn`) from here on. The 2026-11-22 record itself is
Unverified (no repository record found; Decision Log unreadable).

## 8. Order of work

1. DD-2026-11-27/D1 (T0, no dependencies).
2. OPD-C1 public rulesets (T0, available today, free).
3. OPD-C2 identity model, then OPD-C3 private-repo path. OPD-C3 begins with T0
   reading the subscription state; no purchase follows from this document.
4. GGC-001A A-R1 → A-R2 → A-R3 (T1, on GO).
5. OPD-B1/B2 connector scope (T0; depends on OPD-C2).
6. Full regression (G6) across A and C, with the failure response in §6.1.

## 9. Corrections carried from T1 triage (vs GGC-001 v1.0)

| # | Correction |
|---|---|
| K1 | v1.0 inventoried the ChatGPT connector's tools as the guard's surface. The guard never sees those calls (split into A and B). |
| K2 | "Approval checks `event`, tool uses `action`" is wrong for the guarded surface. P10/P11 deny, and the suite pins `event: APPROVE` → deny. `action` belongs to the connector (B). |
| K3 | Bash rerun is a pinned ALLOW, not unclassified (now OPD-A3). MCP rerun really is unclassified. |
| K4 | DENY on `create_file`/`update_file`/`create_blob`/`create_tree`/`create_commit` is too broad. They are TX-16 on non-protected branches. Moving a ref is the transition to gate. |
| K5 | Branch protection is not "unverified". Non-admin endpoints show it **confirmed absent** (GGC-001C §2). |
| K6 | Only PR #7 touches the transition guard. PRs #2/#5 change the Canon-write gate (`hooks/pre_tool_guard.py`): a separate instrument, out of scope here. |
| K7 | The T2 inventory saw 53 public repositories. 21 private Shadowfox repositories were missing. |
| K8 | Order corrected: platform (C) first, since it is the only common boundary. |
| K9 | Identity collapse added as an explicit design axis (GGC-001C §3). |
| K10 | Connector inventory not frozen: 89 = 48 read + 41 write, but v1.0 names only 39 reads (GGC-001B §2). |
| K11 | An observed check is not automatically a suitable required check. Suitability needs three properties: identity (source app), execution path, and definition integrity (GGC-001C §4.1). |
| K12 | 0 required approvals is platform hardening, not T0-only merge authority. Only identity separation (OPD-C2 Option II) provides that. |
| K13 | The four GitHub MCP server names (`create_repository`, `fork_repository`, `create_gist`, `update_gist`) are in GGC-001A's table, not GGC-001B's. A's table now names its surface. |
| K14 | Branch protection: 26 confirmed absent, 1 not applicable (shadowfox-ai-operating-spec is empty, 0 branches). A 404 is not counted as confirmation. |
| K15 | Probes are recorded per case, against both `main` and PR #7, with states PASS, FAIL or BLOCKED (GGC-001A Appendix A). All are offline hook invocations; none is live-session evidence. |

## 10. Out of scope

- The Canon-write gate (`hooks/pre_tool_guard.py`, PRs #2/#5) and ADR-0001
  (PR #3): separate instruments.
- `agent-codex-os` is PSE and **GATED**. No agent action of any kind there
  without an explicit in-session T0 GO. T0 may apply its ruleset personally.
- Security-alert telemetry (DD-2026-11-27/D4) is linked but not covered here.

## 11. Change log

| Rev | Time (UTC) | Change |
|---|---|---|
| 1 | 2026-11-27T22:43Z | Initial draft under GO C |
| 2 | 2026-11-27 | After T2 review: TX-20 widened (P21a–k); TX-21 added (P26); OPD-C relabelled to the decision order (C1 public, C2 identity, C3 private); OPD-A5 and D1-b added; §6.1 failure response; K11–K12; GGC-001A pinned-inventory requirement; GGC-001B Unverified label; GGC-001C Option II operating model, required-check provenance, subscription step and V8 |
| 3 | 2026-11-27 | After T2 review of rev 2: check suitability split into S1 identity / S2 execution path / S3 definition integrity (GGC-001C §4.1); required checks removed from the baseline until Suitable; smse-engine checks marked suitability pending; branch protection corrected to 26 absent + 1 not applicable; §7.1 script covers all 27 repos and fails closed; R8 opaque-input rule and OPD-A6; per-case probe catalog (37 cases, `main` and PR #7, Appendix A); MCP probes labelled offline; BLOCKED state; A's MCP table names its surface; V9–V11 |

={∆§/π}™
