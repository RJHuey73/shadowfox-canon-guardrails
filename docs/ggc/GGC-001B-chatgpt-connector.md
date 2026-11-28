# GGC-001B — ChatGPT GitHub connector enforcement

> **DRAFT rev 3 · T1 · `t0_ratified: false` · no execution authority.** Frame,
> taxonomy (TX-*) and rules (R1–R7) are in [README](README.md).

```yaml
provenance_binding:
  binding_id: PB-GGC-001B-20261127          # local label, not a Canon ID
  source_tier: T1
  t2_source: >-
    GGC-001 v1.0 §4–§5 tool lists and the A/B/C response (89/48/41 counts,
    family breakdown), ChatGPT GitHub connector session, 2026-11-27.
  t1_verified: false                         # the connector surface is not observable from T1
  t0_ratified: false
  canon_refs: []
  session_ref: https://claude.ai/code/session_01XUDqLzF4mEWTvnGJk1FhbV
  created_at: "2026-11-27T22:43:33Z"
  notes: Tool names and counts are T2-reported. T1 checked internal consistency only.
trust_state:
  current_state: PROVISIONAL
```

## 1. Structural fact

Connector calls run inside ChatGPT. They never pass through a Claude Code
hook, so **GGC-001A coverage of this surface is zero by construction.** That
is architecture, not a gap a patch can close. Do not design this instrument
as "extend the guard".

Enforcement levers for this surface:

| Lever | Enforced by | Available now | Status |
|---|---|---|---|
| L1 App installation scope (which repositories the connector's GitHub App can reach) | GitHub | Yes (T0, GitHub settings) | Current scope Unverified |
| L2 Platform rules (GGC-001C) | GitHub | Public repos: yes. Private repos: plan-gated | Confirmed absent |
| L3 Separate identity for agents (GGC-001C Option II) | GitHub | Needs a T0 decision (OPD-C2) | Not in place |
| L4 Connector-side controls (read-only mode, confirmation before writes) | ChatGPT | Unknown | Unverified that it exists |
| L5 Operator policy and monitoring | Procedure | Yes | **Not enforcement** (R6) |

## 2. Inventory (T2-reported · Unverified · not frozen)

| Measure | Value | Note |
|---|---|---|
| Total tools | 89 | T2-reported |
| Read / retrieval | 48 | GGC-001 v1.0 §5 names only **39**: 9 are unaccounted for |
| Write-capable | 41 | The family sums reconcile: 6 + 8 + 10 + 8 + 2 + 7 |
| Independent recount | 89 total, 41 write | T2 re-enumerated the live connector on 2026-11-27 and reconciled the 41 with §3's families. Argument schemas and HTTP endpoints are still outstanding, so G1 stays open. |
| Citation given | `https://github.com/RJHuey73` | A profile page, **not** an inventory |

**G1 requirement:** an export captured from the connector itself, with a
timestamp, listing for every tool its name, argument schema, HTTP method and
endpoint, and read/write class. The 9-tool difference must be resolved. A
read classification holds only if the underlying HTTP method is read-only.
Until that export is reconciled, nothing here or in a downstream document
may label the inventory, or any mapping derived from it, as verified.

## 3. Write-capable tools → TX class → enforcing lever

Names as reported in GGC-001 v1.0. "Field-dependent" means the TX class
comes from argument values, per R1. This table lists connector tools only. The
GitHub MCP server tools in GGC-001A A-R3 (for example `create_repository` or
`create_gist`) belong to a different surface.

| Family | Tool | TX | Lever that can stop it |
|---|---|---|---|
| PR (6) | `merge_pull_request` | 01 | L2+L3, or L1 removal |
| | `enable_auto_merge` | 01 | L2+L3 (auto-merge still honours rules), or L1 removal |
| | `update_pull_request` | Field-dependent: 03 (closed) / 04 / 15 (base, title, body) | **Role only** (L1/L3 with Read). Rules don't govern close. |
| | `mark_pull_request_ready_for_review` | 04 | Role only |
| | `convert_pull_request_to_draft` | 04 | Role only |
| | `create_pull_request` | 15 | Role only |
| Reviews (8) | `add_review_to_pr` (`action: APPROVE`) | 02 | L3: required approval from a separate identity. Under a single identity, an approval by `RJHuey73` *is* T0's approval as far as GitHub can tell. |
| | `dismiss_pull_request_review` | 02 | L2 (stale-review / last-push rules) + L3 |
| | `request_pull_request_reviewers`, `remove_pull_request_reviewers` | 14 | Role only |
| | `resolve_review_thread`, `unresolve_review_thread` | 14 (gating if "require conversation resolution" is on) | Role only |
| | `reply_to_review_comment`, `update_review_comment` | 14 | Role only |
| Issues (10) | `update_issue` | Field-dependent: 03 / 15 | Role only |
| | `add_comment_to_issue` | 14; a bot command takes the class of its effect (01/03) | Role only; a Dependabot merge still honours L2 |
| | `create_issue` | 15 | Role only |
| | `update_issue_comment`, `lock_issue_conversation`, `unlock_issue_conversation`, `add_issue_assignees`, `remove_issue_assignees`, `add_issue_labels`, `remove_issue_label` | 14 | Role only |
| Files / Git (8) | `create_file`, `update_file`, `delete_file` | Field-dependent: 05 (default/protected) / 16 | L2 |
| | `create_blob`, `create_tree`, `create_commit` | 16 (no ref moves) | — (not gated) |
| | `create_branch` | 16, or 05 for a protected name | L2 |
| | `update_ref` | 05 / 06 (protected or forced), else 16 | L2 |
| Workflow (2) | `rerun_workflow_job`, `rerun_failed_workflow_run_jobs` | 08 | Role only |
| Labels / reactions (7) | `label_pr`, `add_reaction_to_issue_comment`, `add_reaction_to_pr`, `add_reaction_to_pr_review_comment`, `remove_reaction_from_issue_comment`, `remove_reaction_from_pr`, `remove_reaction_from_pr_review_comment` | 14 | Role only |

### Consequence for parity (R3)

With write access, this surface can make TX-03, TX-04, TX-08, TX-14 and
TX-15 transitions **whatever rules exist**. Branch rules do not govern them;
only the role of the identity the connector acts as does. R3 then allows only
two outcomes:

1. **OPD-B1 = no write access.** Read-only use. L1 scoped to the
   repositories T2 audits, and the connector acts under an identity with the
   Read role (needs OPD-C2 Option II).
2. **OPD-B1 = write access needed.** TX-03/04/08 on this surface are recorded
   as accepted residual risk, with L2+L3 governing TX-01/02/05/06.

## 4. Requirements

| ID | Requirement | Acceptance |
|---|---|---|
| B-R1 | Freeze the inventory (G1) | Export as §2. Read classification backed by the HTTP method. |
| B-R2 | Every write tool mapped to TX and lever (G2) | §3 table complete for the exported set, not the reported one |
| B-R3 | Decide write need (OPD-B1) | T0 disposition recorded |
| B-R4 | Minimize installation scope (OPD-B2) | T0 records the connector app's repository selection and permission set from GitHub settings (Installed GitHub Apps). The list matches the disposition. |
| B-R5 | Attribution for monitoring | Identify the `performed_via_github_app` slug that connector-made events carry (Unverified; no known connector-made event yet). Monitoring only (R6). |
| B-R6 | Connector-side controls | Check whether L4 exists. If it does, record its setting. It never substitutes for L1–L3. |

## 5. What this instrument cannot do

- Produce a "green" result from Claude Code tests (R4).
- Prevent a merge on an unprotected branch through policy alone (R6/R7).
- Establish the connector's permission set from T1. That is a GitHub
  settings read only T0 can make.

## 6. Open decisions

OPD-B1 (write need), OPD-B2 (installation scope). Both depend on OPD-C2. See
[README §7](README.md#7-open-t0-decisions-consolidated).

={∆§/π}™
