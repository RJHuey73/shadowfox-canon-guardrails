# Threat model: shadowfox-canon-guardrails

Status: **T2 analysis, `ratified: false`.** Written against starting commit
`26138f888c29086c557451d13034c46e5d8ee003` (PR #2), then updated for the
local reconciliation of PR #2 with Envelope A (option 1c, 2026-11-13). It
describes what this code defends against. It is not a statement of Canon
policy.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Canon Spine tables | Airtable `appVftexD3KJRcdij`: Canon ID Registry `tbltw4Jy0LHWWz5DL`, Session Ledger `tblEZ6ctzSoTBsfCW`, Active Task Queue `tblsVXX2XnhVLWMVE`, T0 Decision Log `tblX88U1VOwmK2fF5` | Live governance state. Decision Log writes *are* the record of T0 authorization. |
| T0-GO marker | `.claude/t0-go.json` (or `T0_GO_MARKER_PATH`) | The only authorization token. Whoever can write it can authorize writes. |
| `AIRTABLE_API_KEY` | MCP server process env | Write capability to the base, bounded only by PAT scope. |

## Actors

- **T0 (human).** Mints markers with `hooks/issue_t0_go.py`. Trusted.
- **Agent session (T1/T2).** Calls tools. Untrusted as an authorizer: the
  agent must never be able to authorize its own writes.
- **Claude Code harness.** Sends the PreToolUse JSON to the hook and acts on
  its exit code. Trusted to send well-formed payloads.
- **Airtable.** Remote; responses are untrusted data.

## Enforcement points

1. `hooks/pre_tool_guard.py` (PreToolUse). Classifies every MCP call as
   read-only (allowed), protected (needs a valid marker; checked, never
   consumed) or unclassified (denied), and checks Bash and file-write calls.
   Exit 2 blocks. **Exit 0 or any other exit code lets the call through**:
   Claude Code treats non-2 exit codes as non-blocking errors, so the hook
   turns malformed input and every internal error into exit 2. It still
   cannot help when the harness does not run it (no hook configured, a
   timeout, a permission-bypass mode).
2. `mcp/lib/airtable-client.js` `requireT0Go()`. The authoritative, consuming
   check inside the four MCP servers. Consumption makes a marker single-use.
3. Code shape. The table ID is a module constant in each server, never tool
   input. `sfx-canon-mcp` imports no write function.

## Threats and what this PR does about each

| # | Threat | Before | Status after reconciliation 1c |
|---|---|---|---|
| T1 | A malformed marker or payload crashes the hook (exit 1), so the call is allowed | **Observed**: top-level JSON list, string `tier`, naive or date-only `issued_at`, non-dict `tool_input`, non-string `command` all crash | All of these block (exit 2). Covered by tests. |
| T2 | Python and JS readers disagree on what a valid marker is, so the hook says allow and the server says deny, or the reverse | **Observed**: 21 of 41 shared fixtures wrong in at least one reader; 18 are Python/JS disagreements | One strict contract, enforced identically. Both implementations run the same fixture file. |
| T3 | A string `scope` substring-matches a table ID in Python | **Observed** | `scope` must be a non-empty list of non-empty strings. |
| T4 | A future-dated `issued_at` extends a marker's life without limit | **Observed** in both | Rejected beyond 60 s of clock skew. |
| T5 | Concurrent `requireT0Go()` calls each consume one marker, giving N writes | **Observed**: 10 parallel in-process calls give 10 successes; 8 synchronized processes give 3–6 | Exclusive lock file (`O_EXCL`) plus atomic rename-write: exactly 1 succeeds, across processes too. |
| T6 | A generic Airtable MCP write to the Decision Log passes with a Tier 1 marker | **Observed** (the hook used kind-based tiers, not scope-based) | Minimum tier is derived from scope everywhere. |
| T7 | A Canon-base Airtable call with a malformed `baseId`/`tableId` (non-string) crashes or skips the hook | **Observed** (crash = fail-open) | Blocks. |
| T8 | Formula injection in `decisionlog_search` via `\"` | **Observed**: backslash not escaped | Backslash escaped first. Read-only impact only. |
| T9 | Replay on hook-only write paths (GitHub, Supabase, generic Airtable MCP, Bash): the hook never consumes, so one marker allows unlimited calls within its TTL | **Observed**, and by design (documented) | **Not changed — authorization-model decision, flagged for T0.** Test pins current behaviour. |
| T10 | The agent mints its own marker: Write/Edit tool or `echo >` to the marker path, or runs `issue_t0_go.py` via Bash | **Observed**: nothing guarded the marker path or the issuer | **Partly mitigated, still open.** The hook denies direct references to the marker file, `T0_GO_MARKER_PATH` and execution of the issuer, and file-write tools targeting the marker (acceptance tests). These are string checks: obfuscated forms pass (`test_known_gaps.py::test_gap_t10_*`), and any route the hook does not see is uncovered. This remains the main unresolved trust assumption; ADR-0001 (PR #3) proposes moving authority out of the agent's reach. |
| T11 | Write-capable tools outside the matcher set: `mcp__Airtable__submit_form`, `revert_action`, plugin-namespaced Airtable tools (`mcp__plugin_airtable_airtable__*`), `mcp__Supabase__execute_sql` and other Supabase mutators, GitHub `create_branch`/`enable_pr_auto_merge`/…, Bash `curl -X PATCH` to the Airtable API | **Observed** (tool names from this environment's live tool list) | **Closed for MCP tools, open for Bash.** Every unclassified MCP tool is denied (owner policy), so the listed tools block even with a marker; a mutating HTTP call naming a Canon table or base needs a marker. Still open and pinned: Bash routes that name no protected surface (a URL in a variable, the `gh` CLI), and anything that holds a write credential outside the hook. |
| T12 | Undecodable stdin to the hook is allowed | Documented design choice | **Closed (owner decision).** Empty, non-UTF-8, non-JSON and non-object input deny with exit 2 and a coded diagnostic. |
| T13 | An Airtable write to a non-Canon base passes the hook without a marker | **Observed** ("not this hook's concern") | **Closed (owner decision).** Denied as unclassified, even with a marker naming that base. A write whose base cannot be identified (e.g. `create_base`) is denied as invalid input. |

## What a marker does and does not prove

An unsigned marker file proves only that some process able to write the
marker path wrote it. It does **not** prove human authorization, and adding
deny rules (hook matchers on the path or the issuer) would not change that:
deny rules narrow which tools an agent can use, they are not an identity
boundary, and they fail open whenever the harness does (a crash, a timeout,
a session started without the hooks). Human-only issuance needs a boundary
the agent's OS identity cannot cross; that design is being proposed
separately as an ADR and is not part of this change. Tests that pin these gaps are in `tests/python/test_known_gaps.py`
(marked `known_gap`) and are kept apart from the security acceptance tests.

## Trust assumptions that remain

- The agent cannot write the marker file or run the issuer (T10). The hook
  denies the direct forms on a best-effort basis; nothing in this repo
  enforces it against obfuscation or routes the hook does not see.
- `decision_id` is free text and is not checked against the Decision Log.
- `ttl_seconds` has no upper bound.
- The marker is consumed before the Airtable request runs. A failed write
  burns the marker (fail-closed, and the human re-mints).
- A stale lock file left by a crashed server blocks further writes until a
  human removes it (fail-closed).
- PAT scope is the real outer boundary. The code cannot enforce per-table
  PAT scoping.
- Field IDs in the servers are not verified against the live schema. Tests
  mock all network traffic.
