# shadowfox-canon-guardrails

Claude Code governance scaffold for Shadowfox OS: `PreToolUse` hooks plus a set
of narrow, single-table MCP servers for the Canon Spine (Airtable
`appVftexD3KJRcdij`). Built under work order **Phases 2a/3a/4** (T0=GO
2026-09-03, unverified against T0 Decision Log at time of writing — see
`PROVENANCE.md`).

## Provenance — read before trusting any file here as a "port"

This repo's original brief was to **extend** three pre-existing files
(`pre-tool-guard.py`, `sfx-canon-mcp.js`, `sfx-session-mcp.js`) reportedly
sitting in a 2026-06-09 scaffold (`sfx-scaffold-v1.2.zip`, Canon v9.50.0
header). **That original source was never actually delivered to the session
that wrote this code** — every attempted handoff (local paths, `/mnt/attach`,
`/mnt/user-data/outputs`, a pasted "files received" claim) resolved to either
an empty filesystem check or a prose description with no raw bytes attached.

So: everything in `mcp/sfx-canon-mcp.js` and `mcp/sfx-session-mcp.js` is a
**fresh implementation of a described design pattern** (read-only-by-code-shape;
write-scope hardcoded to one table), not a verified extension of specific
prior code. `mcp/sfx-atq-mcp.js`, `mcp/sfx-decisionlog-mcp.js`, and the T0-GO
marker mechanism in `hooks/` are wholly new — no prior-art claim at all.
`hooks/pre_tool_guard.py` is likewise a fresh implementation of a described
Bash-guard pattern, not a patch to unseen original source.

If the real original files ever surface, diff them against this repo before
assuming parity. Don't cite this repo as evidence of what the original
scaffold contained.

## What's here

| Path | Purpose |
|---|---|
| `mcp/sfx-canon-mcp.js` | Read-only Canon ID Registry access. No write verb exists in this file — least-privilege by code shape. |
| `mcp/sfx-session-mcp.js` | Write-scoped to Session Ledger (`tblEZ6ctzSoTBsfCW`) only. Table ID is a module constant, never a tool parameter. |
| `mcp/sfx-atq-mcp.js` | Write-scoped to Active Task Queue (`tblsVXX2XnhVLWMVE`) only. New — closes gap #1 from the 2026-09-03 session review. |
| `mcp/sfx-decisionlog-mcp.js` | Write-scoped to T0 Decision Log (`tblX88U1VOwmK2fF5`) only. New — closes gap #1. |
| `mcp/lib/airtable-client.js` | Shared HTTP + T0-GO-check helper. Table/base IDs are always passed in by the *caller's* hardcoded constants, never taken from tool input — this is what keeps the shared code from becoming a "write to any table" backdoor. |
| `hooks/pre_tool_guard.py` | `PreToolUse` hook. Bash-surface regex guard (destructive commands, named Canon/Supabase surfaces — now including ATQ + Decision Log) **plus** MCP tool-name matching, so non-Bash write surfaces (Airtable MCP, `gh`-equivalent GitHub MCP calls, Supabase `apply_migration`) are covered too — closes gap #4. |
| `hooks/issue_t0_go.py` | Human-run CLI that mints a single-use, TTL-scoped GO marker. **Never invoke this from an agent session** — it exists specifically so the marker can only originate from a human at a keyboard. |
| `config/settings.json.example` | Example `.claude/settings.json` wiring showing the hook matchers, including the non-Bash MCP tool names. |

## The T0-GO marker — closes gap #2 (no in-path enforcement)

Every write tool in every server here calls `requireT0Go(tableId, { minTier })`
before touching the network. The check is fail-closed:

- No marker file (`.claude/t0-go.json` in the consuming session's working
  directory, gitignored) → blocked.
- Marker's `scope` doesn't list the target table ID → blocked.
- Marker's `tier` is below what the write requires → blocked (see below).
- `issued_at + ttl_seconds` has elapsed → blocked.
- Marker already `consumed` → blocked.

A successful check marks the marker consumed, so it can't be replayed. This
is deliberately **not** a standing flag — that would just be a new
bypassable checkbox, the exact weakness this was built to close.
`issue_t0_go.py` is the only writer of that file, and it's a human-run
script, never something a session should be able to invoke on itself.

**Two tiers, adopted 2026-09-05.** Session Ledger and ATQ writes are Tier 1
(operational) — the default. `decisionlog_create_entry` requires Tier 2
(governance) explicitly; a Tier 1 marker never satisfies it, even scoped
correctly, and tier is never inferred upward. This exists because Decision
Log is different in kind from the other three tables: writing to it doesn't
just record operational state, it *is* the record of T0 authorization —
gating it behind the same casual marker used for an ATQ status update was a
real circularity, not just an aesthetic one. Mint with `--tier 2` when
that's genuinely what's happening; the default stays 1 so operational
writes don't silently get treated as heavier than they are.

This is a v1: the marker's `decision_id` field is not live-validated against
the actual T0 Decision Log (that would mean embedding Airtable credentials
inside the hook process — a new secret-handling surface, and a call for T0,
not defaulted here). Treat the free-text `decision_id` as a paper trail, not
a cryptographic guarantee.

### Marker contract (shared by both readers)

`hooks/pre_tool_guard.py` and `mcp/lib/airtable-client.js` enforce the same
rules, pinned by `tests/fixtures/marker_cases.json` (both suites run it):
top-level JSON object; `decision_id` non-empty string; `scope` non-empty list
of non-empty strings; `tier` integer 1 or 2 (default 1); `issued_at`
ISO-8601 with an explicit offset, at most 60 s in the future;
`ttl_seconds` positive integer; `consumed` boolean (default false). Anything
else is refused. Consumption in `requireT0Go()` holds an exclusive
`<marker>.lock` file for the read-check-consume step, so concurrent writes
(including across the four servers) consume one marker once. A lock left by a
crashed server blocks writes until a human deletes it.

See `docs/THREAT-MODEL.md` for what is and is not defended, including
open trust assumptions.

## Tests

Offline: Airtable is answered by `tests/js/fetch-mock.mjs`, markers live in
temp directories, and no credential is needed.

```bash
npm ci && npm test                  # node:test — marker contract + MCP tool handlers over stdio
pip install pytest
python3 -m pytest tests/python -q   # hook entrypoint + marker contract
```

## Field IDs, not names

All Airtable field references use `fld...` IDs (matching the convention used
throughout the 2026-09-03 session's own live queries), not human-readable
names — robust to renames. **Not execution-tested against a live base** —
verify field IDs against current schema (`list_tables_for_base`) before first
real use.

## Setup

```bash
npm install
cp .env.example .env   # set AIRTABLE_API_KEY
```

Wire hooks into a consuming repo's `.claude/settings.json` — see
`config/settings.json.example`.

## What this repo does not do

- No live write has ever been executed against the real Canon Spine from this
  code. Build/test against a mock or staging base, per the work order's own
  constraint.
- Does not decide where it gets consumed from (own-copy vs. submodule vs.
  sync) — that's presented as a tradeoff to T0 in the Phase 3a handback, not
  decided here.
