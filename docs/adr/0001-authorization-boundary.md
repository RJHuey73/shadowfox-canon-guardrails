# ADR-0001: Authorization boundary for Canon Spine writes

- **Status:** Proposed. T2 draft, `ratified: false`. No Canon ID is assigned; I asserted none.
- **Repo:** `RJHuey73/shadowfox-canon-guardrails`. Committed for review on T0 approval (G2). Committing it does **not** ratify it.
- **Context commit:** PR #2 head `993677eb07ca259ae78a758f9cfb8d803045b710`.
- **Decides:** where the authority to perform a Canon Spine write lives, and what has to hold before one happens.

## 1. Context

Today a "T0 GO" is an **unsigned JSON file** (`.claude/t0-go.json`) in the agent session's working directory, checked by:
- a PreToolUse hook (`hooks/pre_tool_guard.py`), which is advisory and never consumes it;
- the four MCP servers (`requireT0Go()`), which consume it.

The Airtable write credential (`AIRTABLE_API_KEY`) sits in the MCP server processes, which run as the same OS user as the agent session.

Guardrails PR #2 (not yet merged) hardened the parsing and consumption of that file. What it did not change, and what PR #2 pins in `tests/python/test_known_gaps.py`, is this:

| Gap | Observed fact |
|---|---|
| T10 | The agent can write the marker file (Write/Edit tools, `echo >`) or run `issue_t0_go.py` itself. |
| T9 | On hook-only routes (GitHub, Supabase, generic Airtable MCP, Bash) a marker is never consumed. |
| T11 | Write-capable tools sit outside the matchers: `submit_form`, `revert_action`, plugin-namespaced Airtable tools, `Supabase execute_sql`, some GitHub writes, `curl -X PATCH`. |
| T12 | Undecodable hook input is allowed. Claude Code also treats a hook timeout or any non-2 exit as non-blocking. |
| — | TTL is unbounded. |

**The underlying problem is that whoever holds the write credential can write.** While the credential sits inside the agent's OS identity, no file format, signature check, or deny rule inside that identity can prove a human approved a write. The agent can skip the check and call the API with the key.

**What this ADR does not claim.** Deny rules (hook matchers on the marker path or the issuer) and unsigned marker files are **not** treated as proof of human-only authorization anywhere in this ADR. They are defense in depth: they lower the chance of an accidental write. They are not an identity boundary.

## 2. Decision

Move write authority out of the agent's OS identity into a **minimal local broker** that runs under a **separate OS account**, and make it the only holder of any credential able to mutate the Canon Spine.

### Requirements (each is a design constraint the implementation must satisfy)

**R1. Human-only issuance, outside agent authority.**
- Approvals are created only through a channel the agent's OS identity cannot use.
- The broker accepts an approval only on its approval socket, and only when the peer's kernel-reported UID (`SO_PEERCRED` on Linux, `getpeereid`/`LOCAL_PEERCRED` on macOS) belongs to the human approver account. That account is distinct from the agent's account and never shared with it.
- The agent's account cannot read the broker's key, state, or credential files (owner `sfx-broker`, mode `0600`, agent not in the group, no sudo).
- Optional extra step: a local OS authentication prompt on the approver side (polkit / macOS LocalAuthentication). This is extra assurance, not the boundary.

**R2. Request-bound, single-use approval.**
- An approval binds one exact request: route, operation (POST/PATCH), base, table, record ID (or none), the SHA-256 of the canonical JSON body, a broker-generated nonce, and an expiry.
- The human approves *that* digest after seeing the rendered request. It does not cover a table, a scope, or a time window.
- The broker executes the write only if the request it receives hashes to an approved, unexpired, unconsumed digest. It marks the approval consumed in the **same transaction** that records execution (SQLite, `UNIQUE(nonce)`, `BEGIN IMMEDIATE`).
- Replaying a request, or changing any byte of it, fails.

**R3. One authoritative consumer per write route.**
- Each route (Session Ledger, ATQ, Decision Log, and any future Canon write) has exactly one executor: the broker.
- The agent-side MCP servers become thin clients. They submit a request over the broker's request socket and wait for it to be approved and executed. They hold **no** write credential, and `airtableWrite()` is removed from agent space.
- The hook stays as a fast user-visible pre-check, labelled advisory. Nothing depends on it for safety.
- No route can be authorized by two independent readers that might disagree. That is the T2 class of bug, made structural.

**R4. Alternate mutation capabilities are denied, not only unmatched.**
- Any Canon-base credential available to the agent's identity is **read-only** (an Airtable PAT with `data.records:read` only).
- The generic Airtable MCP, plugin-namespaced Airtable servers, and any `curl` path then *cannot* write, whatever the hook matches.
- The same rule applies to the other protected surfaces. Supabase: no service-role key in agent environments; migrations only through `apply_migration` from a human-approved path. GitHub: branch protection on default branches.
- Deny rules and matchers remain as defense in depth, and are documented as such.
- **Cloud sessions** (this one included) run as root in an ephemeral container, where no separate OS identity is possible. They must never receive a Canon write credential at all.

**R5. Fail-closed hook and harness behaviour.**
- Broker: default deny. Any error, a missing approval, a broker that is down, a schema mismatch, or a clock skew beyond 60 s all mean no write.
- Hook: exits 2 on any internal error once PR #2 merges. Because the harness treats timeouts, crashes, sessions without hooks, and permission-bypass modes as non-blocking, **no requirement may rely on the hook running**. R1 to R4 hold even if the hook never runs.

**R6. Maximum TTL and human-controlled recovery.**
- Approvals expire after at most 15 minutes. The ceiling lives in broker configuration owned by `sfx-broker`, so the agent cannot raise it.
- Pending requests expire after 60 minutes.
- Recovery commands run only as the approver account: `revoke <nonce>`, `revoke-all`, `rotate-credential`, `export-audit`.
- The broker keeps an append-only audit log in its own state: request digest, approver UID, timestamps, Airtable response ID.
- A broker crash leaves no lock to clean up: SQLite transactions replace the marker lock file.

### Minimal broker shape (the recommendation)

- One process, about 300 lines of Python standard library, running as `sfx-broker` via a systemd user unit (Linux) or a launchd agent (macOS).
- Two Unix sockets:
  - **`request.sock`** (agent account can connect): `submit(request) -> {request_id, digest}` and `status(request_id)`.
  - **`approve.sock`** (approver account only, enforced by peer-UID check *and* socket file permissions): `list()`, `show(request_id)` returns the rendered request and digest, `approve(request_id, digest)`, `deny(request_id)`.
- On approval, the broker performs the HTTPS write itself, using the only write credential, which it reads from its own `0600` file.
- **Explicitly out of scope:** network listeners, multi-host operation, Airtable-side approval flows, and any Canon policy logic beyond binding approvals to requests.

## 3. Alternatives considered

| Option | Why not sufficient alone |
|---|---|
| Status quo plus deny rules on the marker path and issuer | Deny rules sit in the agent's identity, and the harness fails open past them (timeouts, no hooks, bypass modes). The write credential is still in agent space. |
| HMAC-signed markers | The verifier needs the same secret, so whoever can verify can also mint. And the credential is still in agent space. |
| Ed25519-signed markers (verify-only key in agent space) | This removes self-minting, but not "call Airtable directly with the key". It only works once the credential has moved out, and at that point the broker is the simpler design. |
| Airtable-native approvals (automations, interfaces) | External, harder to test offline, and it ties the policy to one vendor. Could complement the broker later. |
| Hardware key per write | Strong. Can be layered onto R1 as the approver-side step. On its own it doesn't address where the credential lives. |

## 4. Consequences

- **Good:**
  - The agent can no longer write the Canon Spine without a human approving the exact request.
  - The T9, T10, T11 and T12 gaps stop mattering for safety, because they reduce to "the agent's tools fail".
- **Cost:**
  - One more process and one more OS account on the human's machine.
  - Writes become two-step (submit, then approve).
  - Cloud and agent-only sessions can no longer write Canon at all, by design.
- **Migration:** the marker file is retired for Canon routes. `issue_t0_go.py` is removed once the broker is live.

## 5. Rollout preconditions (do not start until these hold)

1. **Consumer inventory confirmed by T0.** As of 2026-10-23, a full-tree search of all 53 checkouts available to the authoring session, plus every `.claude/settings*.json` and MCP config in them, found no consumer of these hooks or servers. GitHub code search does not index these private repos, so that result is not evidence of absence. Any local installs on T0's machines have to be listed by T0.
2. **Write PATs inventoried and narrowed.** Every current Canon write-capable credential is listed and scoped. This needs Airtable access, which is currently blocked by the monthly limit.
3. **This ADR ratified** through the Promote-Gate (`Shadowfox-OS-Specification-Repository/docs/promote-gates/`). Until then it is a proposal.

## 6. Verification plan (for the implementation PR, not this ADR)

Offline tests, extending the test harness from PR #2:
- **Approval-socket UID check:** a peer UID other than the approver is refused.
- **Digest binding:** one changed body byte gives a refusal.
- **Single use:** concurrent approve and execute run once.
- **TTL:** the ceiling is enforced.
- **Fail-closed paths:** broker down, malformed request.
- **No write credential in agent space:** a static check that no agent-side module imports a write function, and that the agent-side env has no write PAT.
- Every `known_gap` test is either converted into an acceptance test against the broker or deleted with its gap closed.
