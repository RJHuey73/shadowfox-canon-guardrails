# ADR-0001: Authorization boundary for Canon Spine writes

- **Status:** Proposed. T2 draft, `ratified: false`. No Canon ID is assigned; I asserted none.
- **Repo:** `RJHuey73/shadowfox-canon-guardrails`. Committed for review on T0 approval (G2), amended on T0 review direction of 2026-10-23, and amended again on T0 approval of review findings A–C (time handling, response classification, `REVOKED`). Committing or amending it does **not** ratify it.
- **Context commit:** PR #2 head `993677eb07ca259ae78a758f9cfb8d803045b710`.
- **Decides:** where the authority to perform a **Canon Spine** write lives, and what has to hold before one happens.
- **Scope:** Canon Spine routes only, meaning writes to Airtable base `appVftexD3KJRcdij`. This ADR establishes the proposed boundary for Canon Spine writes. GitHub and Supabase require separate capability inventories and route-specific enforcement decisions.

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

**The underlying problem is that whoever holds the write credential can write.** While the credential sits inside the agent's control, no file format, signature check, or deny rule inside that boundary can prove a human approved a write. The agent can skip the check and call the API with the key.

**What this ADR does not claim:**
- Deny rules (hook matchers on the marker path or the issuer) and unsigned marker files are **not** treated as proof of human-only authorization anywhere in this ADR. They are defense in depth that lowers the chance of an accidental write; they are not an identity boundary.
- This ADR does **not** close any gap for GitHub or Supabase routes. It also does not guarantee *exactly-once* effects on Airtable; see R3.

## 2. Decision

Move Canon Spine write authority into a **minimal local broker**. The broker runs under an OS identity the agent cannot control (§2.1), is the only holder of any credential able to mutate the Canon Spine, and executes only the immutable requests it has itself stored and a human has approved.

### 2.1 Isolation requirement, stated in terms of actual privileges

**Do not provision write credentials where the agent retains root, equivalent privilege, or another path to control the broker.**

A separate account *name* is not sufficient. A deployment qualifies only if **every** item below holds for the agent's OS identity, meaning the account that runs Claude Code and every process it spawns:

| # | The agent identity must NOT be able to… | Typical ways this fails |
|---|---|---|
| P1 | run code as uid 0 or as the broker account | is root; `sudo`, `doas`, `pkexec` or `su` with any rule; a setuid helper it can influence |
| P2 | gain root-equivalent privilege | membership in `docker`, `lxd`, `libvirt`, `disk`, `wheel`/`sudo`/`admin`; `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE` or `CAP_SETUID` |
| P3 | read the broker's credential, key, state DB or config | the files must be owned by the broker account with mode `0600`/`0700`, and the agent must not be in their group |
| P4 | modify what the broker executes | write access to the broker's code, interpreter, `site-packages`, systemd/launchd unit, environment files or socket directory |
| P5 | inspect or signal the broker process | `ptrace` or `/proc/<pid>/mem` access (separate uid plus Yama `ptrace_scope ≥ 1`); sending signals (separate uid suffices) |
| P6 | act as the approver | sharing the approver's login, SSH keys, `tmux`/`screen` sockets, GUI session, or terminal; Claude Code running *as* the approver account |
| P7 | reach the approval channel | `approve.sock` mode `0660` with group = approver only, and the broker additionally checks the peer UID on every call |

Consequences of §2.1:
- **Claude Code must run under its own account**, distinct from the human approver's. Running it as the human's own login makes the agent the approver (fails P6).
- **Cloud and container sessions where the agent is root** (this authoring session included) fail P1. They must never receive a Canon write credential.
- **Verification:** before any write credential is provisioned, the rollout runs the privilege-boundary checks in §6.1 *on the target host* and records the results.

### 2.2 Versioned canonical approval envelope

The broker builds and stores one envelope per write request at submit time. Envelope version 1 (`"envelope_version": "sfx-canon-approval/1"`):

| Field | Type | Rule |
|---|---|---|
| `envelope_version` | string | exactly `sfx-canon-approval/1`; an unknown version is refused |
| `request_id` | string | UUIDv4 generated **by the broker** |
| `route` | string | one of a fixed enum, e.g. `canon.session_ledger.create`, `canon.session_ledger.update`, `canon.atq.create`, `canon.atq.update`, `canon.decision_log.create` |
| `method` | string | `POST` or `PATCH`, derived from `route` (never supplied by the client) |
| `base_id`, `table_id` | string | derived from `route` via the broker's own constants (never supplied by the client) |
| `record_id` | string or null | `^rec[A-Za-z0-9]{14}$`; required for update routes, null for create routes |
| `fields` | object | keys are `fld…` IDs from the route's allow-list; values are JSON strings, numbers, booleans or arrays of strings |
| `submitted_by_uid` | integer | the peer UID of the submitting process |
| `created_at`, `expires_at` | string | RFC 3339 UTC; `expires_at − created_at` ≤ the pending ceiling (60 min) |

- **Canonical form.** RFC 8785 (JSON Canonicalization Scheme) encoding of the whole envelope.
- **Digest.** `request_digest = SHA-256(JCS(envelope))`, shown in full to the approver.
- **Approval record.** Created separately: `{approval_id, request_id, request_digest, approver_uid, approved_at, approval_expires_at}`. `approval_expires_at − approved_at` ≤ 15 minutes.
- **Version changes.** A future `/2` requires a new ADR amendment. A broker never interprets an envelope version it does not know.

### 2.3 Execute only the stored, immutable, approved request

- On `submit`, the broker validates the client's input, builds the envelope, stores it, and returns `{request_id, request_digest}`. **The stored envelope is immutable.** Changing anything requires a new request with a new `request_id` and a new approval.
- At dispatch the broker builds the HTTP request **only from the stored envelope**, never from anything the client sends after `submit`. Immediately before reserving dispatch, it recomputes the digest and requires it to equal the approved `request_digest`; a mismatch means storage corruption, and it refuses.
- The client cannot name the base, table, method or URL. Those come from `route`.

### 2.4 At-most-once dispatch and the request state machine

```
PENDING ──approve──▶ APPROVED ──reserve──▶ DISPATCH_RESERVED ──▶ SUCCEEDED
   │                    │                         │
   ├─deny───▶ DENIED    ├─expire──▶ EXPIRED       ├──▶ FAILED_CONFIRMED
   ├─expire─▶ EXPIRED   └─revoke──▶ REVOKED       └──▶ OUTCOME_UNKNOWN ──reconcile──▶ SUCCEEDED | FAILED_CONFIRMED
   └─revoke─▶ REVOKED
```

`DENIED`, `EXPIRED`, `REVOKED`, `SUCCEEDED` and `FAILED_CONFIRMED` are terminal. `OUTCOME_UNKNOWN` is terminal except for the approver-only reconciliation below.

**Atomic local consumption is not the same as an atomic remote effect.**
- What the broker *can* make atomic: approval consumption and dispatch reservation, in one local SQLite transaction (`BEGIN IMMEDIATE`; `APPROVED → DISPATCH_RESERVED`; the row records `dispatch_attempt_id` and `reserved_at`). That transaction commits durably (`synchronous=FULL`) **before** any network byte is sent.
- What it *cannot* make atomic: the Airtable HTTPS write. That happens in another system after the commit.
- So the guarantee is **at-most-once dispatch**, not exactly-once effect.

**State transition rules:**
- `DISPATCH_RESERVED` can be entered only from `APPROVED`, exactly once per `request_id` (`UNIQUE(request_id)` on the dispatch table). The single HTTPS request is sent only after that commit.
- **`SUCCEEDED`:** a 2xx response with a record ID was received and committed, along with the record ID.
- **`FAILED_CONFIRMED`:** a response was received that is a *documented rejection with no side effect*, meaning the vendor documents that status as a refusal to process the request. The candidate set is 400, 401, 403, 404, 413, 422 and 429. Each code stays in the set only if, at implementation time, Airtable's current API documentation still describes it as a rejection that applies no change. A code that can't be confirmed that way is classified `OUTCOME_UNKNOWN` instead. The response is stored.
- **`OUTCOME_UNKNOWN`** covers every other case:
  - a timeout or connection error after the request was sent;
  - any 5xx;
  - a 2xx whose body can't be parsed;
  - any status not in the confirmed-rejection set, or any response whose side effect is ambiguous;
  - a broker crash or restart while `DISPATCH_RESERVED`. On startup, every `DISPATCH_RESERVED` row without a terminal state becomes `OUTCOME_UNKNOWN`.
- **No automatic retry, ever.** A retry is a new request: new `request_id`, new digest, new human approval.

**Revocation (`REVOKED`) and its ordering against reservation.**
- `revoke` applies only to requests in `PENDING` or `APPROVED`. It moves them to the terminal state `REVOKED`, which is recorded separately from `EXPIRED`, so the audit trail shows a human revocation rather than a timeout.
- `revoke` and `reserve` are both single conditional state updates, each in its own `BEGIN IMMEDIATE` transaction:
  - `reserve` is `UPDATE … SET state='DISPATCH_RESERVED' WHERE request_id=? AND state='APPROVED'`;
  - `revoke` is `UPDATE … SET state='REVOKED' WHERE request_id=? AND state IN ('PENDING','APPROVED')`.
- SQLite serialises the two writers, so exactly one of them changes the row. Whichever commits first wins, and the loser sees zero rows changed and reports that.
- **Revocation never cancels a reserved or in-flight write.** Once a request is `DISPATCH_RESERVED`, `revoke` is refused with "already reserved; the write may be in flight", and the state is unchanged. The request ends `SUCCEEDED`, `FAILED_CONFIRMED` or `OUTCOME_UNKNOWN` like any other. `revoke-all` affects only `PENDING` and `APPROVED` requests.
- Because the network send happens only after the `reserve` commit, a request whose revoke committed first is never sent.

**Time handling (approval and pending lifetimes).**
- Lifetimes are enforced so that a wall-clock rollback cannot extend them:
  - while the broker process runs, elapsed time since approval (and since submission) is measured with a monotonic clock (`time.monotonic()`, i.e. `CLOCK_MONOTONIC`), which wall-clock changes don't affect;
  - a request is valid only if **both** the monotonic elapsed time **and** the wall-clock elapsed time (`now − approved_at`, `now − created_at`) are within the ceiling. A forward wall-clock jump can therefore only shorten validity, and a rollback can't lengthen it within a process.
- **Restart.** A monotonic clock doesn't survive a restart, so elapsed time since approval can no longer be proven. On startup the broker moves every `APPROVED` request to `EXPIRED` and every `PENDING` request to `EXPIRED` (fail closed), in the same startup transaction that moves `DISPATCH_RESERVED` rows to `OUTCOME_UNKNOWN`. The human re-approves after a restart.
- **What this does not solve.** A check such as "refuse if `now < created_at`" catches only rollbacks to before creation; a rollback that stays after `created_at` passes it. Wall-clock checks alone cannot detect rollback, which is why validity also depends on in-process monotonic time and is reset on restart. A rollback while the broker is stopped is covered only by the restart rule.

**`OUTCOME_UNKNOWN` reconciliation (approver-only).**
1. The broker offers a read-only `reconcile <request_id>` that queries the target table:
   - *update routes:* read `record_id` and compare each envelope field with the stored value;
   - *create routes:* search for records whose envelope fields all match and whose `createdTime` falls in `[reserved_at, reserved_at + 10 min]`. This is exact only if the table has a dedicated `broker_request_id` field to match on. Adding that field is a schema change that needs a separate T0 decision. Without it, a create match is a candidate list for the human, not proof.
2. The approver records the outcome with `resolve <request_id> succeeded <record_id>` or `resolve <request_id> failed`, plus a free-text reason. The resulting state is `SUCCEEDED` or `FAILED_CONFIRMED`, flagged `reconciled=true`, and the evidence goes into the audit log.
3. An `OUTCOME_UNKNOWN` request is never re-dispatched.

### 2.5 Requirements (each is a design constraint the implementation must satisfy)

**R1. Human-only issuance, outside agent authority.**
- Approvals are created only through `approve.sock`, and only by a peer whose kernel-reported UID (`SO_PEERCRED` on Linux, `getpeereid`/`LOCAL_PEERCRED` on macOS) is the configured approver UID.
- The deployment meets §2.1 P1–P7.
- Optional: a local OS authentication prompt on the approver side (polkit / macOS LocalAuthentication). This adds assurance but is not the boundary.

**R2. Request-bound, single-use approval.**
- An approval binds exactly one `request_digest` (§2.2) of one immutable stored envelope (§2.3). It does not cover a table, a scope or a time window.
- It is consumed by the `APPROVED → DISPATCH_RESERVED` transition (§2.4) and can never be consumed twice.

**R3. At-most-once dispatch with explicit unknown outcomes.** As specified in §2.4. The broker never reports `SUCCEEDED` without a received 2xx and a record ID, or a reconciliation by the approver.

**R4. One authoritative consumer per Canon route.**
- Each Canon route has exactly one executor, the broker.
- Agent-side MCP servers become thin clients: they `submit` and poll `status`. They hold **no** write credential, and `airtableWrite()` is removed from agent space.
- The hook stays as an advisory pre-check, and nothing depends on it.

**R5. Alternate Canon mutation capabilities are denied, not only unmatched.**
- Any credential for base `appVftexD3KJRcdij` reachable from the agent's identity is **read-only**: an Airtable PAT with only `data.records:read` and `schema.bases:read`.
- The generic Airtable MCP, plugin-namespaced Airtable servers and `curl` then *cannot* write to the Canon Spine, whatever the hook matches.
- This closes T9 and T11 **for Canon routes only**. GitHub and Supabase require separate capability inventories and route-specific enforcement decisions; their T9/T11 entries stay open.

**R6. Fail closed, independent of the hook and the harness.**
- The broker denies by default. Any of these means no dispatch: a validation error, a missing or expired approval, a digest mismatch, an unknown envelope version, a lifetime that the time-handling rules in §2.4 cannot prove is unexpired (including any approval that predates a broker restart), or the broker being down.
- Because the harness treats hook timeouts, crashes, sessions without hooks and permission-bypass modes as non-blocking, **no requirement may rely on the hook running**.

**R7. Maximum TTL and human-controlled recovery.**
- Approval lifetime is ≤ 15 min, and pending request lifetime is ≤ 60 min. Both ceilings live in configuration owned by the broker account (§2.1 P4).
- Approver-only commands: `revoke <request_id>` (from `PENDING`/`APPROVED` only; see §2.4), `revoke-all`, `reconcile`, `resolve`, `rotate-credential`, `export-audit`.
- Lifetimes are measured as specified under "Time handling" in §2.4. A restart expires every approval that isn't yet reserved.
- The audit log is append-only and kept in the broker's own state. It records every state transition, with digest, UIDs, timestamps and the Airtable response status or record ID.

### 2.6 Minimal broker shape (the recommendation; not implemented by this ADR)

- One process, about 300–400 lines of Python standard library, running as the broker account via a systemd unit (Linux) or a launchd daemon (macOS). Its code, unit and config are owned by root or the broker account and are not writable by the agent (§2.1 P4).
- Two Unix sockets:
  - **`request.sock`** (agent may connect): `submit(route, record_id, fields) → {request_id, request_digest}` and `status(request_id)`.
  - **`approve.sock`** (approver only, by file mode **and** peer-UID check): `list`, `show(request_id)` (rendered envelope plus full digest), `approve(request_id, request_digest)`, `deny`, `revoke`, `reconcile`, `resolve`.
- State is a SQLite DB in WAL mode with `synchronous=FULL`, owned by the broker account.
- **Explicitly out of scope:**
  - network listeners and multi-host operation;
  - GitHub and Supabase routes;
  - Airtable-side approval flows;
  - any Canon policy beyond binding approvals to requests.

## 3. Alternatives considered

| Option | Why not sufficient alone |
|---|---|
| Status quo plus deny rules on the marker path and issuer | Deny rules sit in the agent's identity, and the harness fails open past them (timeouts, no hooks, bypass modes). The write credential is still in agent space. |
| HMAC-signed markers | The verifier needs the same secret, so whoever can verify can also mint. And the credential is still in agent space. |
| Ed25519-signed markers (verify-only key in agent space) | This removes self-minting, but not "call Airtable directly with the key". It only helps once the credential has moved out, and at that point the broker is the simpler design. |
| Broker that retries on timeout ("exactly-once") | Airtable writes are not idempotent and Airtable offers no idempotency key, so a retry after an ambiguous timeout can duplicate a create. That is rejected in favour of at-most-once with `OUTCOME_UNKNOWN`. |
| Airtable-native approvals (automations, interfaces) | External, harder to test offline, and it ties the policy to one vendor. Could complement the broker later. |
| Hardware key per write | Strong. Can be layered onto R1 as the approver-side step. On its own it doesn't address where the credential lives. |

## 4. Consequences

- **Good:** on a deployment that meets §2.1:
  - the agent can no longer write the Canon Spine without a human approving the exact stored request;
  - each approval leads to at most one dispatch;
  - ambiguous outcomes are surfaced instead of being retried.
- **Not changed:** GitHub and Supabase routes. Their gaps remain open until their own inventories and decisions exist.
- **Cost:**
  - One more process and two more OS accounts (broker and agent), separate from the human approver.
  - Writes become two-step (submit, then approve).
  - Some writes end as `OUTCOME_UNKNOWN` and need manual reconciliation.
  - Cloud and root-agent sessions can no longer write Canon at all, by design.
- **Migration:** the marker file is retired for Canon routes, and `issue_t0_go.py` is removed once the broker is live on every consumer.

## 5. Rollout preconditions (do not start until these hold)

1. **Consumer inventory confirmed by T0.** As of 2026-10-23, a full-tree search of all 53 checkouts available to the authoring session, plus every `.claude/settings*.json` and MCP config in them, found no consumer of these hooks or servers. GitHub code search does not index these private repos, so that result is not evidence of absence. Local installs on T0's machines have to be listed by T0.
2. **Canon write credentials inventoried and narrowed.** This needs Airtable access, which is currently blocked by the monthly limit.
3. **§6.1 privilege-boundary checks pass on each target host.** They are recorded before any write credential is provisioned there.
4. **A schema decision on `broker_request_id`** for exact create reconciliation (§2.4), or explicit acceptance that create reconciliation is candidate-based.
5. **This ADR ratified** through the Promote-Gate (`Shadowfox-OS-Specification-Repository/docs/promote-gates/`). Until then it is a proposal.

## 6. Acceptance tests (for the implementation PR, not this ADR)

All offline. Airtable is replaced by a local mock HTTPS server that counts the requests it receives.

### 6.1 Privilege boundary

These run in CI on Linux with three throwaway accounts (`sfx-broker`, `sfx-approver`, `sfx-agent`) created by the test, and as a read-only preflight script on a real target host:
- **Credential and state:** as `sfx-agent`, reading the credential file, the state DB and the config gives `EACCES`. Writing the broker code, unit, config and socket directory also gives `EACCES`.
- **Approval socket:** as `sfx-agent`, connecting to `approve.sock` gives `EACCES`. With the file mode deliberately loosened, the broker still refuses on the peer-UID check, and nothing is approved.
- **Process isolation:** as `sfx-agent`, `kill -0 <broker pid>` gives `EPERM`. `ptrace`/`/proc/<pid>/mem` access fails (asserted when Yama `ptrace_scope ≥ 1`; the test reports it as unverified otherwise).
- **Preflight:** it fails if `sfx-agent` is uid 0 or has any sudo rule (`sudo -n -l`). It also fails on membership in `docker`/`lxd`/`libvirt`/`disk`/`wheel`/`sudo`/`admin`, effective capabilities other than none, or Claude Code running as the approver UID.
- **Approver path:** as `sfx-approver`, `approve` succeeds only with the exact full digest. A truncated or altered digest is refused.

### 6.2 Envelope and immutability

- JCS canonicalization is deterministic across key order, Unicode escaping and number formatting.
- An unknown `envelope_version` is refused.
- A client-supplied base, table, method or URL is ignored or refused.
- A one-byte change in `fields` gives a different digest.
- Corrupting the stored envelope after approval makes dispatch refuse: the digest recheck fails and the mock server receives 0 requests.

### 6.3 At-most-once and crash recovery

The broker is killed with `SIGKILL` at each injected fault point and then restarted:

| Fault point | Expected state after restart | Mock server requests |
|---|---|---|
| after `approve` commit, before reservation | `EXPIRED` (approval can't be proven unexpired after a restart; re-approval needed) | 0 |
| after reservation commit, before send | `OUTCOME_UNKNOWN` | 0 |
| after send, before response | `OUTCOME_UNKNOWN` | 1 |
| after 2xx received, before terminal commit | `OUTCOME_UNKNOWN` | 1 |
| after terminal commit | unchanged terminal state | 1 |

- Restarting twice changes nothing further.
- In no case does the mock server receive a second request for the same `request_id`.
- **Concurrency:** 8 concurrent `dispatch` attempts on one `APPROVED` request give exactly 1 reservation and at most 1 request.
- **Mock responses:**
  - 400, 401, 403, 404, 413, 422 and 429 each map to `FAILED_CONFIRMED` (one case per code), provided the implementation PR cites Airtable's documentation for each as a rejection with no side effect. A code without that citation is tested as `OUTCOME_UNKNOWN` instead;
  - an unlisted status (e.g. 409, 418) maps to `OUTCOME_UNKNOWN`;
  - 500, 503, a timeout after send, and a 2xx with an unparseable body map to `OUTCOME_UNKNOWN`;
  - none of them is retried.
- **Revocation:**
  - `revoke` on `PENDING` or `APPROVED` gives `REVOKED`, the mock server receives 0 requests, and a later `approve`/`dispatch` is refused;
  - `revoke` and `reserve` raced 50 times on fresh `APPROVED` requests: each request ends either `REVOKED` with 0 requests sent, or `DISPATCH_RESERVED` (then a terminal dispatch state) with at most 1 request sent, never both;
  - `revoke` on `DISPATCH_RESERVED`, or on any terminal state, is refused, the state is unchanged, and the in-flight request is not affected;
  - `revoke-all` touches only `PENDING`/`APPROVED`;
  - the audit log distinguishes `REVOKED` from `EXPIRED`.
- **Time handling** (with an injected wall clock and an injected monotonic clock):
  - wall clock set back by 1 h after approval: the approval still expires when monotonic elapsed time reaches the ceiling;
  - wall clock jumped forward past the ceiling: the approval expires immediately (fail closed);
  - restart (new monotonic origin): every `APPROVED` and `PENDING` request becomes `EXPIRED`, and the mock server receives 0 requests;
  - wall clock set back to before `created_at`: refused. The test asserts this is not the only rollback protection: a rollback that stays after `created_at` is also caught by the monotonic check.
- **Reconciliation:**
  - `reconcile` on an update route reports field matches correctly;
  - `resolve` is refused from a non-approver UID;
  - a reconciled request cannot be dispatched again.

### 6.4 Carried over

- **TTL:** both ceilings are enforced, and the agent cannot change them (P4).
- **No write credential in agent space:** a static check that no agent-side module imports a write function, and that the agent-side environment has no Canon write PAT.
- **Known-gap tests:** every Canon-route `known_gap` test is converted into a broker acceptance test or deleted with its gap closed. The GitHub and Supabase `known_gap` tests stay, because this ADR doesn't close them.
