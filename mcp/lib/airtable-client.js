/**
 * Shared Airtable HTTP client + T0-GO gate for the shadowfox-canon-guardrails
 * MCP servers.
 *
 * Security invariant this file exists to protect: base/table IDs are always
 * supplied by the CALLING SERVER's own hardcoded module-level constant, never
 * taken from a tool's input schema. Sharing this file must not become a way
 * to write to an arbitrary table — every export here takes baseId/tableId as
 * plain arguments the caller controls, not as something parsed from
 * user/agent-supplied tool input.
 */

import { open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { z } from "zod";

const AIRTABLE_API_URL = "https://api.airtable.com/v0";
const GO_MARKER_PATH = process.env.T0_GO_MARKER_PATH || ".claude/t0-go.json";

function apiKey() {
  const key = process.env.AIRTABLE_API_KEY;
  if (!key) {
    throw new Error(
      "AIRTABLE_API_KEY is not set. This server refuses to run without it — " +
        "see .env.example."
    );
  }
  return key;
}

/**
 * Call at server startup, before connecting the transport — fail fast and
 * loud rather than accepting connections and only erroring on first tool
 * call.
 */
export function requireApiKeyOrExit() {
  if (!process.env.AIRTABLE_API_KEY) {
    console.error(
      "ERROR: AIRTABLE_API_KEY environment variable is required. See .env.example."
    );
    process.exit(1);
  }
}

/**
 * Low-level Airtable REST call. Table/base IDs come from the caller's own
 * hardcoded constants — see the module-level invariant note above.
 */
async function airtableRequest(baseId, tableId, {
  method = "GET",
  recordId,
  query,
  body,
} = {}) {
  let url = `${AIRTABLE_API_URL}/${baseId}/${tableId}`;
  if (recordId) url += `/${recordId}`;
  if (query) {
    const qs = new URLSearchParams(query);
    url += `?${qs.toString()}`;
  }

  let response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${apiKey()}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    throw new Error(`Airtable request failed (network): ${err.message}`);
  }

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    switch (response.status) {
      case 401:
      case 403:
        throw new Error(
          `Airtable auth/permission error (${response.status}). Check ` +
            `AIRTABLE_API_KEY scopes for base ${baseId}. Detail: ${detail}`
        );
      case 404:
        throw new Error(
          `Airtable 404 — table ${tableId} not found in base ${baseId}, or ` +
            `record ID is stale. Detail: ${detail}`
        );
      case 422:
        throw new Error(
          `Airtable 422 — malformed field reference. If this server uses ` +
            `field IDs and the live schema has changed, this is likely a ` +
            `stale field ID. Detail: ${detail}`
        );
      case 429:
        throw new Error("Airtable rate limit (429). Back off and retry.");
      default:
        throw new Error(
          `Airtable request failed (${response.status}): ${detail}`
        );
    }
  }

  return response.json();
}

export function airtableGet(baseId, tableId, query) {
  return airtableRequest(baseId, tableId, { method: "GET", query });
}

export function airtableGetRecord(baseId, tableId, recordId) {
  return airtableRequest(baseId, tableId, { method: "GET", recordId });
}

/**
 * Write path. Every call site in every server MUST go through requireT0Go()
 * first — this function does not check the gate itself, so it is not a safe
 * substitute for that call. Kept ungated at this layer deliberately: gating
 * here would hide the check from the tool handler that's supposed to be
 * legible about why a write is or isn't allowed.
 */
export function airtableWrite(baseId, tableId, method, { recordId, fields } = {}) {
  return airtableRequest(baseId, tableId, {
    method,
    recordId,
    body: { fields },
  });
}

// The marker contract is shared with hooks/pre_tool_guard.py and pinned by
// tests/fixtures/marker_cases.json, which both implementations run. Change
// the two readers and the fixtures together.
//
// issued_at must be ISO-8601 with an explicit offset (the issuer writes
// microseconds + "Z"); Date.parse would otherwise accept free text and read
// offset-less times as local time.
const ISSUED_AT_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6})?(?:Z|[+-]\d{2}:\d{2})$/;
// A marker dated further ahead than this is refused: otherwise a future
// issued_at stretches its lifetime without bound.
const MAX_CLOCK_SKEW_MS = 60_000;

const GoMarkerSchema = z.object({
  decision_id: z.string().min(1),
  scope: z.array(z.string().min(1)).min(1),
  // Tier 1 = operational writes (Session Ledger, ATQ). Tier 2 = governance
  // writes (Decision Log, and any future Canon-ratification write) — a
  // higher bar, not just a different label. Resolves the circularity noted
  // in sfx-decisionlog-mcp.js's header: a Tier 2 marker is explicitly
  // understood to authorize *recording* a decision, not just an ordinary
  // write, so minting one is itself a deliberate, heavier-weight act.
  tier: z.number().int().min(1).max(2).default(1),
  issued_at: z.string().regex(ISSUED_AT_RE, "must be ISO-8601 with a timezone offset"),
  ttl_seconds: z.number().int().positive(),
  consumed: z.boolean().default(false),
});

/**
 * Fail-closed T0-GO check. Every write tool must call this, with the exact
 * table ID it is about to write to, before making any write request.
 *
 * On success, marks the marker consumed on disk so it cannot be replayed —
 * single-use by default. Throws with an actionable message on any failure
 * mode (missing file, malformed, wrong scope, expired, already consumed).
 *
 * v1 limitation, documented in README: decision_id is not live-validated
 * against the real T0 Decision Log. It is a paper trail, not a cryptographic
 * guarantee. Live validation would require Airtable credentials inside this
 * hook/server process — a new secret-surface tradeoff left for T0 to decide,
 * not defaulted here.
 */
export async function requireT0Go(tableId, { minTier = 1 } = {}) {
  // Read-check-consume must be one critical section, or concurrent calls
  // (in one server, or across the four servers sharing this marker) each
  // see it unconsumed and each proceed. O_EXCL creation of a lock file is
  // atomic across processes; whoever loses is refused, never waited on.
  const lockPath = `${GO_MARKER_PATH}.lock`;
  let lock;
  try {
    lock = await open(lockPath, "wx");
  } catch (err) {
    if (err.code === "EEXIST") {
      throw new Error(
        `T0-GO marker at ${GO_MARKER_PATH} is being checked by another write ` +
          `(${lockPath} exists). Retry; if no write is in flight, a crashed ` +
          `server left the lock behind — a human should remove it.`
      );
    }
    if (err.code === "ENOENT") {
      throw new Error(
        `No T0-GO marker at ${GO_MARKER_PATH}. Run hooks/issue_t0_go.py ` +
          `(human-run only — never from an agent session) before this write ` +
          `can proceed. This write requires Tier ${minTier}.`
      );
    }
    throw new Error(`Cannot lock T0-GO marker at ${GO_MARKER_PATH}: ${err.message}`);
  }
  try {
    return await checkAndConsume(tableId, minTier);
  } finally {
    await lock.close();
    await unlink(lockPath).catch(() => {});
  }
}

async function checkAndConsume(tableId, minTier) {
  let raw;
  try {
    raw = await readFile(GO_MARKER_PATH, "utf-8");
  } catch {
    throw new Error(
      `No T0-GO marker at ${GO_MARKER_PATH}. Run hooks/issue_t0_go.py ` +
        `(human-run only — never from an agent session) before this write ` +
        `can proceed. This write requires Tier ${minTier}.`
    );
  }

  let parsed;
  try {
    parsed = GoMarkerSchema.parse(JSON.parse(raw));
  } catch (err) {
    throw new Error(
      `T0-GO marker at ${GO_MARKER_PATH} is malformed: ${err.message}. ` +
        `Treating as absent — re-issue it.`
    );
  }

  if (parsed.consumed) {
    throw new Error(
      `T0-GO marker for decision ${parsed.decision_id} was already consumed. ` +
        `Each marker is single-use — issue a fresh one for this write.`
    );
  }

  if (!parsed.scope.includes(tableId)) {
    throw new Error(
      `T0-GO marker for decision ${parsed.decision_id} does not cover table ` +
        `${tableId} (scope: ${parsed.scope.join(", ")}). Issue a marker ` +
        `scoped to this table.`
    );
  }

  if (parsed.tier < minTier) {
    throw new Error(
      `T0-GO marker for decision ${parsed.decision_id} is Tier ${parsed.tier}, ` +
        `but this write requires Tier ${minTier} (governance-class write). ` +
        `Issue a Tier ${minTier} marker explicitly — Tier is never inferred upward.`
    );
  }

  const issuedAtMs = Date.parse(parsed.issued_at);
  if (Number.isNaN(issuedAtMs)) {
    throw new Error(
      `T0-GO marker has an unparseable issued_at (${parsed.issued_at}).`
    );
  }
  if (issuedAtMs > Date.now() + MAX_CLOCK_SKEW_MS) {
    throw new Error(
      `T0-GO marker for decision ${parsed.decision_id} is dated in the future ` +
        `(${parsed.issued_at}). Refusing it — re-issue it.`
    );
  }
  const expiresAtMs = issuedAtMs + parsed.ttl_seconds * 1000;
  if (Date.now() > expiresAtMs) {
    throw new Error(
      `T0-GO marker for decision ${parsed.decision_id} expired at ` +
        `${new Date(expiresAtMs).toISOString()}. Issue a fresh one.`
    );
  }

  // Consume it so it can't be replayed for a second write. Write-then-rename
  // so a concurrent reader (the hook) never sees a half-written file.
  const tmpPath = `${GO_MARKER_PATH}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(tmpPath, JSON.stringify({ ...parsed, consumed: true }, null, 2), "utf-8");
  await rename(tmpPath, GO_MARKER_PATH);

  return { decision_id: parsed.decision_id, tier: parsed.tier };
}
