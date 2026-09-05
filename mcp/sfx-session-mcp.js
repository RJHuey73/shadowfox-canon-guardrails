#!/usr/bin/env node
/**
 * sfx-session-mcp — write-scoped to the Session Ledger, and ONLY the
 * Session Ledger.
 *
 * Fresh implementation of a described pattern (see repo README "Provenance"
 * section) — not a verified port of prior source.
 *
 * Security property #1 (unchanged from the described original): SESSION_TABLE
 * below is a module-level constant. It is never read from tool input, so this
 * server cannot be pointed at another table without editing this file.
 *
 * Security property #2 (new in this repo, closes work-order gap #2): every
 * write tool calls requireT0Go() before touching the network. See
 * lib/airtable-client.js and README "The T0-GO marker" for the fail-closed
 * contract. This applies uniformly to session_open/session_close, per the
 * work order's literal ask ("no write-capable tool call fires without a
 * session-visible T0 GO marker") — a future refinement could tier
 * session-bookkeeping writes separately from Canon-ratification writes, but
 * v1 treats all writes here the same way.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { airtableGetRecord, airtableWrite, requireT0Go, requireApiKeyOrExit } from "./lib/airtable-client.js";

const CANON_BASE_ID = "appVftexD3KJRcdij";
const SESSION_TABLE = "tblEZ6ctzSoTBsfCW"; // Session Ledger. Hardcoded. Not a parameter anywhere in this file.

const F_SESSION_ID = "fldAEK04jHw5M6pxD";
const F_DATE = "fldZWHEtoc7bdvA8B";
const F_CANON_VERSION_START = "fldUvJl3jynP5LA5F";
const F_CANON_VERSION_END = "fld1XE5HqRL1ozfvd";
const F_OBJECTIVES = "flddiEbiwOntcAYTN";
const F_OUTCOMES = "fldjOMZWbh8w3ceyl";
const F_DEFERRED_ITEMS = "fldyhZQYVfFX6EPie";
const F_STATUS = "fldOr9Ym0nHh5UAUp";
const F_HANDOFF_NOTES = "fldSDXl4vVTAfVGkW";

const server = new McpServer({ name: "sfx-session-mcp", version: "1.1.0" });

server.registerTool(
  "session_open",
  {
    title: "Open a Session Ledger Record",
    description: `Create a new Session Ledger record. Requires a valid, unconsumed T0-GO marker scoped to ${SESSION_TABLE} (see README) — fails closed otherwise.

Args:
  - session_id (string): e.g. "SFX-SESSION-20260905-EXAMPLE"
  - canon_version_start (string): e.g. "v9.88.0" — query live, don't guess
  - objectives (string): free text

Returns JSON: { record_id, session_id }. Does not set status or close the record — use session_close for that.`,
    inputSchema: {
      session_id: z.string().min(1),
      canon_version_start: z.string().min(1),
      objectives: z.string().min(1),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  async ({ session_id, canon_version_start, objectives }) => {
    try {
      const go = await requireT0Go(SESSION_TABLE);
      const result = await airtableWrite(CANON_BASE_ID, SESSION_TABLE, "POST", {
        fields: {
          [F_SESSION_ID]: session_id,
          [F_DATE]: new Date().toISOString().slice(0, 10),
          [F_CANON_VERSION_START]: canon_version_start,
          [F_OBJECTIVES]: objectives,
          [F_STATUS]: "Active",
        },
      });
      const output = { record_id: result.id, session_id, t0_decision_id: go.decision_id };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "session_close",
  {
    title: "Close a Session Ledger Record",
    description: `Update an existing Session Ledger record to Closed, with outcomes/handoff notes. Requires a valid, unconsumed T0-GO marker scoped to ${SESSION_TABLE} — fails closed otherwise.

Args:
  - record_id (string): Airtable record ID (rec...) from session_open or session_get
  - canon_version_end (string)
  - outcomes (string)
  - deferred_items (string, optional)
  - handoff_notes (string, optional)

Returns JSON: { record_id, status: "Closed" }`,
    inputSchema: {
      record_id: z.string().regex(/^rec[A-Za-z0-9]{14}$/, "must be an Airtable record ID"),
      canon_version_end: z.string().min(1),
      outcomes: z.string().min(1),
      deferred_items: z.string().optional(),
      handoff_notes: z.string().optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ record_id, canon_version_end, outcomes, deferred_items, handoff_notes }) => {
    try {
      const go = await requireT0Go(SESSION_TABLE);
      await airtableWrite(CANON_BASE_ID, SESSION_TABLE, "PATCH", {
        recordId: record_id,
        fields: {
          [F_CANON_VERSION_END]: canon_version_end,
          [F_OUTCOMES]: outcomes,
          [F_STATUS]: "Closed",
          ...(deferred_items ? { [F_DEFERRED_ITEMS]: deferred_items } : {}),
          ...(handoff_notes ? { [F_HANDOFF_NOTES]: handoff_notes } : {}),
        },
      });
      const output = { record_id, status: "Closed", t0_decision_id: go.decision_id };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "session_get",
  {
    title: "Get a Session Ledger Record",
    description: `Read-only fetch of one Session Ledger record by Airtable record ID. No T0-GO required — this is a read.

Args:
  - record_id (string): Airtable record ID (rec...)

Returns JSON with all known Session Ledger fields for that record.`,
    inputSchema: {
      record_id: z.string().regex(/^rec[A-Za-z0-9]{14}$/, "must be an Airtable record ID"),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ record_id }) => {
    try {
      const record = await airtableGetRecord(CANON_BASE_ID, SESSION_TABLE, record_id);
      const output = {
        record_id: record.id,
        session_id: record.fields[F_SESSION_ID],
        date: record.fields[F_DATE],
        canon_version_start: record.fields[F_CANON_VERSION_START],
        canon_version_end: record.fields[F_CANON_VERSION_END],
        status: record.fields[F_STATUS],
        objectives: record.fields[F_OBJECTIVES],
        outcomes: record.fields[F_OUTCOMES],
        deferred_items: record.fields[F_DEFERRED_ITEMS],
        handoff_notes: record.fields[F_HANDOFF_NOTES],
      };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

requireApiKeyOrExit();
const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`sfx-session-mcp running via stdio (write-scoped to ${SESSION_TABLE} only)`);
