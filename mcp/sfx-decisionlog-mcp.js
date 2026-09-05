#!/usr/bin/env node
/**
 * sfx-decisionlog-mcp — write-scoped to the T0 Decision Log, and ONLY the T0
 * Decision Log.
 *
 * New in this repo (closes work-order gap #1). No prior-art claim.
 *
 * Open design tension, flagged rather than silently resolved: this table IS
 * the record of T0 authorization. Gating a new Decision Log entry behind the
 * same generic T0-GO marker used for Session Ledger / ATQ writes is a little
 * circular — a marker is meant to point at a decision that already exists,
 * and here the write IS the decision being recorded. Shipping this gated the
 * same way as the others for v1 consistency, but this is exactly the kind of
 * "ASK, don't default" question CANON-378 §5 calls for before treating it as
 * settled. See README.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { airtableGet, airtableWrite, requireT0Go, requireApiKeyOrExit } from "./lib/airtable-client.js";

const CANON_BASE_ID = "appVftexD3KJRcdij";
const DECISION_LOG_TABLE = "tblX88U1VOwmK2fF5"; // T0 Decision Log. Hardcoded. Not a parameter anywhere in this file.

const F_DECISION_ID = "fldizBpD2dpJFrCf5";
const F_DATE = "fldhUxWFOXjeA6fyI";
const F_RULING = "fldgrncAmnFMZZCC4";
const F_CANON_IMPACT = "fld8slfsR8EnvW26c";
const F_IMPLEMENTATION_STATUS = "fldoCeppbKdDuPKlw";
const F_SOURCE_SESSION = "fldCeowQF34CZD4ue";
const F_AFFECTED_ENTRIES = "fldRDmdkOpmqhJQTy";
const F_CONTEXT = "fldP5I22gVNbXhiUq";

const server = new McpServer({ name: "sfx-decisionlog-mcp", version: "1.0.0" });

server.registerTool(
  "decisionlog_get_latest",
  {
    title: "Get Latest T0 Decision Log Entries",
    description: `Read-only. Sorted by Date descending. No T0-GO required.

Args:
  - limit (number, 1-20, default 5)`,
    inputSchema: { limit: z.number().int().min(1).max(20).default(5) },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ limit }) => {
    try {
      const data = await airtableGet(CANON_BASE_ID, DECISION_LOG_TABLE, {
        "sort[0][field]": F_DATE,
        "sort[0][direction]": "desc",
        pageSize: String(limit),
        maxRecords: String(limit),
      });
      const decisions = data.records.map((r) => ({
        record_id: r.id,
        decision_id: r.fields[F_DECISION_ID],
        date: r.fields[F_DATE],
        ruling: r.fields[F_RULING],
        implementation_status: r.fields[F_IMPLEMENTATION_STATUS],
        affected_entries: r.fields[F_AFFECTED_ENTRIES],
      }));
      const output = { decisions };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "decisionlog_search",
  {
    title: "Search T0 Decision Log",
    description: `Read-only substring search across Ruling, Context, and Affected Entries. No T0-GO required.

Use this before proposing anything that might conflict with a settled ruling — CANON-378's own stated purpose for this table ("T1 searches before proposing anything that might conflict").

Args:
  - query (string): substring to search for
  - limit (number, 1-50, default 10)

Returns empty array if no match — that's a valid result, not evidence a ruling doesn't exist elsewhere (this only searches three fields).`,
    inputSchema: {
      query: z.string().min(1),
      limit: z.number().int().min(1).max(50).default(10),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ query, limit }) => {
    try {
      const q = query.replace(/"/g, '\\"');
      const formula = `OR(FIND("${q}", {${F_RULING}}), FIND("${q}", {${F_CONTEXT}}), FIND("${q}", {${F_AFFECTED_ENTRIES}}))`;
      const data = await airtableGet(CANON_BASE_ID, DECISION_LOG_TABLE, {
        filterByFormula: formula,
        pageSize: String(limit),
        maxRecords: String(limit),
      });
      const decisions = data.records.map((r) => ({
        record_id: r.id,
        decision_id: r.fields[F_DECISION_ID],
        date: r.fields[F_DATE],
        ruling: r.fields[F_RULING],
        canon_impact: r.fields[F_CANON_IMPACT],
        implementation_status: r.fields[F_IMPLEMENTATION_STATUS],
      }));
      const output = { decisions };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "decisionlog_create_entry",
  {
    title: "Create a T0 Decision Log Entry",
    description: `Requires a valid, unconsumed T0-GO marker scoped to ${DECISION_LOG_TABLE} — fails closed otherwise.

See this file's header comment: gating a *new decision record* behind the same generic marker used elsewhere is a known open design tension, not a settled answer. Use with that in mind, and surface it to T0 rather than treating this tool as equivalent in weight to an ATQ status update.

Args:
  - decision_id (string): e.g. "T0-DEC-EXAMPLE-2026-0905"
  - ruling (string)
  - source_session (string): session ID this decision was made in
  - canon_impact (string, optional)
  - affected_entries (string, optional)
  - context (string, optional)`,
    inputSchema: {
      decision_id: z.string().min(1),
      ruling: z.string().min(1),
      source_session: z.string().min(1),
      canon_impact: z.string().optional(),
      affected_entries: z.string().optional(),
      context: z.string().optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  async ({ decision_id, ruling, source_session, canon_impact, affected_entries, context }) => {
    try {
      const go = await requireT0Go(DECISION_LOG_TABLE);
      const result = await airtableWrite(CANON_BASE_ID, DECISION_LOG_TABLE, "POST", {
        fields: {
          [F_DECISION_ID]: decision_id,
          [F_DATE]: new Date().toISOString().slice(0, 10),
          [F_RULING]: ruling,
          [F_SOURCE_SESSION]: source_session,
          ...(canon_impact ? { [F_CANON_IMPACT]: canon_impact } : {}),
          ...(affected_entries ? { [F_AFFECTED_ENTRIES]: affected_entries } : {}),
          ...(context ? { [F_CONTEXT]: context } : {}),
        },
      });
      const output = { record_id: result.id, decision_id, t0_go_decision_id: go.decision_id };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

requireApiKeyOrExit();
const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`sfx-decisionlog-mcp running via stdio (write-scoped to ${DECISION_LOG_TABLE} only)`);
