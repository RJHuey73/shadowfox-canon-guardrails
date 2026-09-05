#!/usr/bin/env node
/**
 * sfx-canon-mcp — read-only access to the Shadowfox Canon Spine.
 *
 * Fresh implementation of a described pattern (see repo README "Provenance"
 * section) — not a verified port of prior source.
 *
 * Security property: no write verb (POST/PATCH/DELETE) appears anywhere in
 * this file. That is enforced by what this file imports (airtableGet only,
 * never airtableWrite) — least-privilege by code shape, not a runtime
 * permission check that could be bypassed or forgotten.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { airtableGet } from "./lib/airtable-client.js";

const CANON_BASE_ID = "appVftexD3KJRcdij";
const CANON_REGISTRY_TABLE = "tbltw4Jy0LHWWz5DL"; // Canon ID Registry (live) — NOT "Canon Registry (Legacy)" tblzhZLLIqd2VS4Mh
const SESSION_LEDGER_TABLE = "tblEZ6ctzSoTBsfCW";
const CLUSTERS_TABLE = "tblzAduCrdnQn44kp"; // confirmed live via list_tables_for_base, 2026-09-03 session

// Canon ID Registry field IDs (verified live, 2026-09-03)
const F_CANON_ID = "fldyg24N6evVANwnt";
const F_TITLE = "fldnSqPf0EFJTrKqx";
const F_STATUS = "fld1K3deZgtYkxrIU";
const F_CLUSTER = "fldBEjVwwOGs8r9ag";
const F_VERSION_RATIFIED = "fldK4CqmEwpmwALPO";
const F_DATE_RATIFIED = "fldUamLrGnQFT8JvG";
const F_NOTES = "fldtDSsXSR2weXjPS";

// Session Ledger field IDs (verified live, 2026-09-03)
const SL_SESSION_ID = "fldAEK04jHw5M6pxD";
const SL_DATE = "fldZWHEtoc7bdvA8B";
const SL_STATUS = "fldOr9Ym0nHh5UAUp";
const SL_HANDOFF_NOTES = "fldSDXl4vVTAfVGkW";
const SL_DEFERRED_ITEMS = "fldyhZQYVfFX6EPie";

// Clusters field IDs (verified live, 2026-09-03)
const CL_PREFIX = "fldzqTIIk0m2cR1O0";
const CL_NAME = "fldN0ZeoDwew1xr4H";
const CL_ENTRY_COUNT = "fldnbQM0lEQgpj9Cs";
const CL_STATUS = "fldsgEJtJ3J6sDj5m";

const server = new McpServer({ name: "sfx-canon-mcp", version: "1.1.0" });

server.registerTool(
  "canon_get_latest_entry",
  {
    title: "Get Latest Canon Registry Entries",
    description: `Fetch the most recently ratified entries in the Canon ID Registry, sorted by Date Ratified descending.

Args:
  - limit (number, 1-20, default 5): how many entries to return

Returns JSON: { entries: [{ canon_id, title, status, cluster, version_ratified, date_ratified }] }

Use this to check the current Canon version/ceiling. Do NOT cache this result across a session — re-query before any Canon-adjacent claim, per the live-not-memory rule this whole system runs on.`,
    inputSchema: {
      limit: z.number().int().min(1).max(20).default(5),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ limit }) => {
    try {
      const data = await airtableGet(CANON_BASE_ID, CANON_REGISTRY_TABLE, {
        "sort[0][field]": F_DATE_RATIFIED,
        "sort[0][direction]": "desc",
        pageSize: String(limit),
        maxRecords: String(limit),
      });
      const entries = data.records.map((r) => ({
        canon_id: r.fields[F_CANON_ID],
        title: r.fields[F_TITLE],
        status: r.fields[F_STATUS],
        cluster: r.fields[F_CLUSTER],
        version_ratified: r.fields[F_VERSION_RATIFIED],
        date_ratified: r.fields[F_DATE_RATIFIED],
      }));
      const output = { entries };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "canon_get_next_id",
  {
    title: "Get Next Clean Canon ID",
    description: `Scans the full Canon ID Registry (paginated) and returns the next unused SFX-CANON-N id.

No args.

Returns JSON: { ceiling_id: "SFX-CANON-379", next_clean_id: "SFX-CANON-380", scanned: 237 }

This does a full-table scan every call (Airtable's API has no numeric sort on text fields) — it's correct, not free. Don't poll this in a loop.`,
    inputSchema: {},
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async () => {
    try {
      let maxN = 0;
      let ceilingId = null;
      let offset;
      let scanned = 0;
      do {
        const data = await airtableGet(CANON_BASE_ID, CANON_REGISTRY_TABLE, {
          "fields[]": F_CANON_ID,
          pageSize: "100",
          ...(offset ? { offset } : {}),
        });
        for (const r of data.records) {
          const id = r.fields[F_CANON_ID];
          const m = /^SFX-CANON-(\d+)$/.exec(id || "");
          if (m) {
            const n = parseInt(m[1], 10);
            if (n > maxN) {
              maxN = n;
              ceilingId = id;
            }
          }
        }
        scanned += data.records.length;
        offset = data.offset;
      } while (offset);

      const output = {
        ceiling_id: ceilingId,
        next_clean_id: `SFX-CANON-${maxN + 1}`,
        scanned,
      };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "canon_get_session_ledger",
  {
    title: "Get Latest Session Ledger Records",
    description: `Fetch the most recent Session Ledger entries, sorted by Date descending. Read-only — this tool cannot open or close a session; use sfx-session-mcp for that.

Args:
  - limit (number, 1-20, default 3): how many records to return

Returns JSON: { sessions: [{ session_id, date, status, handoff_notes, deferred_items }] }`,
    inputSchema: {
      limit: z.number().int().min(1).max(20).default(3),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ limit }) => {
    try {
      const data = await airtableGet(CANON_BASE_ID, SESSION_LEDGER_TABLE, {
        "sort[0][field]": SL_DATE,
        "sort[0][direction]": "desc",
        pageSize: String(limit),
        maxRecords: String(limit),
      });
      const sessions = data.records.map((r) => ({
        session_id: r.fields[SL_SESSION_ID],
        date: r.fields[SL_DATE],
        status: r.fields[SL_STATUS],
        handoff_notes: r.fields[SL_HANDOFF_NOTES],
        deferred_items: r.fields[SL_DEFERRED_ITEMS],
      }));
      const output = { sessions };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "canon_get_clusters",
  {
    title: "Get Canon Cluster Taxonomy",
    description: `List the Canon cluster taxonomy (ARCH, MARKET, TRADE, PROMPT-PACK, etc.) with entry counts and status.

No args.

Returns JSON: { clusters: [{ prefix, name, entry_count, status }] }`,
    inputSchema: {},
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async () => {
    try {
      const data = await airtableGet(CANON_BASE_ID, CLUSTERS_TABLE, { pageSize: "100" });
      const clusters = data.records.map((r) => ({
        prefix: r.fields[CL_PREFIX],
        name: r.fields[CL_NAME],
        entry_count: r.fields[CL_ENTRY_COUNT],
        status: r.fields[CL_STATUS],
      }));
      const output = { clusters };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "canon_query_entry",
  {
    title: "Query Canon Registry by ID or Title Substring",
    description: `Look up a specific Canon Registry entry by exact Canon ID, or search by a title substring.

Args:
  - canon_id (string, optional): exact match, e.g. "SFX-CANON-378"
  - title_contains (string, optional): case-sensitive substring match against Title
  - limit (number, 1-50, default 10)

Exactly one of canon_id / title_contains should be given. Returns JSON: { entries: [...] }, empty array if no match — that's a valid result, not an error.`,
    inputSchema: {
      canon_id: z.string().optional(),
      title_contains: z.string().optional(),
      limit: z.number().int().min(1).max(50).default(10),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ canon_id, title_contains, limit }) => {
    if (!canon_id && !title_contains) {
      return { isError: true, content: [{ type: "text", text: "Error: provide canon_id or title_contains." }] };
    }
    try {
      // Airtable formulas accept {fldXXXX} in place of {Field Name} — using
      // field IDs here too, consistent with this repo's field-ID convention.
      const formula = canon_id
        ? `{${F_CANON_ID}} = "${canon_id.replace(/"/g, '\\"')}"`
        : `FIND("${title_contains.replace(/"/g, '\\"')}", {${F_TITLE}})`;
      const data = await airtableGet(CANON_BASE_ID, CANON_REGISTRY_TABLE, {
        filterByFormula: formula,
        pageSize: String(limit),
        maxRecords: String(limit),
      });
      const entries = data.records.map((r) => ({
        canon_id: r.fields[F_CANON_ID],
        title: r.fields[F_TITLE],
        status: r.fields[F_STATUS],
        cluster: r.fields[F_CLUSTER],
        version_ratified: r.fields[F_VERSION_RATIFIED],
        date_ratified: r.fields[F_DATE_RATIFIED],
        notes: r.fields[F_NOTES],
      }));
      const output = { entries };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("sfx-canon-mcp running via stdio (read-only)");
