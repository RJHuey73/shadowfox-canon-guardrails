#!/usr/bin/env node
/**
 * sfx-atq-mcp — write-scoped to the Active Task Queue, and ONLY the Active
 * Task Queue.
 *
 * New in this repo (closes work-order gap #1: neither described original
 * server covered this table, despite it getting real read/write traffic —
 * TQ-019, TQ-031 close-outs — in the 2026-09-03 session review). No prior-art
 * claim here at all; this is not an "extension" of anything.
 *
 * Same two safety properties as sfx-session-mcp: ATQ_TABLE is a hardcoded
 * module constant (never tool input), and every write calls requireT0Go()
 * first.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { airtableGet, airtableGetRecord, airtableWrite, requireT0Go, requireApiKeyOrExit } from "./lib/airtable-client.js";

const CANON_BASE_ID = "appVftexD3KJRcdij";
const ATQ_TABLE = "tblsVXX2XnhVLWMVE"; // Active Task Queue. Hardcoded. Not a parameter anywhere in this file.

const F_TASK_ID = "fldZZ1pgZELSAZvJW";
const F_TITLE = "fldaWSE4yMuiLtfX0";
const F_PRIORITY = "fldlr64WaVeG7MiQy";
const F_STATUS = "fld2IFOA3mWqjJRvT";
const F_GATE_DEPENDENCY = "fldvBxsbVsNvdXGkW";
const F_BLOCKER = "fldEWBMQ13jHn4d3Y";
const F_CREATED = "fldUOamJR0qdlM6xD";
const F_NOTES = "fldE579pnSWiGuwVf";
const F_CLUSTER = "fld20aNMCVwZbtu2A";

const OPEN_STATUSES = ["Queued", "In Progress"];

const server = new McpServer({ name: "sfx-atq-mcp", version: "1.0.0" });

server.registerTool(
  "atq_list_open",
  {
    title: "List Open Active Task Queue Items",
    description: `Read-only. Lists items with Status in ${JSON.stringify(OPEN_STATUSES)}, sorted by Created descending. No T0-GO required.

Args:
  - limit (number, 1-50, default 20)

Returns JSON: { tasks: [{ record_id, task_id, title, priority, status, blocker, cluster, created }] }`,
    inputSchema: { limit: z.number().int().min(1).max(50).default(20) },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ limit }) => {
    try {
      const orFormula = `OR(${OPEN_STATUSES.map((s) => `{${F_STATUS}} = "${s}"`).join(",")})`;
      const data = await airtableGet(CANON_BASE_ID, ATQ_TABLE, {
        filterByFormula: orFormula,
        "sort[0][field]": F_CREATED,
        "sort[0][direction]": "desc",
        pageSize: String(limit),
        maxRecords: String(limit),
      });
      const tasks = data.records.map((r) => ({
        record_id: r.id,
        task_id: r.fields[F_TASK_ID],
        title: r.fields[F_TITLE],
        priority: r.fields[F_PRIORITY],
        status: r.fields[F_STATUS],
        blocker: r.fields[F_BLOCKER],
        cluster: r.fields[F_CLUSTER],
        created: r.fields[F_CREATED],
      }));
      const output = { tasks };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "atq_get_item",
  {
    title: "Get One Active Task Queue Item",
    description: `Read-only fetch by Airtable record ID. No T0-GO required.

Args:
  - record_id (string): Airtable record ID (rec...)`,
    inputSchema: { record_id: z.string().regex(/^rec[A-Za-z0-9]{14}$/) },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ record_id }) => {
    try {
      const r = await airtableGetRecord(CANON_BASE_ID, ATQ_TABLE, record_id);
      const output = {
        record_id: r.id,
        task_id: r.fields[F_TASK_ID],
        title: r.fields[F_TITLE],
        priority: r.fields[F_PRIORITY],
        status: r.fields[F_STATUS],
        blocker: r.fields[F_BLOCKER],
        gate_dependency: r.fields[F_GATE_DEPENDENCY],
        notes: r.fields[F_NOTES],
        cluster: r.fields[F_CLUSTER],
        created: r.fields[F_CREATED],
      };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "atq_create_task",
  {
    title: "Create an Active Task Queue Item",
    description: `Requires a valid, unconsumed T0-GO marker scoped to ${ATQ_TABLE} — fails closed otherwise. Does not pass typecast, so an unrecognized Priority/Status option value fails loudly instead of silently minting a new taxonomy option (CANON-378 §5: "No new terminology").

Args:
  - task_id (string): e.g. "TQ-034"
  - title (string)
  - priority (string): must be an existing Priority option, e.g. "P1-High"
  - notes (string, optional)`,
    inputSchema: {
      task_id: z.string().min(1),
      title: z.string().min(1),
      priority: z.string().min(1),
      notes: z.string().optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  async ({ task_id, title, priority, notes }) => {
    try {
      const go = await requireT0Go(ATQ_TABLE);
      const result = await airtableWrite(CANON_BASE_ID, ATQ_TABLE, "POST", {
        fields: {
          [F_TASK_ID]: task_id,
          [F_TITLE]: title,
          [F_PRIORITY]: priority,
          [F_STATUS]: "Queued",
          [F_CREATED]: new Date().toISOString().slice(0, 10),
          ...(notes ? { [F_NOTES]: notes } : {}),
        },
      });
      const output = { record_id: result.id, task_id, t0_decision_id: go.decision_id };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  "atq_update_task",
  {
    title: "Update an Active Task Queue Item",
    description: `Requires a valid, unconsumed T0-GO marker scoped to ${ATQ_TABLE} — fails closed otherwise. Only the fields you pass are changed.

Args:
  - record_id (string): Airtable record ID (rec...)
  - status (string, optional): must be an existing Status option
  - notes (string, optional): replaces Notes entirely — read the current value with atq_get_item first if you need to append rather than overwrite
  - blocker (string, optional)`,
    inputSchema: {
      record_id: z.string().regex(/^rec[A-Za-z0-9]{14}$/),
      status: z.string().optional(),
      notes: z.string().optional(),
      blocker: z.string().optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ record_id, status, notes, blocker }) => {
    if (!status && !notes && !blocker) {
      return { isError: true, content: [{ type: "text", text: "Error: provide at least one of status/notes/blocker." }] };
    }
    try {
      const go = await requireT0Go(ATQ_TABLE);
      await airtableWrite(CANON_BASE_ID, ATQ_TABLE, "PATCH", {
        recordId: record_id,
        fields: {
          ...(status ? { [F_STATUS]: status } : {}),
          ...(notes ? { [F_NOTES]: notes } : {}),
          ...(blocker ? { [F_BLOCKER]: blocker } : {}),
        },
      });
      const output = { record_id, t0_decision_id: go.decision_id };
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], structuredContent: output };
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: `Error: ${err.message}` }] };
    }
  }
);

requireApiKeyOrExit();
const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`sfx-atq-mcp running via stdio (write-scoped to ${ATQ_TABLE} only)`);
