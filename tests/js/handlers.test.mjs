// The four MCP servers' public tool handlers, driven through a real MCP
// client over stdio. Each server runs as a child process with fetch mocked
// (fetch-mock.mjs), a fake API key, and a temp marker path, so these tests
// need no credentials and make no network calls.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { REPO, tempDir, validMarker } from "./helpers.mjs";

const BASE = "appVftexD3KJRcdij";
const SESSION = "tblEZ6ctzSoTBsfCW";
const ATQ = "tblsVXX2XnhVLWMVE";
const DECISION_LOG = "tblX88U1VOwmK2fF5";
const REC = "recAAAAAAAAAAAAAA";

const dir = tempDir();
const markerPath = join(dir, "t0-go.json");
const fetchLog = join(dir, "fetch.jsonl");
const clients = {};

async function connect(server) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", join(REPO, "tests", "js", "fetch-mock.mjs"), join(REPO, "mcp", `${server}.js`)],
    env: {
      PATH: process.env.PATH,
      AIRTABLE_API_KEY: "test-key-not-real",
      T0_GO_MARKER_PATH: markerPath,
      FETCH_LOG: fetchLog,
    },
    stderr: "ignore",
  });
  const client = new Client({ name: "guardrails-test", version: "0.0.0" });
  await client.connect(transport);
  return client;
}

before(async () => {
  for (const s of ["sfx-canon-mcp", "sfx-session-mcp", "sfx-atq-mcp", "sfx-decisionlog-mcp"]) {
    clients[s] = await connect(s);
  }
});
after(async () => {
  await Promise.all(Object.values(clients).map((c) => c.close()));
});

function requests() {
  return existsSync(fetchLog)
    ? readFileSync(fetchLog, "utf-8").trim().split("\n").filter(Boolean).map(JSON.parse)
    : [];
}

function reset({ marker } = {}) {
  rmSync(fetchLog, { force: true });
  rmSync(markerPath, { force: true });
  if (marker) writeFileSync(markerPath, JSON.stringify(marker));
}

const call = (server, name, args) => clients[server].callTool({ name, arguments: args });

const WRITES = [
  { server: "sfx-session-mcp", tool: "session_open", table: SESSION, method: "POST", tier: 1,
    args: { session_id: "SFX-SESSION-TEST", canon_version_start: "v0.0.0-test", objectives: "test" } },
  { server: "sfx-session-mcp", tool: "session_close", table: SESSION, method: "PATCH", tier: 1, record: REC,
    args: { record_id: REC, canon_version_end: "v0.0.0-test", outcomes: "test" } },
  { server: "sfx-atq-mcp", tool: "atq_create_task", table: ATQ, method: "POST", tier: 1,
    args: { task_id: "TQ-TEST", title: "test", priority: "P1-High" } },
  { server: "sfx-atq-mcp", tool: "atq_update_task", table: ATQ, method: "PATCH", tier: 1, record: REC,
    args: { record_id: REC, status: "Done" } },
  { server: "sfx-decisionlog-mcp", tool: "decisionlog_create_entry", table: DECISION_LOG, method: "POST", tier: 2,
    args: { decision_id: "T0-DEC-TEST", ruling: "test", source_session: "SFX-SESSION-TEST" } },
];

for (const w of WRITES) {
  const others = [SESSION, ATQ, DECISION_LOG].filter((t) => t !== w.table);

  test(`${w.tool}: denied authorization sends zero requests`, async () => {
    const denials = [
      undefined, // no marker
      validMarker(others, 2), // wrong scope, even at Tier 2
      validMarker([w.table], w.tier, { consumed: true }),
      validMarker([w.table], w.tier, { issued_at: "2020-01-01T00:00:00.000000Z" }), // expired
      ...(w.tier === 2 ? [validMarker([w.table], 1)] : []), // Tier 1 for a Tier 2 write
    ];
    for (const marker of denials) {
      reset({ marker });
      const result = await call(w.server, w.tool, w.args);
      assert.equal(result.isError, true, JSON.stringify(marker));
      assert.deepEqual(requests(), [], JSON.stringify(marker));
    }
  });

  test(`${w.tool}: an allowed write goes to exactly ${w.method} ${w.table}, once`, async () => {
    reset({ marker: validMarker([w.table, ...others], w.tier) });
    const result = await call(w.server, w.tool, w.args);
    assert.notEqual(result.isError, true, JSON.stringify(result.content));
    const reqs = requests();
    assert.equal(reqs.length, 1);
    const [r] = reqs;
    assert.equal(r.host, "api.airtable.com");
    assert.equal(r.method, w.method);
    assert.equal(r.path, `/v0/${BASE}/${w.table}${w.record ? `/${w.record}` : ""}`);
    assert.equal(r.auth, "Bearer test-key-not-real");
    assert.ok(r.body && typeof r.body.fields === "object");
    assert.ok(Object.keys(r.body.fields).every((k) => /^fld[A-Za-z0-9]{14}$/.test(k)));
    assert.equal(JSON.parse(readFileSync(markerPath, "utf-8")).consumed, true);

    // Replay of the same (now consumed) marker: denied, still one request.
    const again = await call(w.server, w.tool, w.args);
    assert.equal(again.isError, true);
    assert.equal(requests().length, 1);
  });
}

test("record IDs that are not Airtable record IDs are rejected before any request", async () => {
  for (const record_id of ["../tbltw4Jy0LHWWz5DL", "rec123", `${REC}/x`, "recAAAAAAAAAAAAAA?x=1"]) {
    reset({ marker: validMarker([SESSION, ATQ]) });
    const a = await call("sfx-session-mcp", "session_close", { record_id, canon_version_end: "v", outcomes: "o" });
    const b = await call("sfx-atq-mcp", "atq_update_task", { record_id, status: "Done" });
    const c = await call("sfx-session-mcp", "session_get", { record_id });
    assert.ok(a.isError && b.isError && c.isError, record_id);
    assert.deepEqual(requests(), [], record_id);
    assert.equal(JSON.parse(readFileSync(markerPath, "utf-8")).consumed, false, "marker must survive");
  }
});

test("atq_update_task with nothing to change neither consumes the marker nor sends a request", async () => {
  reset({ marker: validMarker([ATQ]) });
  const r = await call("sfx-atq-mcp", "atq_update_task", { record_id: REC });
  assert.equal(r.isError, true);
  assert.deepEqual(requests(), []);
  assert.equal(JSON.parse(readFileSync(markerPath, "utf-8")).consumed, false);
});

test("sfx-canon-mcp only ever issues GET requests, with no marker present", async () => {
  reset();
  const { tools } = await clients["sfx-canon-mcp"].listTools();
  assert.ok(tools.length > 0);
  for (const t of tools) {
    const args = {};
    for (const [k, schema] of Object.entries(t.inputSchema.properties ?? {})) {
      if ((t.inputSchema.required ?? []).includes(k)) args[k] = schema.type === "number" || schema.type === "integer" ? 1 : "SFX-CANON-001";
    }
    await call("sfx-canon-mcp", t.name, args);
  }
  const reqs = requests();
  assert.ok(reqs.length > 0);
  assert.ok(reqs.every((r) => r.method === "GET" && r.body === null), JSON.stringify(reqs));
  assert.ok(reqs.every((r) => r.path.startsWith(`/v0/${BASE}/`)));
});

test("read tools on the write servers are GET-only and need no marker", async () => {
  reset();
  await call("sfx-session-mcp", "session_get", { record_id: REC });
  await call("sfx-atq-mcp", "atq_list_open", {});
  await call("sfx-atq-mcp", "atq_get_item", { record_id: REC });
  await call("sfx-decisionlog-mcp", "decisionlog_get_latest", {});
  await call("sfx-decisionlog-mcp", "decisionlog_search", { query: "x" });
  const reqs = requests();
  assert.equal(reqs.length, 5);
  assert.ok(reqs.every((r) => r.method === "GET"));
  assert.deepEqual(reqs.map((r) => r.path.split("/")[3]), [SESSION, ATQ, ATQ, DECISION_LOG, DECISION_LOG]);
});

test("no tool on any server accepts a base or table identifier as input", async () => {
  for (const [name, client] of Object.entries(clients)) {
    const { tools } = await client.listTools();
    for (const t of tools) {
      for (const key of Object.keys(t.inputSchema.properties ?? {})) {
        assert.doesNotMatch(key, /base|table/i, `${name}.${t.name}.${key}`);
      }
    }
  }
});

test("decisionlog_search escapes backslashes so a query cannot close the formula string", async () => {
  reset();
  await call("sfx-decisionlog-mcp", "decisionlog_search", { query: '\\"), TRUE(), ("' });
  const formula = requests()[0].query.filterByFormula;
  // Every FIND("...") argument must still be one well-formed string literal.
  const literal = /FIND\("((?:[^"\\]|\\.)*)", \{fld[A-Za-z0-9]{14}\}\)/g;
  const found = [...formula.matchAll(literal)];
  assert.equal(found.length, 3, formula);
  assert.equal(formula.replace(literal, "").replace(/\s/g, ""), "OR(,,)", formula);
});
