// The shared marker contract, as read by requireT0Go() in
// mcp/lib/airtable-client.js. Same fixtures as
// tests/python/test_marker_contract.py.

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { FIXTURES, markerText, tempDir, validMarker } from "./helpers.mjs";

const dir = tempDir();
const markerPath = join(dir, "t0-go.json");
process.env.T0_GO_MARKER_PATH = markerPath; // read once, at module load
const { requireT0Go } = await import("../../mcp/lib/airtable-client.js");

async function outcome(scope, minTier) {
  try {
    await requireT0Go(scope, { minTier });
    return "allow";
  } catch {
    return "deny";
  }
}

for (const c of FIXTURES.cases) {
  test(`marker fixture: ${c.id}`, async () => {
    writeFileSync(markerPath, markerText(c));
    assert.equal(await outcome(c.scope ?? FIXTURES.default_scope, c.min_tier ?? 1), c.expect);
  });
}

test("missing marker denies", async () => {
  rmSync(markerPath, { force: true });
  assert.equal(await outcome("tblEZ6ctzSoTBsfCW", 1), "deny");
});

test("a successful check consumes the marker; the second check is denied", async () => {
  writeFileSync(markerPath, JSON.stringify(validMarker(["tblEZ6ctzSoTBsfCW"])));
  assert.equal(await outcome("tblEZ6ctzSoTBsfCW", 1), "allow");
  assert.equal(JSON.parse(readFileSync(markerPath, "utf-8")).consumed, true);
  assert.equal(await outcome("tblEZ6ctzSoTBsfCW", 1), "deny");
});

test("a denied check leaves the marker untouched", async () => {
  const text = JSON.stringify(validMarker(["tblsVXX2XnhVLWMVE"]));
  writeFileSync(markerPath, text);
  assert.equal(await outcome("tblEZ6ctzSoTBsfCW", 1), "deny");
  assert.equal(readFileSync(markerPath, "utf-8"), text);
});

test("concurrent checks in one process consume a marker exactly once", async () => {
  writeFileSync(markerPath, JSON.stringify(validMarker(["tblEZ6ctzSoTBsfCW", "tblsVXX2XnhVLWMVE"])));
  const results = await Promise.all(
    Array.from({ length: 10 }, (_, i) => outcome(i % 2 ? "tblEZ6ctzSoTBsfCW" : "tblsVXX2XnhVLWMVE", 1))
  );
  assert.equal(results.filter((r) => r === "allow").length, 1, `results: ${results}`);
  assert.equal(existsSync(`${markerPath}.lock`), false, "lock file must be released");
});

test("concurrent checks across processes consume a marker exactly once", async () => {
  const { spawn } = await import("node:child_process");
  const { pathToFileURL } = await import("node:url");
  const client = pathToFileURL(new URL("../../mcp/lib/airtable-client.js", import.meta.url).pathname).href;
  writeFileSync(markerPath, JSON.stringify(validMarker(["tblEZ6ctzSoTBsfCW"])));
  // Every child imports first, then spins until a shared start instant so
  // the reads genuinely overlap instead of being serialised by spawn time.
  const startAt = Date.now() + 1500;
  const child = `const { requireT0Go } = await import(${JSON.stringify(client)});
    while (Date.now() < ${startAt}) {}
    try { await requireT0Go("tblEZ6ctzSoTBsfCW"); console.log("allow"); } catch { console.log("deny"); }`;
  const run = () => new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ["--input-type=module", "-e", child], {
      env: { PATH: process.env.PATH, T0_GO_MARKER_PATH: markerPath },
    });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.on("error", reject);
    p.on("close", () => resolve(out.trim()));
  });
  const results = await Promise.all(Array.from({ length: 8 }, run));
  assert.equal(results.filter((r) => r === "allow").length, 1, `results: ${results}`);
  assert.equal(existsSync(`${markerPath}.lock`), false, "lock file must be released");
});
