// Shared helpers for the JS tests. No test here reaches the network: the
// MCP servers run in child processes with fetch replaced by
// tests/js/fetch-mock.mjs, and every marker lives under a temp directory.

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const FIXTURES = JSON.parse(
  readFileSync(join(REPO, "tests", "fixtures", "marker_cases.json"), "utf-8")
);

export function tempDir() {
  return mkdtempSync(join(tmpdir(), "sfx-guardrails-"));
}

// Expand "$NOW", "$NOW+N", "$NOW-N" into the issuer's timestamp format
// (microsecond isoformat, "Z"). Mirrors render_time in tests/python/conftest.py.
export function renderTime(token, offset, stripTz = false) {
  if (typeof token !== "string" || !token.startsWith("$NOW")) return token;
  const delta = Number(token.slice(4) || 0);
  const t = new Date(Date.now() + delta * 1000);
  const micro = (d) => d.toISOString().replace(/\.(\d{3})Z$/, ".$1000");
  if (offset) {
    const sign = offset[0] === "+" ? 1 : -1;
    const [h, m] = offset.slice(1).split(":").map(Number);
    const shifted = new Date(t.getTime() + sign * (h * 60 + m) * 60_000);
    return micro(shifted) + offset;
  }
  return micro(t) + (stripTz ? "" : "Z");
}

export function markerText(c) {
  if ("raw" in c) return c.raw;
  const marker = { ...c.marker };
  if ("issued_at" in marker) marker.issued_at = renderTime(marker.issued_at, c.offset, c.strip_tz);
  return JSON.stringify(marker);
}

export function validMarker(scope, tier = 1, overrides = {}) {
  return {
    decision_id: "T0-DEC-TEST",
    scope,
    tier,
    issued_at: renderTime("$NOW-5"),
    ttl_seconds: 600,
    consumed: false,
    ...overrides,
  };
}
