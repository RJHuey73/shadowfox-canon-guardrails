// Preloaded into each MCP server child process (node --import). Replaces
// fetch so no request leaves the process: every call is appended to
// $FETCH_LOG as one JSON line, and Airtable-shaped responses are returned.
// Anything that is not api.airtable.com is refused outright.

import { appendFileSync } from "node:fs";

const LOG = process.env.FETCH_LOG;
if (!LOG) throw new Error("fetch-mock: FETCH_LOG must be set");

globalThis.fetch = async (url, init = {}) => {
  const u = new URL(String(url));
  const entry = {
    method: init.method ?? "GET",
    host: u.host,
    path: u.pathname,
    query: Object.fromEntries(u.searchParams),
    body: init.body ? JSON.parse(init.body) : null,
    auth: init.headers?.Authorization ?? null,
  };
  appendFileSync(LOG, JSON.stringify(entry) + "\n");
  if (u.host !== "api.airtable.com") throw new Error(`fetch-mock: refused non-Airtable host ${u.host}`);
  const body = entry.method === "GET" && !/\/rec[A-Za-z0-9]{14}$/.test(u.pathname)
    ? { records: [] }
    : { id: "recMOCKMOCKMOCK01", fields: {} };
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
};
