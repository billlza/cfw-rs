import assert from "node:assert/strict";
import test from "node:test";

import { summarizeEngineEvent } from "../src/streams.js";

test("redacts credentials from native engine event summaries", () => {
  const summary = summarizeEngineEvent({
    type: "failed",
    message: "https://example.test/path?token=query-secret Authorization: Bearer bearer-secret password=plain-secret",
  });

  assert.equal(summary.includes("query-secret"), false);
  assert.equal(summary.includes("bearer-secret"), false);
  assert.equal(summary.includes("plain-secret"), false);
  assert.match(summary, /\[redacted\]/u);
});

test("bounds native event summaries after redaction", () => {
  assert.equal(
    summarizeEngineEvent({ type: "state", message: "x".repeat(4096) }).length,
    2048,
  );
});
