import assert from "node:assert/strict";
import test from "node:test";

import { store } from "../src/store.js";

test("keeps a bounded log stream and evicts the oldest rows", () => {
  store.clearLogs();
  for (let index = 0; index < 350; index += 1) {
    store.addLog({ level: "info", source: "test", message: `row-${index}` });
  }
  assert.equal(store.get().logs.length, 300);
  assert.equal(store.get().logs[0].message, "row-50");
  assert.equal(store.get().logs.at(-1).message, "row-349");
});

test("bounds externally supplied log fields", () => {
  store.clearLogs();
  store.addLog({
    level: "not-a-level",
    source: "s".repeat(100),
    message: "m".repeat(5000),
  });
  const [entry] = store.get().logs;
  assert.equal(entry.level, "info");
  assert.equal(entry.source.length, 64);
  assert.equal(entry.message.length, 4096);
});

test("redacts credentials before diagnostics enter the store", () => {
  store.clearLogs();
  store.addLog({
    level: "error",
    source: "network",
    message: "request failed: https://example.test/profile?token=abc123 Authorization: Bearer secret-value",
  });
  const [entry] = store.get().logs;
  assert.equal(entry.message.includes("abc123"), false);
  assert.equal(entry.message.includes("secret-value"), false);
  assert.match(entry.message, /\[redacted\]/u);
});
