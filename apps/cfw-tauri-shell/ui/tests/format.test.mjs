import assert from "node:assert/strict";
import test from "node:test";

import {
  delayFailureLabel,
  errorText,
  formatBytes,
  formatGeoipLabel,
  formatRate,
  formatRelativeUpdated,
  formatRuntime,
  invoke,
  latestDelay,
  listen,
  logEntry,
  normalizeLevel,
  providerBatchSummary,
  providerBatchSucceeded,
  redactDiagnosticText,
  safeRegex,
  withLogRow,
  withLogRows,
} from "../src/format.js";
import { MAX_LOG_ROWS } from "../src/state.js";

test("keeps the 0.3.5 traffic and runtime formats", () => {
  assert.equal(formatRuntime(0), "00 : 00 : 00");
  assert.equal(formatRuntime(3671), "01 : 01 : 11");
  assert.equal(formatRuntime(-5), "00 : 00 : 00");
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(999), "999 B");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(20 * 1024 * 1024), "20 MB");
  assert.equal(formatRate(0), "0.00 KB/s");
  assert.equal(formatRate(2), "2.0 MB/s");
});

test("reports a missing GeoIP database instead of inventing one", () => {
  assert.equal(formatGeoipLabel(null), "Unavailable");
  assert.equal(formatGeoipLabel({ present: false }), "Not present");
  assert.equal(
    formatGeoipLabel({ present: true, file_name: "geoip.metadb", mtime_ms: null }),
    "geoip.metadb",
  );
  assert.match(
    formatGeoipLabel({ present: true, file_name: "geoip.metadb", mtime_ms: Date.UTC(2026, 0, 2, 3, 4) }),
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/u,
  );
});

test("normalizes controller log levels and delay history", () => {
  assert.equal(normalizeLevel("WRN"), "warning");
  assert.equal(normalizeLevel("fatal"), "error");
  assert.equal(normalizeLevel("trc"), "debug");
  assert.equal(normalizeLevel(undefined), "info");
  assert.equal(latestDelay([{ delay: 10 }, { delay: 42 }]), 42);
  assert.equal(latestDelay([]), null);
  assert.equal(latestDelay([{ delay: null }]), null);
});

test("summarizes provider batches without hiding failures", () => {
  const result = { requested: 3, succeeded: ["a"], failed: [{ name: "b", error: "boom" }] };
  assert.equal(
    providerBatchSummary("Proxy providers", result),
    "Proxy providers: 1/3 succeeded, 1 failed (b: boom)",
  );
  assert.equal(providerBatchSucceeded(result), false);
  assert.equal(providerBatchSucceeded({ requested: 1, succeeded: ["a"], failed: [] }), true);
  assert.equal(providerBatchSucceeded({ requested: 2, succeeded: ["a"], failed: [] }), false);
  assert.equal(providerBatchSucceeded({ succeeded: [], failed: [] }), false);
});

test("keeps delay probe failure types distinct", () => {
  assert.equal(delayFailureLabel("timeout"), "Timeout");
  assert.equal(delayFailureLabel("not_found"), "Not found");
  assert.equal(delayFailureLabel("transport"), "Network error");
  assert.equal(delayFailureLabel("invalid_response"), "Invalid response");
  assert.equal(delayFailureLabel("unexpected"), "Probe failed");
});

test("relative profile timestamps never claim a time they do not have", () => {
  assert.equal(formatRelativeUpdated(0), "unknown");
  assert.equal(formatRelativeUpdated(Number.NaN), "unknown");
  assert.equal(formatRelativeUpdated(Math.floor(Date.now() / 1000) - 120), "2 minutes");
});

test("an invalid filter regex degrades to a substring search", () => {
  assert.equal(safeRegex("")?.source, undefined);
  assert.equal(safeRegex("("), null);
  assert.equal(safeRegex("ab")?.test("XABY"), true);
});

test("redacts GitHub, AWS, and Azure signed URL credentials", () => {
  const secrets = [
    "github-sig",
    "generic-signature",
    "aws-signature",
    "aws-credential",
    "azure-expiry",
    "azure-permission",
    "azure-version",
    "detached-signature",
  ];
  const diagnostic = redactDiagnosticText(
    "https://example.test/archive?sig=github-sig&signature=generic-signature"
      + "&X-Amz-Signature=aws-signature&X-Amz-Credential=aws-credential"
      + "&se=azure-expiry&sp=azure-permission&sv=azure-version"
      + " signature=detached-signature",
  );

  for (const secret of secrets) assert.equal(diagnostic.includes(secret), false);
  assert.equal(diagnostic.match(/\[redacted\]/gu)?.length, secrets.length);
});

test("error text is redacted and never empty", () => {
  assert.equal(errorText(new Error("failed: token=abc123")), "failed: token=[redacted]");
  assert.equal(errorText(""), "An unknown error occurred.");
  assert.equal(errorText(undefined), "An unknown error occurred.");
});

test("log rows are bounded, levelled and redacted before display", () => {
  const entry = logEntry("WARN", "s".repeat(200), "https://example.test/p?token=abc123", "12:00:00", [
    { key: "k".repeat(200), value: "token=abc123" },
  ]);
  assert.equal(entry.level, "warning");
  assert.equal(entry.source.length, 64);
  assert.equal(entry.message.includes("abc123"), false);
  assert.equal(entry.fields[0].value.includes("abc123"), false);
  assert.equal(logEntry("info", "s", "m".repeat(5000)).message.length, 4096);

  let logs = [];
  for (let index = 0; index < MAX_LOG_ROWS + 50; index += 1) {
    logs = withLogRow(logs, logEntry("info", "test", `row-${index}`));
  }
  assert.equal(logs.length, MAX_LOG_ROWS);
  assert.equal(logs[0].message, `row-${MAX_LOG_ROWS + 49}`);

  const streamed = withLogRows(logs, [logEntry("info", "engine", "a"), logEntry("info", "engine", "b")]);
  assert.equal(streamed.length, MAX_LOG_ROWS);
  assert.equal(streamed[0].message, "b");
});

test("the bridge refuses a command or event outside its allowlist", async () => {
  await assert.rejects(() => invoke("start_core"), /may invoke/u);
  await assert.rejects(() => listen("cfw://core-status", () => {}), /may subscribe/u);
});
