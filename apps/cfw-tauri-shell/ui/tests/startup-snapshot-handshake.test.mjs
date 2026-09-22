import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Separate renderer lifetimes keep every case's subscriptions and request IDs
// independent while executing the same real app.js bootstrap/render harness.
for (const scenario of ["off", "failed", "listen-refused", "after-subscribe", "stale-read"]) {
  test(`startup snapshot handshake: ${scenario}`, () => {
    const environment = { ...process.env, CFM_TEST_STARTUP_RACE: scenario };
    delete environment.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, [
      "--test", "--test-name-pattern=startup engine snapshot handshake retains authoritative state",
      fileURLToPath(new URL("./render.test.mjs", import.meta.url)),
    ], { env: environment, encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /pass 1/u);
  });
}
