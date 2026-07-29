import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  clearCutoverReceipt,
  cutoverConfirmArguments,
  cutoverReceiptIsCurrent,
  migrationHandoffRendererAckArguments,
  migrationRoute,
  newCutoverState,
  normalizeBootPayload,
  normalizeCutoverPreparation,
  normalizeMigrationHandoffStatus,
  normalizeRetirementStatus,
  unverifiableRetirementStatus,
} from "../src/migration.js";

const RECEIPT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PROFILE = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CHALLENGE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

function bootPayload({ handoff = false, rendererReady = null } = {}) {
  return {
    product: {
      name: "Clash for Mac",
      version: "0.4.0",
      license: "GPL-3.0-or-later",
      minimum_macos: "15.0",
      architecture: "arm64",
    },
    migration_handoff: handoff,
    migration_handoff_status: { state: "idle" },
    migration_handoff_renderer_ready: rendererReady,
  };
}

test("boot payload strictly separates dashboard, challenge and published renderer states", () => {
  assert.deepEqual(
    normalizeBootPayload(bootPayload()).migration_handoff_renderer_ready,
    null,
  );
  assert.deepEqual(
    normalizeBootPayload(bootPayload({
      handoff: true,
      rendererReady: { state: "challenge", generation: 1, challenge: CHALLENGE },
    })).migration_handoff_renderer_ready,
    { state: "challenge", generation: 1, challenge: CHALLENGE },
  );
  assert.deepEqual(
    normalizeBootPayload(bootPayload({
      handoff: true,
      rendererReady: { state: "published" },
    })).migration_handoff_renderer_ready,
    { state: "published" },
  );

  for (const invalid of [
    { ...bootPayload(), token: "startup-secret" },
    bootPayload({ rendererReady: { state: "published" } }),
    bootPayload({ handoff: true, rendererReady: null }),
    bootPayload({ handoff: true, rendererReady: { state: "challenge", generation: 0, challenge: CHALLENGE } }),
    bootPayload({ handoff: true, rendererReady: { state: "challenge", generation: 1.5, challenge: CHALLENGE } }),
    bootPayload({ handoff: true, rendererReady: { state: "challenge", generation: 1, challenge: CHALLENGE.toUpperCase() } }),
    bootPayload({ handoff: true, rendererReady: { state: "challenge", generation: 1, challenge: "aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa" } }),
    bootPayload({ handoff: true, rendererReady: { state: "unknown" } }),
  ]) {
    assert.throws(() => normalizeBootPayload(invalid), /invalid|requires|cannot/u);
  }
});

test("renderer ACK requires the current actionable General migration view and bound handlers", () => {
  const challengeBoot = normalizeBootPayload(bootPayload({
    handoff: true,
    rendererReady: { state: "challenge", generation: 7, challenge: CHALLENGE },
  }));
  const readyContext = {
    activePage: "general",
    migrationRendered: true,
    globalActionsBound: true,
    criticalListenersBound: true,
  };
  assert.deepEqual(
    migrationHandoffRendererAckArguments(
      challengeBoot,
      { state: "awaiting_confirmation" },
      readyContext,
    ),
    { generation: 7, challenge: CHALLENGE },
  );
  assert.equal(
    migrationHandoffRendererAckArguments(
      normalizeBootPayload(bootPayload()),
      { state: "awaiting_confirmation" },
      readyContext,
    ),
    null,
  );
  assert.equal(
    migrationHandoffRendererAckArguments(
      normalizeBootPayload(bootPayload({
        handoff: true,
        rendererReady: { state: "published" },
      })),
      { state: "cleared" },
      readyContext,
    ),
    null,
  );
  assert.equal(
    migrationHandoffRendererAckArguments(
      challengeBoot,
      { state: "unverifiable", message: "unreadable" },
      readyContext,
    ),
    null,
  );
  for (const context of [
    { ...readyContext, activePage: "settings" },
    { ...readyContext, migrationRendered: false },
    { ...readyContext, globalActionsBound: false },
    { ...readyContext, criticalListenersBound: false },
  ]) {
    assert.throws(
      () => migrationHandoffRendererAckArguments(
        challengeBoot,
        { state: "awaiting_confirmation" },
        context,
      ),
      /not ready/u,
    );
  }
  for (const retirement of [{ state: "cleared" }, { state: "cleaning" }]) {
    assert.throws(
      () => migrationHandoffRendererAckArguments(challengeBoot, retirement, readyContext),
      /no actionable/u,
    );
  }
});

test("handoff status is closed, bounded and reload-safe", () => {
  assert.deepEqual(normalizeMigrationHandoffStatus({ state: "idle" }), { state: "idle" });
  assert.deepEqual(
    normalizeMigrationHandoffStatus({ state: "in_progress" }),
    { state: "in_progress" },
  );
  assert.deepEqual(normalizeMigrationHandoffStatus({
    state: "failed",
    code: "migration_handoff_failed",
    message: "safe failure",
  }), {
    state: "failed",
    code: "migration_handoff_failed",
    message: "safe failure",
  });
  for (const invalid of [
    { state: "unknown" },
    { state: "in_progress", message: "extra" },
    { state: "failed", code: "unknown", message: "failure" },
    { state: "failed", code: "migration_handoff_failed", message: "x".repeat(513) },
  ]) {
    assert.throws(() => normalizeMigrationHandoffStatus(invalid), /invalid|too long/u);
  }
});

test("every durable retirement status has one explicit migration route", () => {
  const cases = [
    [{ state: "awaiting_confirmation" }, "launch_prepare", "prepare"],
    [{ state: "manual_cleanup_required", action: "review_dns", message: "review" }, "launch_prepare", "prepare"],
    [{ state: "manual_cleanup_required", action: "retry", message: "retry" }, "launch_recovery", "recover"],
    [{ state: "recovery_start_required", target: "tunnel", message: "resume" }, "launch_recovery", "recover"],
    [{ state: "post_cutover_cleanup_required", message: "old data" }, "launch_recovery", "recover"],
    [{ state: "cleaning" }, "busy", "busy"],
    [{ state: "cleared" }, "none", "none"],
  ];
  for (const [raw, dashboard, handoff] of cases) {
    const normalized = normalizeRetirementStatus(raw);
    assert.equal(migrationRoute(normalized, false), dashboard);
    assert.equal(migrationRoute(normalized, true), handoff);
  }
  const unreadable = unverifiableRetirementStatus("journal unreadable");
  assert.equal(migrationRoute(unreadable, false), "unverifiable");
  assert.equal(migrationRoute(unreadable, true), "unverifiable");
});

test("unknown or structurally ambiguous status fails instead of routing to Prepare", () => {
  for (const value of [
    null,
    { state: "future_state" },
    { state: "awaiting_confirmation", message: "unexpected" },
    { state: "manual_cleanup_required", action: "unknown", message: "x" },
    { state: "recovery_start_required", target: "off", message: "x" },
  ]) {
    assert.throws(() => normalizeRetirementStatus(value), /invalid|unknown/u);
  }
});

test("prepare accepts only exact ready or approval responses bound to the target", () => {
  const ready = normalizeCutoverPreparation({
    status: "ready",
    receipt_id: RECEIPT,
    target: "tunnel",
    profile_id: PROFILE,
    valid_for_millis: 5000,
  }, "tunnel", 1000);
  assert.deepEqual(ready, {
    status: "ready",
    receiptId: RECEIPT,
    profileId: PROFILE,
    target: "tunnel",
    issuedAt: 1000,
    expiresAt: 6000,
  });
  assert.deepEqual(
    normalizeCutoverPreparation({ status: "awaiting_approval", target: "tunnel" }, "tunnel", 1000),
    { status: "awaiting_approval", target: "tunnel" },
  );
  for (const invalid of [
    { status: "unknown", target: "tunnel" },
    { status: "awaiting_approval", target: "system_proxy" },
    { status: "awaiting_approval", target: "tunnel", receipt_id: RECEIPT },
    { status: "ready", receipt_id: RECEIPT, target: "tunnel", profile_id: PROFILE, valid_for_millis: 0 },
    { status: "ready", receipt_id: RECEIPT, target: "tunnel", profile_id: PROFILE, valid_for_millis: 5000, extra: true },
  ]) {
    assert.throws(() => normalizeCutoverPreparation(invalid, "tunnel", 1000), /unknown|invalid|bind/u);
  }
});

test("receipt expiry and checkboxes are bound to the current preparation", () => {
  const cutover = {
    ...newCutoverState("system_proxy"),
    receiptId: RECEIPT,
    receiptTarget: "system_proxy",
    receiptIssuedAt: 1000,
    receiptExpiresAt: 6000,
    confirmedReceiptId: RECEIPT,
    dnsReviewedReceiptId: RECEIPT,
  };
  assert.equal(cutoverReceiptIsCurrent(cutover, 5999), true);
  assert.deepEqual(cutoverConfirmArguments(cutover, 5999), {
    receiptId: RECEIPT,
    cutoverConfirmed: true,
    dnsReviewConfirmed: true,
  });
  assert.equal(cutoverReceiptIsCurrent(cutover, 6000), false);
  assert.throws(() => cutoverConfirmArguments(cutover, 6000), /expired/u);

  const next = clearCutoverReceipt(cutover, { targetValue: "tunnel", message: "retry approval" });
  assert.equal(next.target, "tunnel");
  assert.equal(next.receiptId, null);
  assert.equal(next.confirmedReceiptId, null);
  assert.equal(next.dnsReviewedReceiptId, null);
  assert.equal(next.message, "retry approval");
});

test("confirmation never accepts a checkbox from another receipt", () => {
  const cutover = {
    ...newCutoverState("tunnel"),
    receiptId: RECEIPT,
    receiptTarget: "tunnel",
    receiptIssuedAt: 1000,
    receiptExpiresAt: 6000,
    confirmedReceiptId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  };
  assert.throws(() => cutoverConfirmArguments(cutover, 2000), /confirmation/u);
});

function declarations(body) {
  return Object.fromEntries(
    body
      .split(";")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => {
        const separator = entry.indexOf(":");
        return [entry.slice(0, separator).trim(), entry.slice(separator + 1).trim()];
      }),
  );
}

function compactMigrationButtonStyle(styles) {
  const matching = new Set([
    ".cfw-big-button",
    ".cfw-migration-banner > .cfw-big-button",
    ".cfw-migration-confirm + .cfw-big-button",
  ]);
  const computed = new Map();
  for (const match of styles.matchAll(/(?<selectors>[^{}]+)\{(?<body>[^{}]*)\}/gu)) {
    for (const selector of match.groups.selectors.split(",").map((value) => value.trim())) {
      if (!matching.has(selector)) continue;
      const specificity = (selector.match(/\.|\[/gu) ?? []).length;
      for (const [property, value] of Object.entries(declarations(match.groups.body))) {
        const current = computed.get(property);
        if (!current || specificity >= current.specificity) {
          computed.set(property, { specificity, value });
        }
      }
    }
  }
  return Object.fromEntries([...computed].map(([property, value]) => [property, value.value]));
}

test("migration CSS computes a non-clipping long action at the compact 850x603 breakpoint", async () => {
  const styles = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const computed = compactMigrationButtonStyle(styles);
  assert.equal(computed.width, "100%", "compact migration action overrides the global 84px width");
  assert.equal(computed.height, "auto", "long migration copy can grow beyond the global 45px height");
  assert.equal(computed["min-height"], "45px");
  assert.equal(computed["white-space"], "normal");
  assert.equal(computed["overflow-wrap"], "anywhere");
  assert.match(
    styles,
    /\.cfw-migration-confirm input\[type="checkbox"\]:focus-visible\s*\{[^}]*outline:\s*2px solid var\(--accent\)[^}]*outline-offset:\s*2px/su,
  );
  assert.match(styles, /@media \(max-width: 900px\), \(max-height: 620px\)/u);
  assert.doesNotMatch(styles, /\.cfw-row\s*\{[^}]*migration/u);
});

test("renderer ACK remains after first render and every critical migration listener", async () => {
  const source = await readFile(new URL("../src/app.js", import.meta.url), "utf8");
  const start = source.indexOf("async function bootstrap()");
  const end = source.indexOf("\nasync function importProfileFromPath", start);
  assert.ok(start >= 0 && end > start, "bootstrap source boundary exists");
  const bootstrap = source.slice(start, end);
  const ordered = [
    "bindGlobalEvents();",
    "await loadBootPayload();",
    "renderPage();",
    'await listen("cfw://engine-event"',
    'await listen("tauri://drag-drop"',
    "criticalMigrationListenersBound = true;",
    "await loadRetirementStatus();",
    "renderPage();",
    "await acknowledgeMigrationHandoffRendererReady();",
    "if (state.toggles.checkForUpdates)",
  ];
  let cursor = -1;
  for (const marker of ordered) {
    const next = bootstrap.indexOf(marker, cursor + 1);
    assert.ok(next > cursor, `${marker} stays after the prior readiness boundary`);
    cursor = next;
  }
  assert.match(
    bootstrap,
    /if \(!state\.migrationHandoff\) \{\s*try \{\s*await loadBootPayload\(\);/su,
    "handoff events never rotate the renderer challenge inside one JS lifetime",
  );
});
