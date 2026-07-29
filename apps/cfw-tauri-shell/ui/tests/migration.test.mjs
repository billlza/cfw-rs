import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  clearCutoverReceipt,
  cutoverConfirmArguments,
  cutoverReceiptIsCurrent,
  migrationRoute,
  newCutoverState,
  normalizeCutoverPreparation,
  normalizeRetirementStatus,
  unverifiableRetirementStatus,
} from "../src/migration.js";

const RECEIPT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PROFILE = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

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

test("migration CSS is bounded inside the existing compact General viewport", async () => {
  const styles = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const rule = styles.match(/\.cfw-migration-banner\s*\{(?<body>[^}]+)\}/u)?.groups?.body ?? "";
  assert.match(rule, /max-width:\s*100%/u);
  assert.match(rule, /max-height:\s*154px/u);
  assert.match(rule, /overflow:\s*auto/u);
  assert.match(rule, /box-sizing:\s*border-box/u);
  assert.match(styles, /@media \(max-width: 900px\), \(max-height: 620px\)/u);
  assert.doesNotMatch(styles, /\.cfw-row\s*\{[^}]*migration/u);
});
