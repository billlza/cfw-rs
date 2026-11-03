// The legacy migration: a failed commit, the cached snapshot, explicit
// maintenance, unfinished transactions, hand-off recovery, and the exact
// command arguments.
import assert from "node:assert/strict";
import test from "node:test";
import {
  PROFILE_ID, appModule, emit, glassRoot, interactiveElement, invocationDetails, page,
  querySelectorAllElements, rejected, renderPage, responses, state,
} from "./support/render-harness.mjs";

test("a failed legacy commit discards the consumed preview and stale retry button", async () => {
  const preview = {
    status: "ready",
    preview_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    name: "Migrated profile",
    source_host: "subscription.example",
    legacy_bytes: 494575,
    active: true,
  };
  const confirm = interactiveElement();
  confirm.dataset.previewId = preview.preview_id;
  rejected.commit_legacy_cfw_profile_migration = "credential vault access was denied";
  state.legacyProfileMigrationPreview = preview;
  state.glassDialog = { kind: "legacy-profile-migration", payload: preview, busy: false, error: null };
  querySelectorAllElements.set("[data-glass-legacy-migration-confirm]", [confirm]);

  try {
    await renderPage("profiles");
    await confirm.trigger("click");
    assert.equal(state.legacyProfileMigrationPreview, null);
    assert.equal(state.glassDialog?.kind, "info");
    assert.match(state.glassDialog?.payload?.body ?? "", /preview the legacy profile again/u);
  } finally {
    delete rejected.commit_legacy_cfw_profile_migration;
    querySelectorAllElements.clear();
    state.glassDialog = null;
    state.legacyProfileMigrationPreview = null;
  }
});

test("legacy migration describes a local cached snapshot and makes no download claim", async () => {
  const originalDialog = state.glassDialog;
  state.glassDialog = {
    kind: "legacy-profile-migration",
    payload: {
      status: "ready",
      preview_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      name: "Cached subscription",
      source_host: "subscription.example",
      legacy_bytes: 4096,
      active: true,
    },
    busy: false,
    error: null,
  };

  try {
    glassRoot.innerHTML = "";
    await renderPage("profiles");
    assert.match(glassRoot.innerHTML, /legacy YAML snapshot saved on this Mac/u);
    assert.match(glassRoot.innerHTML, /Migration does not download a newer subscription/u);
    assert.match(glassRoot.innerHTML, /retained only as the HTTPS update source/u);
    assert.match(glassRoot.innerHTML, /cached YAML is never executed/u);
    assert.doesNotMatch(glassRoot.innerHTML, /using the current HTTPS subscription/u);
  } finally {
    state.glassDialog = originalDialog;
    glassRoot.innerHTML = "";
  }
});

test("legacy maintenance is an explicit Settings action and keeps its profile precondition", async () => {
  const originalProfiles = state.profiles;
  const originalRetirement = state.retirement;
  const originalHandoff = state.migrationHandoff;
  const originalMaintenance = state.legacyMaintenanceOpen;
  const originalRetirementResponse = responses.legacy_retirement_status;

  try {
    state.profiles = [];
    state.retirement = { state: "awaiting_confirmation" };
    state.migrationHandoff = false;
    state.legacyMaintenanceOpen = false;
    responses.legacy_retirement_status = state.retirement;
    assert.doesNotMatch(await renderPage("general"), /cfw-content-migration|Start Migration|Finish setup/u);
    assert.match(await renderPage("settings"), /data-action="open-legacy-maintenance"/u);
    invocationDetails.length = 0;
    await appModule.handleAction("open-legacy-maintenance");
    assert.deepEqual(invocationDetails, [
      { command: "legacy_retirement_status", args: {} },
      { command: "open_page", args: { page: "general" } },
    ]);
    const html = page.innerHTML;
    assert.match(html, /cfw-content-migration/u);
    assert.match(html, /Optional legacy CFM maintenance/u);
    assert.match(html, /Import and select a replacement profile/u);
    assert.match(html, /data-action="open-migration-profiles"/u);
    assert.doesNotMatch(html, /data-action="begin-migration-handoff"/u);

    await appModule.handleAction("open-migration-profiles");
    assert.equal(state.activePage, "profiles");
    assert.deepEqual(invocationDetails.at(-1), {
      command: "open_page",
      args: { page: "profiles" },
    });
    await appModule.handleAction("close-legacy-maintenance");
    assert.equal(state.legacyMaintenanceOpen, false);
    assert.doesNotMatch(await renderPage("general"), /cfw-migration-banner/u);
  } finally {
    state.profiles = originalProfiles;
    state.retirement = originalRetirement;
    state.migrationHandoff = originalHandoff;
    state.legacyMaintenanceOpen = originalMaintenance;
    responses.legacy_retirement_status = originalRetirementResponse;
  }
});

test("an unfinished legacy transaction exposes recovery even when maintenance was not opened", async () => {
  const originalRetirement = state.retirement;
  const originalHandoff = state.migrationHandoff;
  const originalMaintenance = state.legacyMaintenanceOpen;
  try {
    state.retirement = { state: "recovery_start_required", target: "tunnel", message: "durable journal remains" };
    state.migrationHandoff = false;
    state.legacyMaintenanceOpen = false;
    const html = await renderPage("general");
    assert.match(html, /durable journal remains/u);
    assert.match(html, /data-action="begin-migration-handoff"[^>]*>Open Recovery/u);
    assert.doesNotMatch(html, /Prepare cutover|Finish setup/u);
    await appModule.handleAction("close-legacy-maintenance");
    assert.match(page.innerHTML, /Open Recovery/u);
  } finally {
    state.retirement = originalRetirement;
    state.migrationHandoff = originalHandoff;
    state.legacyMaintenanceOpen = originalMaintenance;
  }
});

test("renderer refresh recovers app-owned handoff progress and terminal failure", async () => {
  state.migrationHandoff = false;
  state.retirement = { state: "awaiting_confirmation" };
  responses.boot_payload.migration_handoff_status = { state: "in_progress" };
  await emit("cfw://engine-event", {
    type: "boundary_failure",
    code: "migration_handoff_failed",
    message: "refresh",
  });
  let html = await renderPage("general");
  assert.equal(state.migrationHandoffStatus.state, "in_progress");
  assert.match(html, /Legacy CFM maintenance session is starting/u);
  assert.match(html, /data-action="begin-migration-handoff" disabled>Starting…/u);

  responses.boot_payload.migration_handoff_status = {
    state: "failed",
    code: "migration_handoff_failed",
    message: "The migration session did not complete. No legacy cutover was authorized; review the migration log and retry.",
  };
  await emit("cfw://engine-event", {
    type: "boundary_failure",
    code: "migration_handoff_failed",
    message: "refresh",
  });
  html = await renderPage("general");
  assert.equal(state.migrationHandoffStatus.state, "failed");
  assert.match(html, /No legacy cutover was authorized/u);
  assert.match(html, /Retry Maintenance…/u);
  assert.doesNotMatch(html, /begin-migration-handoff" disabled/u);

  rejected.begin_migration_handoff = "injected readiness failure";
  await appModule.handleAction("begin-migration-handoff");
  assert.equal(state.migrationHandoffStatus.state, "failed");
  assert.equal(invocationDetails.at(-2).command, "begin_migration_handoff");
  assert.equal(invocationDetails.at(-1).command, "boot_payload");
  delete rejected.begin_migration_handoff;

  responses.boot_payload.migration_handoff_status = { state: "idle" };
  state.migrationHandoffStatus = { state: "idle" };
  state.retirement = { state: "cleared" };
  state.legacyMaintenanceOpen = false;
});

test("migration actions invoke exact target, receipt and confirmation arguments", async () => {
  state.migrationHandoff = true;
  state.retirement = { state: "awaiting_confirmation" };
  state.cutover = {
    ...state.cutover,
    target: "tunnel",
    receiptId: null,
  };
  responses.prepare_legacy_cutover = { status: "awaiting_approval", target: "tunnel" };
  await appModule.handleAction("prepare-cutover");
  assert.deepEqual(invocationDetails.at(-1), {
    command: "prepare_legacy_cutover",
    args: { target: "tunnel" },
  });
  assert.equal(state.cutover.awaitingApproval, true);
  assert.equal(state.cutover.receiptId, null);

  responses.prepare_legacy_cutover = {
    status: "ready",
    receipt_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    target: "tunnel",
    profile_id: PROFILE_ID,
    valid_for_millis: 60_000,
  };
  await appModule.handleAction("prepare-cutover");
  state.cutover.confirmedReceiptId = state.cutover.receiptId;
  state.cutover.dnsReviewedReceiptId = state.cutover.receiptId;
  responses.disable_service_mode = null;
  responses.legacy_retirement_status = { state: "cleared" };
  await appModule.handleAction("confirm-cutover");
  const disable = invocationDetails.findLast((entry) => entry.command === "disable_service_mode");
  assert.deepEqual(disable, {
    command: "disable_service_mode",
    args: {
      receiptId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      cutoverConfirmed: true,
      dnsReviewConfirmed: true,
    },
  });

  state.migrationHandoff = false;
  state.retirement = { state: "cleared" };
});
