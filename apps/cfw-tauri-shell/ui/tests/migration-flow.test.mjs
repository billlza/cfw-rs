import { dom, element, host, spy } from "./support/fake-host.mjs";
import { runEngine, stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state, runtime } from "../src/state.js";
import { newCutoverState } from "../src/migration.js";
import {
  acknowledgeMigrationHandoffRendererReady,
  loadBootPayload,
  loadRetirementStatus,
  markCriticalListenersBound,
  markHandoffStatusUnverifiable,
} from "../src/migration-session.js";
import { renderMigrationBanner } from "../src/migration-banner.js";
import { createMigrationActions } from "../src/migration-actions.js";
import { createLegacyMigrationDialog } from "../src/legacy-migration-dialog.js";

const RECEIPT = "34db18b6-9903-4e9f-8854-15648e19e4f3";
const PROFILE = "5b1f5f2a-8c3d-4e5f-9a6b-7c8d9e0f1a2b";
const PREVIEW = "0f8fad5b-d9cb-469f-a165-70867728950e";
const MIGRATED = "886313e1-3b8a-5372-9b90-0c9aee199e5d";
const CHALLENGE = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const lastLog = () => state.logs[0];

const boot = (overrides = {}) => ({
  native_ui: { profile_menu: false, runtime_settings: false, general_switches: false, prompt_dialog: false, window_glass: false },
  product: { name: "Clash for Mac", version: "0.5.1", license: "GPL-3.0-or-later", operating_system: "macos", minimum_os_version: "15.0", architecture: "arm64" },
  migration_handoff: false,
  migration_handoff_status: { state: "idle" },
  migration_handoff_renderer_ready: null,
  ...overrides,
});

beforeEach(async () => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.retirement = null;
  state.legacyMaintenanceOpen = false;
  state.migrationHandoff = false;
  state.cutover = newCutoverState("system_proxy");
  state.activePage = "general";
  state.glassDialog = null;
  state.profiles = [{ id: "work", name: "Work", active: true }];
  state.profilesUnavailableReason = null;
  state.legacyProfileMigrationPreview = null;
  host.respond("boot_payload", boot());
  await loadBootPayload();
  stopEngine();
});

test("the boot payload opens maintenance for a handoff window and for a handoff in progress", async () => {
  assert.equal(state.legacyMaintenanceOpen, false);
  host.respond("boot_payload", boot({ migration_handoff_status: { state: "in_progress" } }));
  await loadBootPayload();
  assert.equal(state.legacyMaintenanceOpen, true);
  state.legacyMaintenanceOpen = false;
  host.respond("boot_payload", boot({ migration_handoff: true, migration_handoff_renderer_ready: { state: "challenge", generation: 1, challenge: CHALLENGE } }));
  await loadBootPayload();
  assert.equal(state.migrationHandoff, true);
  assert.equal(state.legacyMaintenanceOpen, true);
});

test("an untrustworthy handoff status is marked failed and logged", () => {
  markHandoffStatusUnverifiable(new Error("status read failed"));
  assert.deepEqual(state.migrationHandoffStatus, {
    state: "failed",
    code: "migration_handoff_task_failed",
    message: "Migration handoff status could not be verified. Review the application log before retrying.",
  });
  assert.equal(lastLog().message, "Migration handoff state could not be trusted: status read failed");
});

test("a handoff window acknowledges its first migration view once", async () => {
  await acknowledgeMigrationHandoffRendererReady();
  assert.deepEqual(host.commands(), ["boot_payload"], "an ordinary window acknowledges nothing");
  host.respond("boot_payload", boot({ migration_handoff: true, migration_handoff_renderer_ready: { state: "challenge", generation: 4, challenge: CHALLENGE } }));
  await loadBootPayload();
  host.respond("legacy_retirement_status", { state: "awaiting_confirmation" });
  await loadRetirementStatus();
  dom.byId("page", element("section", { querySelector: (selector) => (selector === ".cfw-migration-banner" ? element("div") : null) }));
  runtime.globalEventsBound = true;
  markCriticalListenersBound();
  host.respond("acknowledge_migration_handoff_renderer_ready", null);
  await acknowledgeMigrationHandoffRendererReady();
  assert.deepEqual(host.argsOf("acknowledge_migration_handoff_renderer_ready"), [{ generation: 4, challenge: CHALLENGE }]);
  await acknowledgeMigrationHandoffRendererReady();
  assert.equal(host.argsOf("acknowledge_migration_handoff_renderer_ready").length, 1, "a published acknowledgement is not repeated");
});

test("an unreadable retirement status stays visible as unverifiable", async () => {
  host.respond("legacy_retirement_status", new Error("journal locked"));
  await loadRetirementStatus();
  assert.deepEqual(state.retirement, { state: "unverifiable", message: "journal locked" });
  assert.equal(lastLog().message, "Unable to read the legacy retirement state: journal locked");
  assert.match(renderMigrationBanner(), /cfw-migration-unverifiable[\s\S]*journal locked/u);
});

test("the banner shows completed maintenance with a close button, ongoing cleanup, and expires stale receipts", () => {
  assert.equal(renderMigrationBanner(), "", "no status, no banner");
  state.retirement = { state: "cleared" };
  assert.equal(renderMigrationBanner(), "");
  state.legacyMaintenanceOpen = true;
  const complete = renderMigrationBanner();
  assert.match(complete, /Legacy CFM maintenance is complete/u);
  assert.match(complete, /data-action="close-legacy-maintenance"/u);

  state.retirement = { state: "cleaning" };
  const busy = renderMigrationBanner();
  assert.match(busy, /Legacy CFM maintenance is in progress/u);
  assert.doesNotMatch(busy, /close-legacy-maintenance/u, "running cleanup cannot be closed");

  state.migrationHandoff = true;
  state.retirement = { state: "awaiting_confirmation" };
  state.cutover = { ...newCutoverState("tunnel"), receiptId: RECEIPT, receiptTarget: "tunnel", receiptIssuedAt: 0, receiptExpiresAt: 1 };
  const expired = renderMigrationBanner();
  assert.equal(state.cutover.receiptId, null);
  assert.match(expired, /The cutover preparation expired\. Prepare the replacement again\./u);
  assert.match(expired, /data-action="prepare-cutover"/u);
});

test("maintenance opens on the General page and only an ordinary window can close it", async () => {
  const renderPage = spy();
  const { actions } = createMigrationActions({ renderPage, loadEngineStatus: spy(async () => true) });
  host.respond("legacy_retirement_status", { state: "cleared" });
  host.respond("open_page", null);
  state.activePage = "logs";
  await actions["open-legacy-maintenance"]();
  assert.equal(state.legacyMaintenanceOpen, true);
  assert.equal(state.activePage, "general");
  assert.deepEqual(host.argsOf("open_page"), [{ page: "general" }]);
  await actions["close-legacy-maintenance"]();
  assert.equal(state.legacyMaintenanceOpen, false);
  state.legacyMaintenanceOpen = true;
  state.migrationHandoff = true;
  await actions["close-legacy-maintenance"]();
  assert.equal(state.legacyMaintenanceOpen, true, "the handoff window owns its maintenance");
  await actions["open-migration-profiles"]();
  assert.equal(state.activePage, "profiles");
  assert.equal(renderPage.count(), 4);
});

test("starting the handoff session reports success, or re-reads the boot state after a refusal", async () => {
  const renderPage = spy();
  const { actions } = createMigrationActions({ renderPage, loadEngineStatus: spy(async () => true) });
  host.respond("begin_migration_handoff", null);
  await actions["begin-migration-handoff"]();
  assert.deepEqual(state.migrationHandoffStatus, { state: "in_progress" });
  assert.equal(state.cutover.message, "The verified migration window is ready. This dashboard will now close.");
  assert.equal(lastLog().message, "Launching the signed migration session…");

  host.respond("begin_migration_handoff", new Error("admission refused"));
  host.respond("boot_payload", boot({ migration_handoff_status: { state: "failed", code: "migration_handoff_admission_failed", message: "refused" } }));
  await actions["begin-migration-handoff"]();
  assert.equal(state.migrationHandoffStatus.state, "failed");
  assert.equal(lastLog().message, "Could not start the migration session: admission refused");

  host.respond("boot_payload", new Error("boot unreadable"));
  await actions["begin-migration-handoff"]();
  assert.equal(state.migrationHandoffStatus.code, "migration_handoff_task_failed");
  assert.ok(state.logs.some((entry) => entry.message === "Migration handoff state could not be trusted: boot unreadable"));
  assert.equal(renderPage.count(), 6);
});

test("preparing the cutover records a ready receipt, a pending approval, or the refusal", async () => {
  const { actions } = createMigrationActions({ renderPage: spy(), loadEngineStatus: spy(async () => true) });
  state.cutover = newCutoverState("tunnel");
  host.respond("prepare_legacy_cutover", { status: "ready", receipt_id: RECEIPT, target: "tunnel", profile_id: PROFILE, valid_for_millis: 60_000 });
  await actions["prepare-cutover"]();
  assert.deepEqual(host.argsOf("prepare_legacy_cutover"), [{ target: "tunnel" }]);
  assert.equal(state.cutover.receiptId, RECEIPT);
  assert.equal(state.cutover.receiptTarget, "tunnel");
  assert.equal(state.cutover.busy, false);
  assert.equal(state.cutover.message, "Replacement staged and validated. Confirm the one-way cutover to proceed.");

  host.respond("prepare_legacy_cutover", { status: "awaiting_approval", target: "tunnel" });
  await actions["prepare-cutover"]();
  assert.equal(state.cutover.awaitingApproval, true);
  assert.equal(state.cutover.receiptId, null, "a new preparation drops the previous receipt");
  assert.equal(state.cutover.message, "System Extension approval is pending.");

  host.respond("prepare_legacy_cutover", { status: "ready", receipt_id: "not-a-uuid", target: "tunnel", profile_id: PROFILE, valid_for_millis: 1 });
  await actions["prepare-cutover"]();
  assert.equal(state.cutover.message, "ready response identity is invalid");
  assert.equal(state.cutover.target, "tunnel");
  assert.equal(lastLog().message, "Prepare cutover failed: ready response identity is invalid");
});

function readyCutover(confirmed = true) {
  const now = Date.now();
  return {
    ...newCutoverState("system_proxy"),
    receiptId: RECEIPT,
    receiptTarget: "system_proxy",
    receiptIssuedAt: now - 1,
    receiptExpiresAt: now + 60_000,
    confirmedReceiptId: confirmed ? RECEIPT : null,
    dnsReviewedReceiptId: RECEIPT,
  };
}

test("the one-way cutover needs a current, confirmed receipt and reloads state after either outcome", async () => {
  const loadEngineStatus = spy(async () => true);
  const { actions } = createMigrationActions({ renderPage: spy(), loadEngineStatus });
  await actions["confirm-cutover"]();
  assert.equal(state.cutover.message, "Cutover receipt is missing or expired; run Prepare again.");
  assert.deepEqual(host.argsOf("disable_service_mode"), []);
  state.cutover = readyCutover(false);
  await actions["confirm-cutover"]();
  assert.equal(state.cutover.message, "Tick the one-way cutover confirmation for this preparation.");
  assert.equal(state.cutover.receiptId, RECEIPT, "an unticked confirmation keeps its receipt");

  state.cutover = readyCutover();
  host.respond("disable_service_mode", null);
  host.respond("legacy_retirement_status", { state: "cleared" });
  await actions["confirm-cutover"]();
  assert.deepEqual(host.argsOf("disable_service_mode"), [{ receiptId: RECEIPT, cutoverConfirmed: true, dnsReviewConfirmed: true }]);
  assert.equal(state.cutover.message, "Cutover complete. Replacement networking is active.");
  assert.equal(state.cutover.receiptId, null);
  assert.equal(loadEngineStatus.count(), 1);
  assert.deepEqual(state.retirement, { state: "cleared" });

  state.cutover = readyCutover();
  host.respond("disable_service_mode", new Error("legacy daemon busy"));
  await actions["confirm-cutover"]();
  assert.equal(state.cutover.message, "legacy daemon busy");
  assert.equal(state.cutover.busy, false);
  assert.equal(lastLog().message, "Cutover failed: legacy daemon busy");
});

test("recovery of an interrupted cutover reports both outcomes and re-reads the status", async () => {
  const loadEngineStatus = spy(async () => true);
  const { actions } = createMigrationActions({ renderPage: spy(), loadEngineStatus });
  host.respond("recover_legacy_cutover", null);
  host.respond("legacy_retirement_status", { state: "cleared" });
  await actions["recover-cutover"]();
  assert.equal(state.cutover.message, "Recovery complete.");
  assert.equal(lastLog().message, "Interrupted cutover recovered.");
  host.respond("recover_legacy_cutover", new Error("no journal"));
  await actions["recover-cutover"]();
  assert.equal(state.cutover.message, "no journal");
  assert.equal(state.cutover.busy, false);
  assert.equal(host.argsOf("legacy_retirement_status").length, 2);
});

test("the cutover form records consent per receipt and a target change drops the receipt", async () => {
  const renderPage = spy();
  const confirm = dom.set("[data-cutover-confirm]", element("input"));
  const dns = dom.set("[data-cutover-dns-review]", element("input"));
  const target = dom.set("[data-cutover-target]", element("select"));
  createMigrationActions({ renderPage, loadEngineStatus: spy() }).bindPage();
  state.cutover = readyCutover(false);
  await confirm.fire("change", { currentTarget: { checked: true } });
  assert.equal(state.cutover.confirmedReceiptId, RECEIPT);
  await confirm.fire("change", { currentTarget: { checked: false } });
  assert.equal(state.cutover.confirmedReceiptId, null);
  await dns.fire("change", { currentTarget: { checked: true } });
  assert.equal(state.cutover.dnsReviewedReceiptId, RECEIPT);
  await dns.fire("change", { currentTarget: { checked: false } });
  assert.equal(state.cutover.dnsReviewedReceiptId, null);
  await target.fire("change", { currentTarget: { value: "elsewhere" } });
  assert.equal(state.cutover.receiptId, RECEIPT, "an unknown target is ignored");
  await target.fire("change", { currentTarget: { value: "tunnel" } });
  assert.equal(state.cutover.target, "tunnel");
  assert.equal(state.cutover.receiptId, null);
  assert.equal(renderPage.count(), 1);
});

function legacyDialog(overrides = {}) {
  return createLegacyMigrationDialog({
    renderPage: spy(),
    renderGlassOverlays: spy(),
    closeGlassOverlays: spy(),
    loadProfilesSnapshot: spy(async () => true),
    applyActiveProfile: spy(async () => ({ applied: true })),
    ...overrides,
  });
}

const preview = { status: "ready", preview_id: PREVIEW, name: "iKuuu", source_host: "example.test", legacy_bytes: 2048, active: true };

test("migrating the legacy subscription previews it with the engine Off and a readable repository", async () => {
  const dialog = legacyDialog();
  const migrate = dialog.actions["migrate-legacy-profiles"];
  state.profilesUnavailableReason = "repository locked";
  await migrate();
  assert.equal(lastLog().message, "Profile repository is unavailable: repository locked");
  state.profilesUnavailableReason = null;
  runEngine();
  await migrate();
  assert.equal(lastLog().message, "Stop the core before credential maintenance or legacy migration.");
  stopEngine();

  host.respond("preview_legacy_cfw_profile_migration", preview);
  await migrate();
  assert.deepEqual(state.glassDialog, { kind: "legacy-profile-migration", payload: preview, busy: false, error: null });
  assert.deepEqual(state.legacyProfileMigrationPreview, preview);

  host.respond("preview_legacy_cfw_profile_migration", { status: "not_subscription", name: "Local", legacy_bytes: 10, reason: "It is a local file." });
  await migrate();
  assert.deepEqual(state.glassDialog, { kind: "info", payload: { title: "Legacy profile is local", body: "It is a local file." } });
  assert.equal(state.legacyProfileMigrationPreview, null);

  host.respond("preview_legacy_cfw_profile_migration", { status: "no_active_profile" });
  await migrate();
  assert.equal(state.glassDialog.payload.title, "No selected legacy subscription");

  host.respond("preview_legacy_cfw_profile_migration", new Error("legacy settings unreadable"));
  await migrate();
  assert.deepEqual(state.glassDialog, { kind: "info", payload: { title: "Legacy migration failed", body: "legacy settings unreadable" } });
  assert.equal(lastLog().message, "Legacy profile preview failed: legacy settings unreadable");
});

test("the migration dialog shows its size, host and progress, and refuses a repeated confirmation", async () => {
  const dialog = legacyDialog();
  const html = dialog.dialogs.render({ kind: "legacy-profile-migration", payload: preview, busy: true, error: "earlier failure" });
  assert.match(html, /Convert the 2\.0 KB legacy YAML snapshot saved on this Mac for “iKuuu”/u);
  assert.match(html, /example\.test is retained only as the HTTPS update source/u);
  assert.match(html, /role="alert">earlier failure/u);
  assert.match(html, /disabled>Migrating…/u);

  const confirm = element("button", { dataset: { previewId: PREVIEW } });
  const blank = element("button", { dataset: {} });
  dom.setAll("[data-glass-legacy-migration-confirm]", [confirm, blank]);
  dialog.dialogs.bind();
  await blank.fire("click");
  state.glassDialog = { kind: "info" };
  await confirm.fire("click");
  state.glassDialog = { kind: "legacy-profile-migration", payload: preview, busy: true };
  await confirm.fire("click");
  assert.deepEqual(host.commands().filter((command) => command.startsWith("commit")), []);
});

test("a confirmed migration is committed, selected and applied, and each failure keeps its preview unusable", async () => {
  const applyActiveProfile = spy(async () => ({}));
  const dialog = legacyDialog({ applyActiveProfile });
  const confirm = element("button", { dataset: { previewId: PREVIEW } });
  dom.setAll("[data-glass-legacy-migration-confirm]", [confirm]);
  dialog.dialogs.bind();

  const open = () => {
    state.glassDialog = { kind: "legacy-profile-migration", payload: preview, busy: false, error: null };
    state.legacyProfileMigrationPreview = preview;
  };
  open();
  host.respond("commit_legacy_cfw_profile_migration", { id: MIGRATED, name: "iKuuu", bytes: 4096, digest: "a".repeat(64), reused: false, selected: true });
  await confirm.fire("click");
  assert.deepEqual(host.argsOf("commit_legacy_cfw_profile_migration"), [{ previewId: PREVIEW, confirmed: true }]);
  assert.deepEqual(applyActiveProfile.calls, [["migrating iKuuu"]]);
  assert.equal(lastLog().message, "iKuuu imported, credentials verified, and selected");
  assert.equal(state.legacyProfileMigrationPreview, null);

  open();
  host.respond("commit_legacy_cfw_profile_migration", { id: MIGRATED, name: "iKuuu", bytes: 4096, digest: "a".repeat(64), reused: true, selected: true });
  await confirm.fire("click");
  assert.equal(lastLog().message, "iKuuu recovered, credentials verified, and selected");

  open();
  host.respond("commit_legacy_cfw_profile_migration", new Error("preview consumed"));
  await confirm.fire("click");
  assert.equal(state.glassDialog.payload.title, "Legacy migration failed");
  assert.match(state.glassDialog.payload.body, /^preview consumed The one-shot preview is no longer trusted/u);
  assert.equal(lastLog().message, "Legacy profile migration failed: preview consumed");

  open();
  host.respond("commit_legacy_cfw_profile_migration", { id: MIGRATED, name: "iKuuu", bytes: 4096, digest: "a".repeat(64), reused: false, selected: true });
  const failing = legacyDialog({ applyActiveProfile: spy(async () => { throw new Error("engine refused"); }) });
  dom.setAll("[data-glass-legacy-migration-confirm]", [element("button", { dataset: { previewId: PREVIEW } })]);
  failing.dialogs.bind();
  await document.querySelectorAll("[data-glass-legacy-migration-confirm]")[0].fire("click");
  assert.equal(state.glassDialog.payload.title, "Profile migrated; activation failed");
  assert.equal(lastLog().message, "Migrated profile staging failed: engine refused");
});
