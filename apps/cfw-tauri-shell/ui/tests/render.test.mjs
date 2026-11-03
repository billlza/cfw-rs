// The dashboard's startup and its full render sweeps: the bootstrap and its
// engine snapshot handshake, every page, dialog and language, and hostile input
// that must neither crash the renderer nor echo attacker text.
// support/render-harness.mjs stubs the WebView and drives the real bootstrap;
// startup-snapshot-handshake.test.mjs runs this file under its other cases.
import assert from "node:assert/strict";
import test from "node:test";
import { t } from "../src/i18n.js";
import {
  DIAGNOSTICS, PAGES, PROFILE_ID, PROJECTION, RUNNING_ENGINE, appModule, bootstrapFailed,
  bootstrapReady, documentStub, emit, glassRoot, invoked, listeners, loginItemWasPending,
  nativeCompletionBeforeListener, nav, renderPage, responses, responsiveBeforeLoginItemReply,
  setEngine, startupInvocationCommands, startupObservedEngine, startupRaceCase, state,
  streamEvent, updateListenerWasReady,
} from "./support/render-harness.mjs";

test("an action nobody handles is refused, never silently rendered", async () => {
  const before = invoked.length;
  await assert.rejects(() => appModule.handleAction("no-such-action"), /Unknown dashboard action: no-such-action/u);
  assert.equal(invoked.length, before, "a refused action reaches no host command");
});

test("startup engine snapshot handshake retains authoritative state", () => {
  assert.equal(nativeCompletionBeforeListener, startupRaceCase !== "after-subscribe");
  assert.equal(bootstrapReady, startupRaceCase !== "listen-refused");
  assert.equal(bootstrapFailed, startupRaceCase === "listen-refused");
  const expectedActive = ["running", "after-subscribe", "stale-read"].includes(startupRaceCase);
  assert.equal(startupObservedEngine.active, expectedActive);
  if (startupRaceCase === "failed") {
    assert.equal(startupObservedEngine.availabilityReason, "native service status unavailable");
  } else if (startupRaceCase === "listen-refused") {
    assert.equal(startupObservedEngine.availabilityReason, "native startup reconciliation is pending");
  } else {
    assert.equal(startupObservedEngine.availabilityReason, null);
  }
  for (const command of ["apply_active_profile", "reconcile_startup_services", "set_core_enabled", "set_system_proxy_enabled", "set_tun_enabled", "set_proxy_mode", "select_profile", "select_proxy", "write_runtime_settings_snapshot", "write_automation_settings"]) {
    assert.equal(startupInvocationCommands.includes(command), false, `startup observation must not invoke ${command}`);
  }
});

test("bootstrap reaches the dashboard instead of the fatal handler", () => {
  assert.equal(documentStub.body.innerHTML.includes("fatal"), false);
  assert.ok(listeners.has("cfw://page"), "the page event is subscribed during bootstrap");
  assert.ok(invoked.includes("boot_payload"));
  assert.ok(invoked.includes("engine_snapshot"));
  assert.equal(
    invoked.includes("acknowledge_migration_handoff_renderer_ready"),
    false,
    "the ordinary dashboard never acknowledges handoff renderer readiness",
  );
  assert.equal(updateListenerWasReady, true, "automatic update check must start after its listener");
});

test("a stalled macOS Login Item query does not prevent dashboard readiness", () => {
  assert.equal(responsiveBeforeLoginItemReply, true);
  assert.equal(loginItemWasPending, true, "pending status must not look like an observed OS state");
});

test("every page renders", async () => {
  for (const { id } of PAGES) {
    const html = await renderPage(id);
    assert.ok(html.length > 200, `page ${id} rendered ${html.length} characters`);
  }
});

test("malformed Login Item state and fatal startup never echo attacker text", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const secret = "<img src=x onerror=fatal-secret>";
  const malformed = {
    ...structuredClone(original),
    launch_at_login: {
      persisted_intent: false,
      live_status: secret,
      matches_persisted_intent: false,
    },
  };
  const originalBody = documentStub.body.innerHTML;

  try {
    responses.read_settings_snapshot = malformed;
    await emit("cfw://settings-changed", malformed);
    assert.equal(state.settingsUnavailableReason !== null, true);
    assert.equal(state.logs.some((entry) => entry.message.includes(secret)), false);

    appModule.renderFatalBootstrap(new Error(`token=fatal-secret ${secret}`));
    assert.match(documentStub.body.innerHTML, /startup_state_unverifiable/u);
    assert.equal(documentStub.body.innerHTML.includes("fatal-secret"), false);
    assert.equal(documentStub.body.innerHTML.includes("<img"), false);
    assert.ok(documentStub.body.innerHTML.length < 512);
  } finally {
    documentStub.body.innerHTML = originalBody;
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
  }
});

test("live stream events do not crash the renderer", async () => {
  await setEngine(RUNNING_ENGINE);
  state.logsPaused = true;
  state.connectionPaused = true;
  await appModule.handleAction("toggle-log-stream");
  await appModule.handleAction("toggle-connection-stream");
  await renderPage("logs");
  await emit("cfw://log-lines", streamEvent("request-logs", [
    { time: "12:00:00", level: "info", source: "engine", message: "hello", fields: [{ key: "k", value: "v" }] },
  ]));
  await emit(
    "cfw://connections-snapshot",
    streamEvent("connections", responses.controller_snapshot.connections),
  );
  await emit("cfw://stream-error", streamEvent("connections", {
    stream: "connections",
    message: "socket closed",
    level: "warning",
  }));
  await emit("cfw://engine-event", { type: "boundary_failure", code: "x", message: "boom" });
  await emit("cfw://update-available", { available: true, version: "0.4.1", current: "0.4.0" });
  assert.equal(state.logs.some((entry) => entry.message === "hello"), true);
  assert.equal(state.logs.some((entry) => entry.message.includes("boom")), true);
});

test("every glass dialog renders", async () => {
  const cases = [
    ["copy", { kind: "copy", id: PROFILE_ID }, "Copy profile"],
    ["settings", { kind: "settings", id: PROFILE_ID }, "Edit profile information"],
    ["delete", { kind: "delete", id: PROFILE_ID }, "Delete profile"],
    ["reset-settings", { kind: "reset-settings" }, "Reset all settings"],
    ["preview-config", { kind: "preview-config", payload: PROJECTION }, "Projected configuration"],
    ["network-services", { kind: "network-services", payload: DIAGNOSTICS }, "Network services"],
    ["dns-query", { kind: "dns-query", payload: { name: "a.test", type: "A", result: "" } }, "Resolve through the running engine"],
    ["info", { kind: "info", payload: { title: "System DNS", body: "never written" } }, "System DNS"],
    ["product-about", { kind: "product-about", payload: { phase: "idle", update: { available: true, version: "0.4.1" } } }, "Open Download"],
    ["credentials", { kind: "credentials", id: PROFILE_ID }, "Reading credential requirements"],
    ["credential-cleanup", { kind: "credential-cleanup" }, "Unused credentials"],
  ];
  for (const [name, dialog, needle] of cases) {
    state.glassDialog = dialog;
    state.credentialSetup = null;
    state.credentialGcPreview = name === "credential-cleanup"
      ? { previewId: "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b", orphanCount: 1, orphanReferences: [{ id: PROFILE_ID, kind: "trojan_password" }] }
      : null;
    glassRoot.innerHTML = "";
    await renderPage("general");
    assert.ok(glassRoot.innerHTML.includes(needle), `dialog ${name} did not render "${needle}"`);
  }
  state.glassDialog = null;
  state.credentialGcPreview = null;
});

test("all dashboard pages render in each language without changing network identity or modes", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const forbidden = new Set(["apply_active_profile", "select_proxy", "select_profile", "set_proxy_mode", "set_core_enabled", "set_system_proxy_enabled", "set_tun_enabled", "write_runtime_settings_snapshot", "write_automation_settings"]);
  try {
    await setEngine(RUNNING_ENGINE);
    const identity = structuredClone(state.engine.runtimeIdentity);
    const before = invoked.length;
    for (const language of ["zh-Hans", "zh-Hant", "ja", "en"]) {
      responses.read_settings_snapshot = { ...original, settings: { ...original.settings, language }, resolved_locale: language };
      await emit("cfw://settings-changed", responses.read_settings_snapshot);
      assert.equal(documentStub.documentElement.lang, language);
      for (const entry of PAGES) {
        const html = await renderPage(entry.id);
        assert.ok(html.trim(), `${language}: ${entry.id}`);
        assert.doesNotMatch(html, /\{(?:count|name|error|number|title|mode)\}/u);
        const navButtons = [...nav.innerHTML.matchAll(/<button\b([^>]*)>/gu)].map((match) => match[1]);
        assert.deepEqual(navButtons.map((attributes) => attributes.match(/data-page="([^"]+)"/u)?.[1]), PAGES.map(({ id }) => id));
        const currentPages = navButtons.filter((attributes) => /aria-current="page"/u.test(attributes));
        const activePages = navButtons.filter((attributes) => /class="[^"]*\bactive\b/u.test(attributes));
        assert.equal(currentPages.length, 1, `${language}: exactly one current navigation page`);
        assert.ok(currentPages[0].includes(`data-page="${entry.id}"`), `${language}: ${entry.id}`);
        assert.deepEqual(currentPages, activePages, `${language}: visible and accessible page state must agree`);
      }
      const general = await renderPage("general");
      assert.ok(general.includes(t("System Proxy")), language);
      assert.ok(general.includes(t("Home Directory")), language);
      const settings = await renderPage("settings");
      assert.ok(settings.includes(t("Language")), language);
      assert.match(settings, new RegExp(`value="${language}" selected`, "u"));
      assert.deepEqual(state.engine.runtimeIdentity, identity);
      assert.equal(state.engine.desiredMode, "system-proxy");
    }
    assert.deepEqual(invoked.slice(before).filter((command) => forbidden.has(command)), []);
  } finally {
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
  }
});
