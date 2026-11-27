// Dismissing a dialog through the overlay layer, as Escape does, while the
// shortcuts and network rules read: their form opens once the read ends, as
// it does once a dialog that opened meanwhile was closed again.
import test from "node:test";
import assert from "node:assert/strict";
import { appModule, deferred, documentListeners, glassRoot, renderPage, responses, state } from "./support/render-harness.mjs";

test("a dialog dismissed while the shortcuts and network rules read takes nothing from them", async () => {
  const pending = deferred();
  responses.read_automation_settings = () => pending.promise;
  try {
    await renderPage("settings");
    const opening = appModule.handleAction("open-automation-settings");
    await appModule.handleAction("reset-settings");
    assert.equal(state.glassDialog?.kind, "reset-settings");
    for (const handler of documentListeners.get("keydown") ?? []) handler({ key: "Escape", preventDefault() {} });
    assert.equal(state.glassDialog, null, "Escape dismissed the confirmation");
    pending.resolve({ settings: { shortcuts: [], network_enabled: false, network_rules: [] }, revision: "automation-v1",
      network: { kind: "wifi", interface: "en0", ssid: null } });
    await opening;
    assert.equal(state.automationDialog?.snapshot.revision, "automation-v1");
    assert.match(glassRoot.innerHTML, /aria-labelledby="automation-title"/u);
  } finally {
    state.automationDialog = null;
    delete responses.read_automation_settings;
    await renderPage("settings");
  }
});
