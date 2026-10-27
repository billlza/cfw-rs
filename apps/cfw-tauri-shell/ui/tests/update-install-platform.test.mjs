import assert from "node:assert/strict";
import test from "node:test";
import { setLocale, SUPPORTED_LOCALES } from "../src/i18n.js";
import { IDLE_UPDATE_INSTALL, createUpdateInstall, installFailureText, updateInstallView } from "../src/update-install.js";

const update = { available: true, version: "0.5.1", install: { supported: true } };
const ready = { ...IDLE_UPDATE_INSTALL, phase: "ready", version: "0.5.1" };

test("Windows update failures and handoff describe the Windows package", () => {
  setLocale("en");
  for (const category of ["environment", "storage", "package"]) {
    const message = installFailureText({ category, code: "native_failure" }, "windows");
    assert.doesNotMatch(message, /Mac|Applications|disk image/u);
    assert.match(message, /Windows/u);
    assert.ok(message.endsWith("(native_failure)"));
  }
  const staged = updateInstallView(update, ready, "windows");
  assert.match(staged.status, /Clash for Windows/u);
  assert.equal(staged.primary.action, "commit");
  const installing = updateInstallView(update, { ...ready, phase: "installing" }, "windows");
  assert.match(installing.status, /Clash for Windows/u);
  assert.equal(installing.cancel, false);
  const forged = { ...IDLE_UPDATE_INSTALL, failure: { category: "authenticity", code: "signature_mismatch" } };
  const rejected = updateInstallView(update, forged, "windows");
  assert.equal(rejected.offerDownloadPage, false);
  assert.equal(rejected.primary, null);
});

test("updater presentation requires a known host operating system", () => {
  for (const os of [undefined, null, "", "linux", "Windows", {}]) {
    assert.throws(() => installFailureText({ category: "network", code: "network" }, os), /operating system is invalid/u);
    assert.throws(() => updateInstallView(update, ready, os), /operating system is invalid/u);
  }
});

test("Windows controller failures use the identity delivered by boot_payload", async () => {
  setLocale("en");
  const state = { payload: { product: { operating_system: "windows" } }, updateInfo: update, updateInstall: { ...IDLE_UPDATE_INSTALL } };
  const logs = [];
  const controller = createUpdateInstall({
    state,
    invoke: async () => { throw { code: "storage_unavailable", category: "storage" }; },
    appendLog: (...args) => logs.push(args), errorText: String,
    sleep: async () => {}, notify: () => {}, onChange: () => {},
  });
  await controller.prepare();
  assert.equal(state.updateInstall.failure.code, "storage_unavailable");
  assert.match(logs.at(-1)[2], /Windows/u);
  assert.doesNotMatch(logs.at(-1)[2], /Mac/u);
});

test("Windows update instructions are translated in every supported locale", () => {
  for (const locale of SUPPORTED_LOCALES) {
    try {
      setLocale(locale);
      const message = updateInstallView(update, ready, "windows").status;
      assert.match(message, /Clash for Windows/u);
      assert.doesNotMatch(message, /\{version\}/u);
      if (locale !== "en") assert.doesNotMatch(message, /is ready to install/u);
      for (const category of ["environment", "storage", "package"]) {
        const value = installFailureText({ category, code: "failure" }, "windows");
        assert.doesNotMatch(value, /Mac|Applications|disk image/u);
        assert.ok(value.endsWith("(failure)"));
      }
    } finally { setLocale("en"); }
  }
});
