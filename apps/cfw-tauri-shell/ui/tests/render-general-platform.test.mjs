// The General page on each host: the host's identity and the commands it
// copies, Windows network details, the host's version in About and Feedback,
// and the maintenance that only a Mac offers.
import assert from "node:assert/strict";
import test from "node:test";
import {
  WINDOWS_PLATFORM_DESIGN, appModule, glassRoot, invoked, page, renderPage, responses, state,
} from "./support/render-harness.mjs";

test("General uses host identity and copies platform-appropriate commands without changing the engine", async () => {
  const original = {
    product: state.payload.product,
    projection: state.projection,
    writeText: navigator.clipboard.writeText,
    page: state.activePage,
    dialog: state.glassDialog,
  };
  const observedEngine = structuredClone(state.engine);
  const commandsBefore = invoked.length;
  const copies = [];
  navigator.clipboard.writeText = async (value) => { copies.push(value); };
  try {
    state.projection = { ...state.projection, mixedPort: 7890 };
    for (const [operatingSystem, name, expectedLabel, expectedCommands] of [
      ["macos", "Clash for Mac", "Start with macOS", [
        "export https_proxy=http://127.0.0.1:7890",
        "export http_proxy=http://127.0.0.1:7890",
        "export all_proxy=socks5://127.0.0.1:7890",
      ].join("\n")],
      ["windows", "Clash for Windows", "Start with Windows", [
        '$env:https_proxy = "http://127.0.0.1:7890"',
        '$env:http_proxy = "http://127.0.0.1:7890"',
        '$env:all_proxy = "socks5://127.0.0.1:7890"',
      ].join("\n")],
    ]) {
      state.payload.product = { ...original.product, name, operating_system: operatingSystem };
      const html = await renderPage("general");
      assert.ok(html.includes(`<span>${name}</span>`));
      assert.ok(html.includes(expectedLabel));
      assert.equal((html.match(/class="cfw-row"/gu) ?? []).length, 12);
      if (operatingSystem === "windows") {
        assert.doesNotMatch(html, /Clash for Mac|Start with macOS|NetworkExtension|System Extension|System Settings/u);
        assert.match(html, /PowerShell/u);
      }
      await appModule.handleAction("tun-info");
      if (operatingSystem === "windows") {
        assert.match(glassRoot.innerHTML, /Windows virtual network adapter/u);
        assert.doesNotMatch(glassRoot.innerHTML, /macOS|NetworkExtension|System Settings/u);
      } else {
        assert.match(glassRoot.innerHTML, /NetworkExtension/u);
      }
      await appModule.handleAction("copy-proxy-exports");
      assert.equal(copies.at(-1), expectedCommands);
    }
    const copiedCount = copies.length;
    state.projection = { ...state.projection, mixedPort: "7890; bad-command" };
    await appModule.handleAction("copy-proxy-exports");
    assert.equal(copies.length, copiedCount, "an invalid endpoint must never become clipboard shell code");
    assert.deepEqual(state.engine, observedEngine);
    assert.deepEqual(invoked.slice(commandsBefore), [], "rendering and copying do not invoke network commands");
  } finally {
    state.payload.product = original.product;
    state.projection = original.projection;
    state.glassDialog = original.dialog;
    navigator.clipboard.writeText = original.writeText;
    await renderPage(original.page);
  }
});

test("Windows network details keep user proxy settings separate and escape adapter names", async () => {
  const original = { response: responses.network_diagnostics, diagnostics: state.networkDiagnostics, dialog: state.glassDialog };
  try {
    responses.network_diagnostics = {
      platform: "windows", adapters: [{ index: 5, display_name: "Office <adapter>", interface_type: 6, operational_status: 1 }],
      user_proxy: { manual_proxy_enabled: true, auto_config_enabled: false, auto_detect_enabled: false },
    };
    await appModule.handleAction("show-network-interfaces");
    assert.match(glassRoot.innerHTML, /Network adapters/u);
    assert.match(glassRoot.innerHTML, /Current user proxy: Manual proxy/u);
    assert.match(glassRoot.innerHTML, /Office &lt;adapter&gt;/u);
    assert.doesNotMatch(glassRoot.innerHTML, /Office <adapter>|SystemConfiguration|<th>Order<\/th>|<th>Proxy<\/th>/u);
    state.glassDialog = null;
    const settings = await renderPage("settings");
    assert.match(settings, /Current user proxy/u);
    assert.match(settings, /Office &lt;adapter&gt;/u);
  } finally {
    responses.network_diagnostics = original.response;
    state.networkDiagnostics = original.diagnostics;
    state.glassDialog = original.dialog;
  }
});

test("About and Feedback retain the host's Windows version and architecture", async () => {
  const original = { product: state.payload.product, platform: state.platform, dialog: state.glassDialog, page: state.activePage };
  try {
    state.payload.product = {
      ...original.product, name: "Clash for Windows", operating_system: "windows",
      minimum_os_version: "10.0.26100", architecture: "x64",
    };
    state.platform = WINDOWS_PLATFORM_DESIGN;
    state.glassDialog = { kind: "product-about", payload: { phase: "idle" } };
    await renderPage("general");
    assert.match(glassRoot.innerHTML, /aria-label="About Clash for Windows"/u);
    assert.match(glassRoot.innerHTML, /class="product-about-name">Clash for Windows<\/div>/u);
    assert.ok(glassRoot.innerHTML.includes("x64 · Windows 10.0.26100+"));
    assert.doesNotMatch(glassRoot.innerHTML, /macOS 15\.0|Clash for Mac/u);
    state.glassDialog = null;
    const feedback = await renderPage("feedback");
    assert.ok(feedback.includes(WINDOWS_PLATFORM_DESIGN.startup_strategy));
    assert.match(feedback, /<dt>Start at Login<\/dt>/u);
    assert.doesNotMatch(feedback, /<dt>launchd<\/dt>/u);
    assert.ok(feedback.includes("x64 · Windows 10.0.26100 or later"));
    assert.doesNotMatch(feedback, /ARM64 macOS only|macOS 15\.0/u);
    state.payload.product = { ...state.payload.product, minimum_os_version: null };
    state.glassDialog = { kind: "product-about", payload: { phase: "idle" } };
    await renderPage("general");
    assert.ok(glassRoot.innerHTML.includes("x64 · Windows</div>"));
    assert.doesNotMatch(glassRoot.innerHTML, /null|undefined|Windows\s+15\.0|\d\+/u);
    state.glassDialog = null;
    const unqualified = await renderPage("feedback");
    assert.ok(unqualified.includes("x64 · Windows</p>"));
    assert.doesNotMatch(unqualified, /Windows.*(?:null|undefined|15\.0|or later)/u);
  } finally {
    state.payload.product = original.product;
    state.platform = original.platform;
    state.glassDialog = original.dialog;
    await renderPage(original.page);
  }
});

test("Windows omits Mac maintenance without showing a completed cleanup or dispatching cutover", async () => {
  const original = {
    product: state.payload.product, retirement: state.retirement,
    maintenanceOpen: state.legacyMaintenanceOpen, page: state.activePage,
    profiles: state.profiles, invalidProfiles: state.invalidProfiles,
    profilesUnavailableReason: state.profilesUnavailableReason,
  };
  const commandsBefore = invoked.length;
  try {
    state.payload.product = {
      ...original.product, name: "Clash for Windows", operating_system: "windows",
      architecture: "x64", minimum_os_version: null,
    };
    state.retirement = { state: "not_applicable" };
    state.legacyMaintenanceOpen = true;
    const settings = await renderPage("settings");
    assert.doesNotMatch(settings, /open-legacy-maintenance|Older Clash for Mac|Legacy maintenance/u);
    const general = await renderPage("general");
    assert.doesNotMatch(general, /begin-migration-handoff|prepare-cutover|confirm-cutover|recover-cutover|data-migration/u);
    state.profiles = [];
    state.invalidProfiles = [];
    state.profilesUnavailableReason = null;
    const profiles = await renderPage("profiles");
    assert.doesNotMatch(profiles, /migrate-legacy-profiles|Migrate selected legacy subscription/u);
    assert.match(profiles, /data-action="import-profile-file"/u);
    assert.match(profiles, /data-action="import-profile"/u);
    for (const action of [
      "open-legacy-maintenance", "begin-migration-handoff", "prepare-cutover",
      "confirm-cutover", "recover-cutover", "migrate-legacy-profiles",
    ]) {
      await assert.rejects(() => appModule.handleAction(action), /does not apply/u);
    }
    assert.deepEqual(invoked.slice(commandsBefore), []);
  } finally {
    state.payload.product = original.product;
    state.retirement = original.retirement;
    state.legacyMaintenanceOpen = original.maintenanceOpen;
    state.profiles = original.profiles;
    state.invalidProfiles = original.invalidProfiles;
    state.profilesUnavailableReason = original.profilesUnavailableReason;
    await renderPage(original.page);
  }
});
