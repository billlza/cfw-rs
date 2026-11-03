// The General page: the status bar, its dialogs and switches, the host's
// platform details, capability reasons, and the country-rules row.
import assert from "node:assert/strict";
import test from "node:test";
import {
  OFF_ENGINE, RUNNING_ENGINE, appModule, documentListeners, element, emit, glassRoot,
  intervalCallbacks, invocationDetails, invoked, nav, page, querySelectorAllElements,
  querySelectorElements, renderPage, responses, runtime, setEngine, state, statusBarNodes,
  streamEvent,
} from "./support/render-harness.mjs";

test("status bar clock preserves changing values without rewriting unchanged DOM", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalNodes = new Map(statusBarNodes);
  const originalNow = Date.now;
  let now = 1_000_000;
  function countedNode(id) {
    const node = element("div", id);
    let text = "", width = "";
    node.writes = { text: 0, width: 0 };
    Object.defineProperty(node, "textContent", {
      get: () => text,
      set: (value) => { text = value; node.writes.text += 1; },
    });
    Object.defineProperty(node.style, "width", {
      get: () => width,
      set: (value) => { width = value; node.writes.width += 1; },
    });
    return node;
  }
  const writes = () => [...statusBarNodes.values()].map((node) => ({ ...node.writes }));
  const resetWrites = () => {
    for (const node of statusBarNodes.values()) node.writes = { text: 0, width: 0 };
  };
  const noWrites = Array.from({ length: 4 }, () => ({ text: 0, width: 0 }));
  try {
    Date.now = () => now;
    for (const id of statusBarNodes.keys()) statusBarNodes.set(id, countedNode(id));
    const clocks = intervalCallbacks.filter(({ delay }) => delay === 1000);
    assert.equal(clocks.length, 1, "real bootstrap retains exactly one one-second clock");
    const tick = clocks[0].callback;
    await setEngine(OFF_ENGINE);
    await renderPage("general");
    assert.equal(statusBarNodes.get("upload-rate").textContent, "0.00 KB/s");
    assert.equal(statusBarNodes.get("download-rate").textContent, "0.00 KB/s");
    assert.equal(statusBarNodes.get("runtime-value").textContent, "00 : 00 : 00");
    assert.equal(statusBarNodes.get("traffic-progress").style.width, "0%");
    resetWrites();
    let ipcBefore = invoked.length;
    for (let second = 0; second < 60; second++) { now += 1000; tick(); }
    assert.equal(invoked.length, ipcBefore, "Off clock ticks issue no IPC");
    assert.deepEqual(writes(), noWrites, "60 stable Off ticks must preserve existing DOM values");

    await setEngine(RUNNING_ENGINE);
    resetWrites(); ipcBefore = invoked.length;
    now += 1000; tick();
    assert.equal(statusBarNodes.get("runtime-value").textContent, "00 : 00 : 01");
    now += 1000; tick();
    assert.equal(statusBarNodes.get("runtime-value").textContent, "00 : 00 : 02");
    assert.deepEqual(writes(), [{ text: 0, width: 0 }, { text: 0, width: 0 },
      { text: 2, width: 0 }, { text: 0, width: 0 }]);
    assert.equal(invoked.length, ipcBefore, "running clock ticks issue no IPC");

    // The same registered callback must publish changes in the displayed rates.
    resetWrites();
    state.traffic.upload = 0.5; state.traffic.download = 2;
    tick();
    assert.equal(statusBarNodes.get("upload-rate").textContent, "512 KB/s");
    assert.equal(statusBarNodes.get("download-rate").textContent, "2.0 MB/s");
    assert.equal(statusBarNodes.get("traffic-progress").style.width, "10%");
    assert.deepEqual(writes(), [{ text: 1, width: 0 }, { text: 1, width: 0 },
      { text: 0, width: 0 }, { text: 0, width: 1 }]);
    state.traffic.upload = 1; state.traffic.download = 0.5;
    tick();
    assert.equal(statusBarNodes.get("upload-rate").textContent, "1.0 MB/s");
    assert.equal(statusBarNodes.get("download-rate").textContent, "512 KB/s");
    assert.equal(statusBarNodes.get("traffic-progress").style.width, "6%");
    resetWrites(); tick();
    assert.deepEqual(writes(), noWrites);
    assert.equal(invoked.length, ipcBefore, "rate display changes issue no IPC");

    // A replacement node must receive current values even when state is unchanged.
    const detachedNodes = [...statusBarNodes.values()];
    for (const id of statusBarNodes.keys()) statusBarNodes.set(id, countedNode(id));
    tick();
    assert.equal(statusBarNodes.get("upload-rate").textContent, "1.0 MB/s");
    assert.equal(statusBarNodes.get("download-rate").textContent, "512 KB/s");
    assert.equal(statusBarNodes.get("runtime-value").textContent, "00 : 00 : 02");
    assert.equal(statusBarNodes.get("traffic-progress").style.width, "6%");
    assert.deepEqual(writes(), [{ text: 1, width: 0 }, { text: 1, width: 0 },
      { text: 1, width: 0 }, { text: 0, width: 1 }]);
    assert.deepEqual(detachedNodes.map((node) => node.writes), noWrites);
    assert.equal(invoked.length, ipcBefore, "replacing DOM nodes introduces no IPC");

    await setEngine(OFF_ENGINE);
    assert.equal(statusBarNodes.get("runtime-value").textContent, "00 : 00 : 00");
    assert.equal(statusBarNodes.get("upload-rate").textContent, "0.00 KB/s");
    assert.equal(statusBarNodes.get("download-rate").textContent, "0.00 KB/s");
    assert.equal(statusBarNodes.get("traffic-progress").style.width, "0%");
    resetWrites(); ipcBefore = invoked.length;
    now += 1000; tick();
    assert.deepEqual(writes(), noWrites, "returning Off clears old values once");
    assert.equal(invoked.length, ipcBefore);
  } finally {
    Date.now = originalNow;
    for (const [id, node] of originalNodes) statusBarNodes.set(id, node);
    await setEngine(originalEngine);
  }
});

test("live connection snapshots refresh the General status bar without replacing the page", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalPaused = state.connectionPaused;
  const originalStream = state.connectionStream;
  const originalConnections = state.connections;
  const originalTraffic = { ...state.traffic };
  const originalNow = Date.now;
  let now = 2_000_000;
  // General renders no connection data. Replacing its DOM on every snapshot
  // detaches the controls a pointer or an assistive client is about to use.
  function countedMarkup(node) {
    let markup = node.innerHTML, writes = 0;
    Object.defineProperty(node, "innerHTML", {
      configurable: true, enumerable: true,
      get: () => markup,
      set: (value) => { markup = value; writes += 1; },
    });
    return {
      writes: () => writes,
      restore: () => Object.defineProperty(node, "innerHTML", {
        configurable: true, enumerable: true, writable: true, value: markup,
      }),
    };
  }
  const megabyte = 1024 * 1024;
  const snapshot = (second) => streamEvent("connections", {
    upload: second * megabyte,
    download: second * 2 * megabyte,
    connections: [{
      id: `general-live-${second}`, upload: second, download: second,
      start: "2026-01-01T00:00:00Z", chains: ["PROXY"], rule: "MATCH",
      metadata: { host: "general.example" },
    }],
  }, RUNNING_ENGINE);
  const counted = [];
  try {
    Date.now = () => now;
    state.connectionPaused = false;
    state.connectionStream = { at: 0, uploadTotal: 0, downloadTotal: 0, rows: new Map() };
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    assert.ok(runtime.connectionsLiveStream.binding, "the running engine has a live connection stream");
    const rendered = await renderPage("general");
    assert.ok(rendered.includes('class="cfw-general-view'), "the General page is rendered");
    counted.push(countedMarkup(page), countedMarkup(nav), countedMarkup(glassRoot));
    for (let second = 1; second <= 5; second++) {
      now += 1000;
      await emit("cfw://connections-snapshot", snapshot(second));
    }
    assert.deepEqual(state.connections.map(({ id }) => id), ["general-live-5"],
      "each snapshot is still applied to the shared connection state");
    assert.equal(statusBarNodes.get("upload-rate").textContent, "1.0 MB/s");
    assert.equal(statusBarNodes.get("download-rate").textContent, "2.0 MB/s");
    assert.deepEqual(counted.map((node) => node.writes()), [0, 0, 0],
      "snapshots must not replace the General page, navigation or overlay DOM");
    assert.equal(page.innerHTML, rendered);
  } finally {
    for (const node of counted) node.restore();
    Date.now = originalNow;
    state.connectionPaused = originalPaused;
    state.connectionStream = originalStream;
    state.connections = originalConnections;
    Object.assign(state.traffic, originalTraffic);
    await setEngine(originalEngine);
  }
});

test("overlay-only General dialogs hide native switches and restore fresh geometry on close", async () => {
  const keys = ["allowLan", "ipv6DNS", "tunMode", "mixin", "systemProxy", "startAtLogin"];
  const prior = { resize: globalThis.ResizeObserver, style: globalThis.getComputedStyle,
    frame: globalThis.requestAnimationFrame, events: window.addEventListener,
    enabled: state.payload.native_ui.general_switches,
    presentationError: state.nativeGeneralPresentationError,
    automation: responses.read_automation_settings };
  let top = 80;
  const rows = keys.map((key, index) => {
    const label = element("label"), input = element("input");
    const classes = new Set(), attributes = new Map();
    label.classList = { add: (name) => classes.add(name), remove: (name) => classes.delete(name) };
    label.setAttribute = (name, value) => attributes.set(name, value);
    label.removeAttribute = (name) => attributes.delete(name);
    label.getAttribute = (name) => attributes.get(name) ?? null;
    label.querySelector = () => ({ textContent: key });
    label.getBoundingClientRect = () => ({ x: 790, y: top + index * 40, width: 34, height: 20 });
    input.dataset.toggle = key;
    input.disabled = index === 5;
    input.checked = index === 1;
    input.closest = () => label;
    input.removeAttribute = (name) => { if (name === "data-native-general-key") delete input.dataset.nativeGeneralKey; };
    return input;
  });
  const general = element();
  general.parentElement = null;
  querySelectorElements.set(".cfw-general-view", general);
  querySelectorAllElements.set(".cfw-general-view .inline-switch input[data-toggle]", rows);
  globalThis.ResizeObserver = class { observe() {} disconnect() {} };
  globalThis.getComputedStyle = () => ({ overflowX: "visible", overflowY: "visible" });
  globalThis.requestAnimationFrame = (callback) => setImmediate(callback);
  window.addEventListener = () => {};
  responses.sync_native_general_switches = true;
  responses.focus_native_general_switch = true;
  responses.dismiss_native_general_switches = true;
  responses.read_automation_settings = {
    settings: { shortcuts: [], network_enabled: false, network_rules: [] },
    revision: "modal-lifecycle", network: null,
  };
  const frames = () => invocationDetails.filter(({ command }) => command === "sync_native_general_switches").map(({ args }) => args.request);
  let submission = 0;
  const flush = async () => { for (let i = 0; i < 4; i++) await new Promise((resolve) => setImmediate(resolve)); };
  const close = async () => {
    for (const listener of documentListeners.get("keydown") ?? []) {
      listener({ key: "Escape", preventDefault() {} });
    }
    await flush();
  };
  try {
    state.payload.native_ui.general_switches = true;
    state.glassDialog = null;
    await renderPage("general"); await flush();
    assert.equal(frames().at(-1)?.items.length, 6);
    for (const action of ["show-network-interfaces", "allow-lan-info", "dns-query", "mixin-info",
      "open-runtime-settings", "open-automation-settings", "show-network-interfaces"]) {
      const before = frames().length;
      const previous = frames().at(-1);
      const businessState = rows.map(({ disabled, checked }) => ({ disabled, checked }));
      await appModule.handleAction(action);
      assert.ok(rows.every((input) => input.closest().inert === true), "DOM mirrors become inert during overlay-only rendering");
      const completion = invocationDetails.find(({ command }) => command === "sync_native_general_switches").args.completion;
      const callsBeforeInput = invoked.length;
      // A native input may already be in IPC when its DOM modal opens.
      completion.onmessage({ kind: "input", requestId: previous.requestId, sequence: previous.sequence,
        submission: ++submission, key: 3, action: 1, value: true });
      completion.onmessage({ kind: "input", requestId: previous.requestId, sequence: previous.sequence,
        submission: 0, key: 3, action: 2, value: false });
      await flush();
      assert.match(glassRoot.innerHTML, /glass-dialog-backdrop/u);
      assert.ok(frames().length > before, "Overlay-only rendering must publish native occlusion");
      assert.deepEqual(frames().at(-1).items, []);
      assert.ok(rows.every((input) => input.closest().inert === true && input.closest().getAttribute("aria-hidden") === "true"));
      assert.deepEqual(rows.map(({ disabled, checked }) => ({ disabled, checked })), businessState);
      assert.equal(frames().at(-1).acknowledgedSubmission, submission);
      assert.deepEqual(invoked.slice(callsBeforeInput).filter((command) => !command.startsWith("sync_native_general_switches")), [],
        "Occluded native input cannot traverse, regain focus, or invoke a business command");
      top += 7;
      await close();
      assert.equal(glassRoot.innerHTML, "");
      assert.equal(frames().at(-1).items.length, 6);
      assert.equal(frames().at(-1).items[0].rect.y, top, "Reopening measures current DOM geometry");
      assert.ok(rows.every((input) => input.closest().inert === false));
      assert.deepEqual(rows.map(({ disabled, checked }) => ({ disabled, checked })), businessState,
        "Closing a modal restores presentation without changing original disabled/checked state");
    }
    responses.sync_native_general_switches = () => { throw new Error("modal layout rejected"); };
    await appModule.handleAction("show-network-interfaces"); await flush();
    assert.match(state.nativeGeneralPresentationError, /modal layout rejected/u);
    assert.ok(invoked.includes("dismiss_native_general_switches"));
    assert.ok(rows.every((input) => input.closest().inert === true), "A reported native failure must not expose occluded DOM mirrors");
    await close();
    assert.ok(rows.every((input) => input.closest().inert === false), "The original DOM control remains available after a reported presentation failure");
  } finally {
    state.glassDialog = null;
    await renderPage("feedback"); await flush();
    state.payload.native_ui.general_switches = prior.enabled;
    state.nativeGeneralPresentationError = prior.presentationError;
    if (prior.automation === undefined) delete responses.read_automation_settings;
    else responses.read_automation_settings = prior.automation;
    querySelectorElements.delete(".cfw-general-view");
    querySelectorAllElements.delete(".cfw-general-view .inline-switch input[data-toggle]");
    globalThis.ResizeObserver = prior.resize;
    globalThis.getComputedStyle = prior.style;
    globalThis.requestAnimationFrame = prior.frame;
    window.addEventListener = prior.events;
    responses.sync_native_general_switches = true;
    // The page adapter is a lifetime singleton; its empty presentation remains
    // available for later disabled-feature page renders in this shared harness.
  }
});

test("General exposes IPv6 as a direct switch rather than a settings-dialog button", async () => {
  const html = await renderPage("general");
  const row = html.match(/<div class="cfw-row-left">IPv6 DNS<\/div>([\s\S]*?)<div class="cfw-row">/u)?.[1];
  assert.ok(row);
  assert.match(row, /data-toggle="ipv6DNS"/u);
  assert.doesNotMatch(row, /data-action="open-runtime-settings"/u);
});

test("a refreshed projection updates the inherited IPv6 switch", async () => {
  const original = responses.read_runtime_settings_snapshot;
  try {
    responses.read_runtime_settings_snapshot = {
      ...original,
      effective: { ...original.effective, ipv6_dns_enabled:false },
    };
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
    assert.equal(state.toggles.ipv6DNS, false);
    assert.equal(state.runtimeSettings.effective.ipv6_dns_enabled, false);
    const html = await renderPage("general");
    assert.doesNotMatch(html, /data-toggle="ipv6DNS"[^>]*checked/u);
  } finally {
    responses.read_runtime_settings_snapshot = original;
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
  }
});

test("the General page exposes runtime controls and explains unsupported features", async () => {
  await setEngine(RUNNING_ENGINE);
  const html = await renderPage("general");
  assert.match(html, /127\.0\.0\.1:7890/u);
  assert.match(html, /sing-box 1\.13\.0/u, "the engine names itself in its version string");
  assert.doesNotMatch(html, /sing-box · sing-box/u);
  for (const needle of [
    "trusted private source networks",
    "validated runtime replacement",
    "Mixin is unavailable",
    "Country rules use sing-box rule sets",
  ]) {
    assert.ok(html.includes(needle), `General page is missing the reason: ${needle}`);
  }
  assert.match(html, /data-runtime-log-level aria-label="Engine log level">/u);
  assert.match(html, /data-action="open-runtime-settings">127/u);
  assert.doesNotMatch(html, /data-toggle="allowLan"[^>]*disabled/u);
  assert.match(html, /data-toggle="mixin"[^>]*disabled/u);
});

test("the General page surfaces approval and capability reasons", async () => {
  await setEngine({
    snapshot: { desired_mode: "tunnel", generation: 1, config_digest: null, state: { state: "awaiting_approval", generation: 1 } },
    capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true },
  });
  const awaitingApproval = await renderPage("general");
  assert.ok(awaitingApproval.includes("Needs approval"));
  assert.match(awaitingApproval, /data-action="retry-tun-mode">Approve/u);
  assert.doesNotMatch(awaitingApproval, /data-toggle="tunMode" checked/u);
  assert.match(awaitingApproval, /data-action="cancel-tun-mode">Cancel request/u);

  state.engineMutationBusy = true;
  const mutationBusy = await renderPage("general");
  assert.match(mutationBusy, /data-action="retry-tun-mode" disabled>Approve/u);
  assert.match(mutationBusy, /data-toggle="tunMode"\s+disabled/u);
  assert.match(mutationBusy, /data-action="cancel-tun-mode" disabled/u);
  state.engineMutationBusy = false;

  await setEngine({
    snapshot: {
      desired_mode: "system_proxy",
      generation: 2,
      config_digest: "digest",
      state: { state: "failed", generation: 2, target: "system_proxy", error: "approval required" },
    },
    capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true },
  });
  const failedProxy = await renderPage("general");
  assert.match(failedProxy, /data-action="retry-system-proxy">Retry/u);
  assert.doesNotMatch(failedProxy, /data-toggle="systemProxy" checked/u);
  assert.match(failedProxy, /data-action="cancel-system-proxy">Cancel request/u);

  await setEngine({
    snapshot: { desired_mode: "off", generation: 0, config_digest: null, state: { state: "off" } },
    capabilities: { system_proxy: false, tunnel: false },
    unavailable_reason: "native runtime unavailable",
  });
  assert.ok((await renderPage("general")).includes("native runtime unavailable"));
});

test("General routes recovery, post-cutover cleanup and unreadable state without changing pages", async () => {
  state.migrationHandoff = true;
  state.retirement = { state: "recovery_start_required", target: "tunnel", message: "durable journal remains" };
  let html = await renderPage("general");
  assert.ok(html.includes("Recover Replacement"));
  assert.equal(html.includes("Prepare cutover"), false);

  state.retirement = { state: "post_cutover_cleanup_required", message: "old data remains" };
  html = await renderPage("general");
  assert.ok(html.includes("Recover Replacement"));

  state.retirement = { state: "unverifiable", message: "journal unreadable" };
  html = await renderPage("general");
  assert.ok(html.includes("Legacy CFM maintenance state cannot be verified"));
  assert.equal(html.includes("Prepare cutover"), false);

  state.retirement = { state: "awaiting_confirmation" };
  state.cutover = {
    ...state.cutover,
    target: "system_proxy",
    receiptId: null,
  };
  html = await renderPage("general");
  assert.ok(html.includes("data-cutover-target"));
  assert.ok(html.includes("System Proxy"));
  assert.ok(html.includes("TUN"));

  state.migrationHandoff = false;
  state.retirement = { state: "cleared" };
});

test("the General country-rules row shows the switch, never a disguised empty state", async () => {
  await setEngine(RUNNING_ENGINE);
  const settings = state.runtimeSettings;
  const policy = state.savedProfilePolicy;
  const policyError = state.savedProfilePolicyError;
  const row = (html) => html.match(/GeoIP Database<\/div>\s*<div class="cfw-row-right">\s*<span class="cfw-link-value">([^<]*)<\/span>/u)?.[1];
  try {
    // Each case sets a saved policy, as a successful load does.
    state.savedProfilePolicyError = null;
    for (const [direct, countries, expected] of [
      [true, ["CN", "JP"], "Mainland China direct · CN, JP"],
      [true, [], "Mainland China direct"],
      [false, ["CN", "JP"], "CN, JP"],
      [false, [], "No country rules configured"],
      [undefined, [], "unavailable"],
      [undefined, ["JP"], "JP"],
    ]) {
      state.runtimeSettings = direct === undefined ? null
        : { ...settings, effective: { ...settings.effective, mainland_china_direct: direct } };
      state.savedProfilePolicy = { ...(policy ?? { groups: [], rules: [], nodeLabels: {} }), geoipCountries: countries };
      assert.equal(row(await renderPage("general")), expected, `${direct} ${countries}`);
    }
  } finally {
    state.savedProfilePolicyError = policyError;
    state.runtimeSettings = settings;
    state.savedProfilePolicy = policy;
  }
});

test("a failed runtime settings reload leaves the General country-rules row unknown instead of stale", async () => {
  await setEngine(RUNNING_ENGINE);
  const settings = state.runtimeSettings;
  const policy = state.savedProfilePolicy;
  const policyError = state.savedProfilePolicyError;
  const originalProfiles = state.profiles;
  const profiles = originalProfiles.length > 0 ? originalProfiles : [{ id: "11111111-1111-4111-8111-111111111111", name: "Profile", active: false }];
  const row = (html) => html.match(/GeoIP Database<\/div>\s*<div class="cfw-row-right">\s*<span class="cfw-link-value">([^<]*)<\/span>\s*<small class="cfw-row-note" title="([^"]*)">/u)?.slice(1);
  try {
    // The cases below set a saved policy, as a successful load does.
    state.savedProfilePolicyError = null;
    // A failed reload keeps the last snapshot that was read and sets the error.
    state.runtimeSettingsError = "runtime settings unavailable";
    for (const [direct, countries, expected] of [
      [true, [], "unavailable"],
      [true, ["JP"], "JP"],
      [false, [], "unavailable"],
    ]) {
      state.runtimeSettings = { ...settings, effective: { ...settings.effective, mainland_china_direct: direct } };
      state.savedProfilePolicy = { ...(policy ?? { groups: [], rules: [], nodeLabels: {} }), geoipCountries: countries };
      const [value, note] = row(await renderPage("general"));
      assert.equal(value, expected, `${direct} ${countries}`);
      assert.match(note, /^Country rules use sing-box rule sets/u, `${direct} ${countries}`);
    }
    // The profile's rules are unknown too when its saved policy failed to
    // load: the row never claims there are no country rules then.
    state.runtimeSettingsError = null;
    state.savedProfilePolicyError = "saved profile policy unavailable";
    for (const [direct, stale, expected] of [
      [false, null, "unavailable"],
      [true, null, "Mainland China direct"],
      [false, ["JP"], "unavailable"],
      [true, ["JP"], "Mainland China direct"],
    ]) {
      state.runtimeSettings = { ...settings, effective: { ...settings.effective, mainland_china_direct: direct } };
      state.savedProfilePolicy = stale && { ...(policy ?? { groups: [], rules: [], nodeLabels: {} }), geoipCountries: stale };
      const [value] = row(await renderPage("general"));
      assert.equal(value, expected, `policy error, switch ${direct}, stale ${stale}`);
    }
    // While the selected profile's policy is loading it is cleared without an
    // error; only without a selected profile are there truly no rules.
    state.savedProfilePolicyError = null;
    state.savedProfilePolicy = null;
    for (const [selected, direct, expected] of [
      [true, false, "unavailable"],
      [true, true, "Mainland China direct"],
      [false, false, "No country rules configured"],
    ]) {
      state.profiles = profiles.map((profile, index) => ({ ...profile, active: selected && index === 0 }));
      state.runtimeSettings = { ...settings, effective: { ...settings.effective, mainland_china_direct: direct } };
      const [value] = row(await renderPage("general"));
      assert.equal(value, expected, `loading, selected ${selected}, switch ${direct}`);
    }
  } finally {
    state.runtimeSettingsError = null;
    state.savedProfilePolicyError = policyError;
    state.runtimeSettings = settings;
    state.savedProfilePolicy = policy;
    state.profiles = originalProfiles;
  }
});
