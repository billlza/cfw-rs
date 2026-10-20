import assert from "node:assert/strict";
import test from "node:test";
import { networkDiagnosticsView } from "../src/network-diagnostics.js";
import { catalogs, SUPPORTED_LOCALES, getLocale, setLocale } from "../src/i18n.js";

const windows = {
  platform: "windows",
  adapters: [{ index: 5, display_name: "Ethernet <office>", interface_type: 6, operational_status: 1 }],
  user_proxy: { manual_proxy_enabled: true, auto_config_enabled: false, auto_detect_enabled: true },
};

test("Windows reports user proxy options separately from adapter status", () => {
  const old = getLocale();
  try {
    setLocale("en");
    const view = networkDiagnosticsView(windows, () => { throw new Error("not a Mac service"); });
    assert.deepEqual(view.columns, ["Adapter", "Type", "Status"]);
    assert.deepEqual(view.rows, [["Ethernet <office>", "Ethernet", "Up"]]);
    assert.equal(view.summary[0][0], "Current user proxy");
    assert.equal(view.summary[0][1], "Manual proxy, WPAD");
    assert.doesNotMatch(JSON.stringify(view), /SystemConfiguration|set order|ownership.*true/u);
    const unknown = structuredClone(windows);
    unknown.adapters[0].operational_status = 99;
    assert.equal(networkDiagnosticsView(unknown).rows[0][2], "Unknown (99)");
  } finally { setLocale(old); }
});

test("malformed Windows observations cannot appear as empty or disabled settings", () => {
  for (const change of [
    (value) => { delete value.user_proxy; },
    (value) => { delete value.user_proxy.manual_proxy_enabled; },
    (value) => { value.user_proxy.auto_detect_enabled = "false"; },
    (value) => { value.adapters = null; },
    (value) => { value.adapters.push(value.adapters[0]); },
    (value) => { value.adapters[0].index = 0; },
    (value) => { value.platform = "unknown"; },
  ]) {
    const value = structuredClone(windows);
    change(value);
    assert.throws(() => networkDiagnosticsView(value), /invalid/u);
  }
});

test("Mac diagnostics retain the original service order and unavailable fields", () => {
  const old = getLocale();
  try {
    setLocale("en");
    const view = networkDiagnosticsView({ services: [{ display_name: "Wi-Fi", order: 2 }],
      proxied_services: ["Wi-Fi"], unavailable: ["default_route_interface"] }, () => "HTTPS");
    assert.deepEqual(view.columns, ["Service", "Order", "Proxy"]);
    assert.deepEqual(view.rows, [["Wi-Fi", "2", "HTTPS"]]);
    assert.deepEqual(view.unavailable, ["default_route_interface"]);
    assert.equal(view.summary[1][1], "Wi-Fi");
  } finally { setLocale(old); }
});

test("dynamic native interface types and statuses are translated in all languages", () => {
  for (const locale of SUPPORTED_LOCALES) {
    for (const key of ["Ethernet", "Loopback", "Wi-Fi", "Tunnel", "Up", "Down", "Testing", "Unknown", "Dormant", "Not present", "Lower layer down"]) {
      assert.ok(Object.hasOwn(catalogs[locale], key), `${locale}: ${key}`);
    }
  }
});
