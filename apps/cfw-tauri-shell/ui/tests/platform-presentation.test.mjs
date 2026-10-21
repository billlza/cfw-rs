import assert from "node:assert/strict";
import test from "node:test";
import { platformPresentation, platformStartupDesign, proxyEnvironmentCommands } from "../src/platform-presentation.js";
import { catalogs, SUPPORTED_LOCALES } from "../src/i18n.js";

test("Windows startup design uses its native field while Mac retains launchd", () => {
  assert.deepEqual(platformStartupDesign("windows", { startup_strategy: "Windows startup approval" }), {
    label: "Start at Login", value: "Windows startup approval",
  });
  assert.deepEqual(platformStartupDesign("macos", { launchd_strategy: "SMAppService Login Item" }), {
    label: "launchd", value: "SMAppService Login Item",
  });
});

test("missing or mismatched startup metadata cannot become an empty platform row", () => {
  for (const os of ["windows", "macos"]) {
    for (const design of [null, {}, { startup_strategy: "", launchd_strategy: " " }, { startup_strategy: 3, launchd_strategy: true }]) {
      assert.throws(() => platformStartupDesign(os, design), /startup strategy is invalid/u);
    }
  }
  assert.throws(() => platformStartupDesign("windows", { launchd_strategy: "Mac only" }), /startup strategy is invalid/u);
  assert.throws(() => platformStartupDesign("linux", { startup_strategy: "unknown" }), /operating system is invalid/u);
});

test("proxy environment commands preserve the actual listener and each shell's assignment syntax", () => {
  for (const port of [1, 7890, 65535]) {
    const mac = proxyEnvironmentCommands("macos", port).split("\n");
    const windows = proxyEnvironmentCommands("windows", port).split("\n");
    assert.deepEqual(mac, [
      `export https_proxy=http://127.0.0.1:${port}`,
      `export http_proxy=http://127.0.0.1:${port}`,
      `export all_proxy=socks5://127.0.0.1:${port}`,
    ]);
    assert.deepEqual(windows, [
      `$env:https_proxy = "http://127.0.0.1:${port}"`,
      `$env:http_proxy = "http://127.0.0.1:${port}"`,
      `$env:all_proxy = "socks5://127.0.0.1:${port}"`,
    ]);
  }
});

test("unknown hosts and invalid ports cannot produce executable clipboard text", () => {
  for (const platform of [undefined, null, "", "linux", "Windows", {}, 1]) {
    assert.throws(() => platformPresentation(platform), /operating system is invalid/u);
    assert.throws(() => proxyEnvironmentCommands(platform, 7890), /operating system is invalid/u);
  }
  for (const platform of ["macos", "windows"]) {
    for (const port of [undefined, null, 0, -1, 65536, 7890.5, NaN, Infinity, "7890", '7890"; command', {}]) {
      assert.throws(() => proxyEnvironmentCommands(platform, port), /port is invalid/u);
    }
  }
});

test("both platforms' dynamic presentation labels exist in every bundled language", () => {
  for (const platform of ["macos", "windows"]) {
    const presentation = platformPresentation(platform);
    for (const locale of SUPPORTED_LOCALES) {
      for (const key of Object.entries(presentation).filter(([name]) => name !== "name").map(([, value]) => value)) {
        assert.ok(Object.hasOwn(catalogs[locale], key), `${locale}: ${key}`);
        assert.ok(catalogs[locale][key].trim(), `${locale}: ${key}`);
      }
    }
  }
});
