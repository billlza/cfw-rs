import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import { catalogs, SUPPORTED_LOCALES, resolveLocale, setLocale, getLocale, t, formatDate } from "../src/i18n.js";
import { escapeHtml, engineStateLabel, systemProxyValueLabel, tunnelValueLabel } from "../src/format.js";
import pages from "../src/pages.json" with { type: "json" };

const parameters = (value) => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu)].map((match) => match[1]).sort();

test("all four bundled languages have complete messages and identical named parameters", () => {
  const keys = Object.keys(catalogs.en).sort();
  assert.ok(keys.length > 600);
  for (const locale of SUPPORTED_LOCALES) {
    assert.deepEqual(Object.keys(catalogs[locale]).sort(), keys, locale);
    for (const key of keys) {
      const message = catalogs[locale][key];
      assert.equal(typeof message, "string", `${locale}: ${key}`);
      assert.notEqual(message.trim(), "", `${locale}: ${key}`);
      assert.deepEqual(parameters(message), parameters(key), `${locale}: ${key}`);
    }
  }
});

test("every literal dashboard message and page label is present in the catalogs", () => {
  const root = new URL("../src/", import.meta.url);
  const messages = new Set(pages.flatMap(({ title, summary }) => [title, summary]));
  for (const file of readdirSync(root).filter((name) => name.endsWith(".js"))) {
    const source = readFileSync(new URL(file, root), "utf8");
    for (const match of source.matchAll(/\bt\(\s*("(?:[^"\\]|\\.)*")/gu)) messages.add(JSON.parse(match[1]));
  }
  for (const message of messages) assert.ok(Object.hasOwn(catalogs.en, message), `Missing bundled message: ${message}`);
});

test("system language selection respects ordered preferences and Chinese scripts", () => {
  for (const [preferred, expected] of [
    [["zh-Hans-TW"], "zh-Hans"], [["zh-Hant-CN"], "zh-Hant"],
    [["zh_HK"], "zh-Hant"], [["zh-MO"], "zh-Hant"], [["zh-SG"], "zh-Hans"],
    [["fr-FR", "ja-JP", "en-US"], "ja"], [["en-GB", "zh-CN"], "en"],
    [["de-DE"], "en"], [[], "en"],
  ]) {
    assert.equal(resolveLocale("system", preferred), expected);
    assert.equal(resolveLocale("ja", preferred), "ja");
  }
  assert.throws(() => resolveLocale("fr"), RangeError);
  assert.throws(() => setLocale("<script>"), RangeError);
});

test("named interpolation preserves user text without recursively interpreting it", () => {
  const old = getLocale();
  try {
    for (const locale of SUPPORTED_LOCALES) {
      setLocale(locale);
      const name = 'General <img src=x onerror="attack()"> {error}';
      const output = t("Delete “{name}”? This removes the managed profile from the repository.", { name });
      assert.ok(output.includes(name));
      assert.ok(escapeHtml(output).includes("&lt;img"));
      assert.ok(!escapeHtml(output).includes("<img"));
      assert.throws(() => t("Close All ({count})"), /Missing translation parameter/u);
      assert.equal(t("A future source-owned English message."), "A future source-owned English message.");
      assert.equal(t("__proto__"), "__proto__");
    }
  } finally { setLocale(old); }
});

test("state labels change language while engine identity and mode values remain intact", () => {
  const old = getLocale();
  const engine = { state: "TunnelSystemProxyActive", desiredMode: "tunnel-system-proxy", generation: 17, configDigest: "unchanged", active: true };
  const before = structuredClone(engine);
  try {
    const expected = { en: "On", "zh-Hans": "开启", "zh-Hant": "開啟", ja: "オン" };
    for (const locale of SUPPORTED_LOCALES) {
      setLocale(locale);
      assert.equal(engineStateLabel(engine), expected[locale]);
      assert.equal(systemProxyValueLabel(engine), expected[locale]);
      assert.equal(tunnelValueLabel(engine), expected[locale]);
      assert.deepEqual(engine, before);
    }
    setLocale("ja");
    assert.equal(formatDate(new Date("2026-09-20T00:00:00Z"), { year: "numeric", month: "long", timeZone: "UTC" }), "2026年9月");
  } finally { setLocale(old); }
});
