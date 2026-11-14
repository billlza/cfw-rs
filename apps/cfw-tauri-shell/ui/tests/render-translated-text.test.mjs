// Pages and dialogs whose text used to bypass the catalogs, rendered in every
// display language.
import assert from "node:assert/strict";
import test from "node:test";
import { getLocale, setLocale, SUPPORTED_LOCALES } from "../src/i18n.js";
import { providerActionKey } from "../src/provider-results.js";
import {
  OFF_ENGINE, emit, glassRoot, reloadButton, renderPage, responses, setEngine, state,
} from "./support/render-harness.mjs";

async function inEveryLanguage(check) {
  const old = getLocale();
  try {
    for (const locale of SUPPORTED_LOCALES) {
      setLocale(locale);
      await check(locale);
    }
  } finally { setLocale(old); }
}

test("the About dialog names its version and its running check in the display language", async () => {
  const original = state.glassDialog;
  const version = String(state.payload.product.version);
  const expected = {
    en: [`Version ${version}`, "Checking…"],
    "zh-Hans": [`版本 ${version}`, "检测中…"],
    "zh-Hant": [`版本 ${version}`, "檢測中…"],
    ja: [`バージョン ${version}`, "確認中…"],
  };
  try {
    await inEveryLanguage(async (locale) => {
      const [versionLine, checking] = expected[locale];
      state.glassDialog = { kind: "product-about", payload: { phase: "checking" } };
      await renderPage("general");
      const html = glassRoot.innerHTML;
      assert.ok(html.includes(`<div>${versionLine}</div>`), `${locale}: the version line`);
      assert.ok(html.includes(`<button type="button" class="glass-btn" disabled>${checking}</button>`), `${locale}: the busy action`);
      assert.ok(html.includes(`data-glass-check-update disabled>${checking}</button>`), `${locale}: the check button`);
      if (locale !== "en") assert.equal(html.includes("Checking…"), false, `${locale}: no English label`);
      if (!locale.startsWith("zh")) assert.equal(html.includes("版本"), false, `${locale}: no Chinese label`);
    });
  } finally {
    state.glassDialog = original;
  }
});

test("Start at Login explains what macOS reports in the display language", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const expected = {
    requires_approval: {
      en: "macOS requires approval in System Settings › General › Login Items.",
      "zh-Hans": "macOS 要求在「系统设置 › 通用 › 登录项」中批准。",
      "zh-Hant": "macOS 要求在「系統設定 › 一般 › 登入項目」中核准。",
      ja: "macOS の「システム設定 › 一般 › ログイン項目」での承認が必要です。",
    },
    enabled: {
      en: "macOS currently enables this Login Item, while the saved preference says Off.",
      "zh-Hans": "macOS 当前已启用此登录项，但已保存的偏好为关闭。",
      "zh-Hant": "macOS 目前已啟用此登入項目，但已儲存的偏好為關閉。",
      ja: "macOS ではこのログイン項目が有効ですが、保存済みの設定はオフです。",
    },
  };
  try {
    for (const status of Object.keys(expected)) {
      const snapshot = {
        ...original,
        settings: { ...original.settings, launch_at_login: false },
        launch_at_login: { persisted_intent: false, live_status: status, matches_persisted_intent: false },
      };
      responses.read_settings_snapshot = snapshot;
      await emit("cfw://settings-changed", snapshot);
      await inEveryLanguage(async (locale) => {
        const html = await renderPage("settings");
        assert.ok(html.includes(expected[status][locale]), `${locale}: ${status}`);
        if (locale !== "en") assert.equal(html.includes(expected[status].en), false, `${locale}: ${status} is not shown in English`);
      });
    }
  } finally {
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
  }
});

test("the Providers page names its running actions and its unavailable state in the display language", async () => {
  const original = { bulk: state.providerBulkActions, error: state.providerCapabilityError };
  const expected = {
    en: ["Updating…", "Checking…", "Proxy provider management unavailable", "Rule provider management unavailable"],
    "zh-Hans": ["正在更新…", "检测中…", "无法管理代理提供者", "无法管理规则提供者"],
    "zh-Hant": ["正在更新…", "檢測中…", "無法管理代理提供者", "無法管理規則提供者"],
    ja: ["更新中…", "確認中…", "プロキシプロバイダーを管理できません", "ルールプロバイダーを管理できません"],
  };
  try {
    state.providerBulkActions = new Set(["update-all-providers", "health-check-all"]);
    state.providerCapabilityError = "provider management is unavailable in this application";
    await inEveryLanguage(async (locale) => {
      const html = await renderPage("providers");
      const [updating, checking, proxyHeading, ruleHeading] = expected[locale];
      assert.match(html, new RegExp(`data-action="update-all-providers"[^>]*>${updating}</button>`, "u"), locale);
      assert.match(html, new RegExp(`data-action="health-check-all"[^>]*>${checking}</button>`, "u"), locale);
      assert.ok(html.includes(`<h3>${proxyHeading}</h3>`), locale);
      assert.ok(html.includes(`<h3>${ruleHeading}</h3>`), locale);
      assert.equal(/Updating\.\.\.|Checking\.\.\./u.test(html), false, `${locale}: three dots are not an ellipsis`);
    });
  } finally {
    state.providerBulkActions = original.bulk;
    state.providerCapabilityError = original.error;
  }
});

test("a provider's row names its running update in the display language", async () => {
  const original = { providers: state.providers, rules: state.ruleProviders, actions: state.providerActions };
  const expected = { en: "Updating", "zh-Hans": "正在更新", "zh-Hant": "正在更新", ja: "更新中" };
  try {
    state.providers = [{ name: "nodes", vehicle: "HTTP", proxies: 2, health: "ok", updated: "now", error: null, updatable: true }];
    state.ruleProviders = [{ name: "rules", behavior: "domain", rules: 3, updated: "now", error: null, updatable: true }];
    state.providerActions = new Set([providerActionKey("proxy-update", "nodes"), providerActionKey("rule-update", "rules")]);
    await inEveryLanguage(async (locale) => {
      const html = await renderPage("providers");
      assert.match(html, new RegExp(`data-provider-update="nodes" disabled>${expected[locale]}</button>`, "u"), `${locale}: the proxy provider`);
      assert.match(html, new RegExp(`data-rule-provider-update="rules" disabled>${expected[locale]}</button>`, "u"), `${locale}: the rule provider`);
    });
  } finally {
    state.providers = original.providers;
    state.ruleProviders = original.rules;
    state.providerActions = original.actions;
  }
});

test("the Profiles page names a source, a state and the inspector's view in the display language", async () => {
  const originalProfiles = responses.profiles_snapshot;
  const originalSettings = responses.read_settings_snapshot;
  const originalInspector = state.profileInspector;
  const expected = {
    en: ["subscription (unknown)", "Work · edit", "yes", "Work · QR code", "Work · details", "no", "local file (unknown)"],
    "zh-Hans": ["订阅 (未知)", "Work · 编辑", "是", "Work · 二维码", "Work · 详情", "否", "本地文件 (未知)"],
    "zh-Hant": ["訂閱 (未知)", "Work · 編輯", "是", "Work · QR 碼", "Work · 詳細資訊", "否", "本機檔案 (未知)"],
    ja: ["サブスクリプション (不明)", "Work · 編集", "はい", "Work · QR コード", "Work · 詳細", "いいえ", "ローカルファイル (不明)"],
  };
  try {
    responses.profiles_snapshot = {
      profiles: [{ id: "work", name: "Work", active: false, bytes: 2, source_kind: "subscription" }],
      invalid_profiles: [{ id: "broken", name: "Broken", source_kind: "local", selected: false, error: "outbounds are missing" }],
    };
    await inEveryLanguage(async (locale) => {
      const [card, edit, yes, qrcode, details, no, invalidCard] = expected[locale];
      // The saved time is worded when the list is read, in the language the
      // settings name.
      responses.read_settings_snapshot = { ...originalSettings, resolved_locale: locale, settings: { ...originalSettings.settings, language: locale } };
      await reloadButton.click();
      state.profileInspector = null;
      let html = await renderPage("profiles");
      assert.ok(html.includes(`>${card}</p>`), `${locale}: the card`);
      assert.ok(html.includes(`<p>${invalidCard}</p>`), `${locale}: the card of a profile that fails validation`);
      const profile = { id: "work", name: "Work", body: "{}", active: true };
      state.profileInspector = { id: "work", mode: "edit", profile };
      html = await renderPage("profiles");
      assert.ok(html.includes(`<h3>${edit}</h3>`), `${locale}: the editor's title`);
      assert.ok(html.includes(`<dd>${yes}</dd>`), `${locale}: an active profile`);
      state.profileInspector = { id: "work", mode: "qrcode", profile, svg: "<svg></svg>" };
      assert.ok((await renderPage("profiles")).includes(`<h3>${qrcode}</h3>`), `${locale}: the QR code's title`);
      state.profileInspector = { id: "work", mode: "identity", profile: { ...profile, active: false } };
      html = await renderPage("profiles");
      assert.ok(html.includes(`<h3>${details}</h3>`), `${locale}: any other view's title`);
      assert.ok(html.includes(`<dd>${no}</dd>`), `${locale}: an inactive profile`);
    });
  } finally {
    state.profileInspector = originalInspector;
    responses.profiles_snapshot = originalProfiles;
    responses.read_settings_snapshot = originalSettings;
    await reloadButton.click();
  }
});

test("the About page names its rows and its system requirement in the display language", async () => {
  const expected = {
    en: ["tunnel", "helper", "window", "pages", "or later"],
    "zh-Hans": ["隧道", "辅助程序", "窗口", "页面", "或更高版本"],
    "zh-Hant": ["通道", "輔助程式", "視窗", "頁面", "或更新版本"],
    ja: ["トンネル", "ヘルパー", "ウインドウ", "ページ", "以降"],
  };
  const minimum = state.payload.product.minimum_os_version;
  assert.equal(typeof minimum, "string", "the fixture names a minimum system version");
  await inEveryLanguage(async (locale) => {
    const html = await renderPage("feedback");
    const [tunnel, helper, window, pages, later] = expected[locale];
    for (const label of [tunnel, helper, window, pages]) assert.ok(html.includes(`<dt>${label}</dt>`), `${locale}: ${label}`);
    assert.ok(html.includes(`${minimum} ${later}`), `${locale}: ${later}`);
    if (locale !== "en") assert.equal(/<dt>(?:tunnel|helper|window|pages)<\/dt>|or later/u.test(html), false, locale);
  });
});

test("the Proxies page titles the listing of a profile without groups in the display language", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalProfiles = responses.profiles_snapshot;
  const originalText = responses.read_profile_text;
  const originalGroup = state.activeProxyGroup;
  const expected = { en: "Configured nodes", "zh-Hans": "已配置的节点", "zh-Hant": "已設定的節點", ja: "設定済みのノード" };
  try {
    responses.profiles_snapshot = { profiles: [{ id: "nodes-profile", name: "Nodes", active: true, bytes: 200, source_kind: "local", updated_epoch_secs: 1 }], invalid_profiles: [] };
    responses.read_profile_text = { id: "nodes-profile", name: "Nodes", proxy_selections: {},
      body: JSON.stringify({ outbounds: [{ type: "socks5", tag: "Node A" }, { type: "direct", tag: "DIRECT" }] }) };
    await setEngine(OFF_ENGINE);
    await reloadButton.click();
    state.activeProxyGroup = "Configured nodes";
    await inEveryLanguage(async (locale) => {
      const html = await renderPage("proxies");
      assert.ok(html.includes(`<h2>${expected[locale]}</h2>`), `${locale}: the heading`);
      assert.match(html, new RegExp(`data-proxy-group-tab="Configured nodes" title="${expected[locale]}"`, "u"), `${locale}: the tab keeps its identity`);
      if (locale !== "en") assert.equal(html.includes("<h2>Configured nodes</h2>"), false, locale);
    });
  } finally {
    state.activeProxyGroup = originalGroup;
    responses.profiles_snapshot = originalProfiles;
    responses.read_profile_text = originalText;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("a connection's details and an idle controller are labelled in the display language", async () => {
  const original = { connections: state.connections, detail: state.connectionDetailId, projection: state.projection };
  const expected = { en: ["Speed", "not running"], "zh-Hans": ["速度", "未运行"], "zh-Hant": ["速度", "未執行"], ja: ["速度", "停止中"] };
  try {
    state.connections = [{ id: "one", host: "example.test", rule: "MATCH", chains: ["Proxy"], upload: "1 B", download: "2 B", speed: "0 B/s", metadata: {} }];
    state.connectionDetailId = "one";
    state.projection = { ...state.projection, controller: null };
    await inEveryLanguage(async (locale) => {
      const [speed, idle] = expected[locale];
      assert.ok((await renderPage("connections")).includes(`<dt>${speed}</dt>`), `${locale}: the detail row`);
      assert.ok((await renderPage("settings")).includes(idle), `${locale}: the controller value`);
      if (locale !== "en") assert.equal((await renderPage("settings")).includes("not running"), false, locale);
    });
  } finally {
    state.connections = original.connections;
    state.connectionDetailId = original.detail;
    state.projection = original.projection;
  }
});

test("the Proxies page names a running latency test in the display language", async () => {
  const original = state.toggles.testingDelays;
  const expected = {
    en: ["Cancel latency test", "Testing…"],
    "zh-Hans": ["取消延迟测试", "测试中…"],
    "zh-Hant": ["取消延遲測試", "測試中…"],
    ja: ["遅延テストをキャンセル", "テスト中…"],
  };
  try {
    state.toggles.testingDelays = true;
    await inEveryLanguage(async (locale) => {
      const html = await renderPage("proxies");
      const [cancel, testing] = expected[locale];
      assert.match(html, new RegExp(`data-action="delay-test" title="${cancel}"`, "u"), locale);
      assert.ok(html.includes(testing), `${locale}: nodes without a result are being tested`);
      if (locale !== "en") assert.equal(/Cancel latency test|Testing…/u.test(html), false, locale);
    });
  } finally {
    state.toggles.testingDelays = original;
  }
});
