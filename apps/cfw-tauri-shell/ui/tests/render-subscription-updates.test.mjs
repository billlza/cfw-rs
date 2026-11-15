// Background subscription updates in the running dashboard: the startup read,
// the setting, the notes on the Profiles page and the host's reports, in every
// display language. support/render-harness.mjs drives the real bootstrap.
import assert from "node:assert/strict";
import test from "node:test";
import { getLocale, setLocale, SUPPORTED_LOCALES } from "../src/i18n.js";
import {
  OFF_ENGINE, PROFILE_ID, emit, interactiveElement, invocationDetails, invoked, listeners,
  querySelectorAllElements, reloadButton, renderPage, responses, setEngine, startupInvocationCommands, state,
} from "./support/render-harness.mjs";

const OTHER_ID = "9a1f5a53-6d0b-4c53-9a8e-3a4f3d7d7b11";
const count = (command) => invoked.filter((name) => name === command).length;
const quiet = { interval: "off", profiles: [], updated: [] };

async function inEveryLanguage(check) {
  const old = getLocale();
  try {
    for (const locale of SUPPORTED_LOCALES) {
      setLocale(locale);
      await check(locale);
    }
  } finally { setLocale(old); }
}

/// Two subscriptions: the one the core runs and another one.
async function withTwoSubscriptions(run) {
  const original = responses.profiles_snapshot;
  responses.profiles_snapshot = {
    profiles: [
      { id: PROFILE_ID, name: "Work", active: true, bytes: 2048, updated_epoch_secs: 1_700_000_000, source_kind: "subscription" },
      { id: OTHER_ID, name: "Home", active: false, bytes: 1024, updated_epoch_secs: 1_700_000_000, source_kind: "subscription" },
    ],
    invalid_profiles: [],
  };
  try {
    await reloadButton.click();
    await run();
  } finally {
    responses.profiles_snapshot = original;
    await emit("cfw://subscription-updates", quiet);
    await reloadButton.click();
  }
}

test("the dashboard hears the host's reports and reads the update state at startup and on reload", async () => {
  assert.ok(listeners.has("cfw://subscription-updates"));
  assert.equal(startupInvocationCommands.filter((command) => command === "subscription_updates").length, 1);
  assert.equal(startupInvocationCommands.includes("set_subscription_update_interval"), false);
  const before = count("subscription_updates");
  await reloadButton.click();
  assert.equal(count("subscription_updates"), before + 1);
});

test("the Settings page offers the intervals in the display language", async () => {
  const expected = {
    en: ["Automatic subscription updates", "Download subscriptions in the background.", ["Off", "Every 6 hours", "Every 12 hours", "Every day", "Every week"]],
    "zh-Hans": ["订阅自动更新", "在后台下载订阅。", ["关闭", "每 6 小时", "每 12 小时", "每天", "每周"]],
    "zh-Hant": ["訂閱自動更新", "在背景下載訂閱。", ["關閉", "每 6 小時", "每 12 小時", "每天", "每週"]],
    ja: ["サブスクリプションの自動更新", "サブスクリプションをバックグラウンドでダウンロードします。", ["オフ", "6 時間ごと", "12 時間ごと", "毎日", "毎週"]],
  };
  const values = ["off", "six_hours", "twelve_hours", "daily", "weekly"];
  try {
    await emit("cfw://subscription-updates", { ...quiet, interval: "twelve_hours" });
    await inEveryLanguage(async (locale) => {
      const html = await renderPage("settings");
      const [label, hint, options] = expected[locale];
      assert.ok(html.includes(`<b>${label}</b>`), `${locale}: the label`);
      assert.ok(html.includes(`<small>${hint}`), `${locale}: the hint`);
      const select = html.slice(html.indexOf("data-subscription-update-interval"));
      const offered = select.slice(0, select.indexOf("</select>"));
      assert.equal(offered.startsWith("data-subscription-update-interval >"), true, `${locale}: the control is enabled`);
      assert.deepEqual(
        [...offered.matchAll(/<option value="([a-z_]+)" (selected)?>([^<]+)<\/option>/gu)].map(([, value, selected, text]) => [value, Boolean(selected), text]),
        values.map((value, index) => [value, value === "twelve_hours", options[index]]),
        locale,
      );
    });
  } finally {
    await emit("cfw://subscription-updates", quiet);
  }
});

test("a state the host could not read disables the setting and shows the host's reason", async () => {
  const original = responses.subscription_updates;
  try {
    responses.subscription_updates = () => { throw new Error('the stored <document> is not "canonical"'); };
    await reloadButton.click();
    const html = await renderPage("settings");
    const reason = "the stored &lt;document&gt; is not &quot;canonical&quot;";
    assert.ok(html.includes(`<small>${reason}</small>`));
    assert.ok(html.includes(`data-subscription-update-interval disabled title="${reason}">`));
    assert.equal(html.includes("Download subscriptions in the background."), false, "the reason replaces the hint");
    assert.ok(state.logs.some(({ level, message }) => level === "error"
      && message === 'Automatic subscription updates are unavailable: the stored <document> is not "canonical"'));
  } finally {
    responses.subscription_updates = original;
    await reloadButton.click();
  }
  assert.ok((await renderPage("settings")).includes("data-subscription-update-interval >"), "a later read enables it again");
});

test("choosing an interval on the Settings page stores it and shows what the host stored", async () => {
  const expected = {
    en: ["Every day", "Automatic subscription updates: Every day"],
    "zh-Hans": ["每天", "订阅自动更新：每天"],
    "zh-Hant": ["每天", "訂閱自動更新：每天"],
    ja: ["毎日", "サブスクリプションの自動更新：毎日"],
  };
  const select = interactiveElement("select");
  select.value = "daily";
  const sent = () => invocationDetails.filter(({ command }) => command === "set_subscription_update_interval").map(({ args }) => args);
  try {
    responses.set_subscription_update_interval = ({ interval }) => ({ interval, profiles: [] });
    querySelectorAllElements.set("[data-subscription-update-interval]", [select]);
    await inEveryLanguage(async (locale) => {
      const before = sent().length;
      await emit("cfw://subscription-updates", quiet);
      await renderPage("settings");
      await select.trigger("change");
      assert.deepEqual(sent().slice(before), [{ interval: "daily" }], locale);
      const [option, line] = expected[locale];
      assert.ok((await renderPage("settings")).includes(`<option value="daily" selected>${option}</option>`), `${locale}: the stored interval is selected`);
      assert.deepEqual(
        state.logs.filter(({ source, message }) => source === "settings" && message === line).map(({ level }) => level),
        ["info"],
        `${locale}: the change is logged once`,
      );
    });
  } finally {
    querySelectorAllElements.delete("[data-subscription-update-interval]");
    delete responses.set_subscription_update_interval;
    await emit("cfw://subscription-updates", quiet);
  }
});

test("the Profiles page shows a waiting change and a failed update in the display language", async () => {
  const expected = {
    en: ["New subscription content is available. Applying it restarts the core.", "Apply update", "Automatic update failed: subscription request timed out", "New subscription content is available."],
    "zh-Hans": ["订阅有新内容。应用后内核会重启。", "应用更新", "自动更新失败：subscription request timed out", "订阅有新内容。"],
    "zh-Hant": ["訂閱有新內容。套用後核心會重新啟動。", "套用更新", "自動更新失敗：subscription request timed out", "訂閱有新內容。"],
    ja: ["サブスクリプションに新しい内容があります。適用するとコアが再起動します。", "更新を適用", "自動更新に失敗しました：subscription request timed out", "サブスクリプションに新しい内容があります。"],
  };
  const originalEngine = responses.engine_snapshot;
  await withTwoSubscriptions(async () => {
    assert.equal((await renderPage("profiles")).includes("profile-card-update"), false, "no note without a report");
    await emit("cfw://subscription-updates", {
      interval: "daily",
      profiles: [
        { id: PROFILE_ID, attempted_epoch_secs: 1_700_000_100, state: "waiting" },
        { id: OTHER_ID, attempted_epoch_secs: 1_700_000_200, state: "failed", error: "subscription request timed out" },
      ],
      updated: [],
    });
    try {
      await inEveryLanguage(async (locale) => {
        const [waiting, apply, failed] = expected[locale];
        const html = await renderPage("profiles");
        const [, work, home] = html.split("data-profile-card=");
        assert.ok(work.includes(`<p class="profile-card-update" role="note">${waiting}</p>`), `${locale}: the waiting change`);
        assert.ok(work.includes(`<button class="profile-card-apply" data-profile-update="${PROFILE_ID}" >${apply}</button>`), `${locale}: the action`);
        assert.ok(home.includes(`<p class="profile-card-update failed" role="note">${failed}</p>`), `${locale}: the failure`);
        assert.equal(home.includes("profile-card-apply"), false, `${locale}: a failure offers no action of its own`);
        if (locale !== "en") assert.equal(/New subscription content|Apply update|Automatic update failed/u.test(html), false, `${locale}: no English text`);
      });
      // With the core off nothing restarts.
      await setEngine(OFF_ENGINE);
      await inEveryLanguage(async (locale) => {
        const html = await renderPage("profiles");
        assert.ok(html.includes(`<p class="profile-card-update" role="note">${expected[locale][3]}</p>`), `${locale}: no restart is announced`);
      });
    } finally {
      await setEngine(originalEngine);
    }
  });
});

test("applying from the card updates the profile, and the host's next report takes the note away", async () => {
  const button = interactiveElement("button");
  button.dataset.profileUpdate = PROFILE_ID;
  await withTwoSubscriptions(async () => {
    try {
      responses.update_profile = {
        id: PROFILE_ID, name: "Work", bytes: 2048, digest: "digest",
        credential_cleanup_removed: 0, credential_cleanup_pending: false, reset_proxy_groups: [],
      };
      await emit("cfw://subscription-updates", {
        interval: "daily", profiles: [{ id: PROFILE_ID, attempted_epoch_secs: 1_700_000_100, state: "waiting" }], updated: [],
      });
      querySelectorAllElements.set("[data-profile-update]", [button]);
      await renderPage("profiles");
      const snapshots = count("profiles_snapshot");
      await button.trigger("click");
      assert.deepEqual(
        invocationDetails.filter(({ command }) => command === "update_profile").map(({ args }) => args),
        [{ id: PROFILE_ID }],
      );
      assert.ok(count("profiles_snapshot") > snapshots, "the list is read again");
      assert.ok(state.logs.some(({ message }) => message === "Work subscription updated"));
      assert.equal(state.subscriptionUpdates.applying.size, 0);

      await emit("cfw://subscription-updates", { interval: "daily", profiles: [], updated: [] });
      assert.equal((await renderPage("profiles")).includes("profile-card-update"), false);
    } finally {
      querySelectorAllElements.delete("[data-profile-update]");
      delete responses.update_profile;
    }
  });
});

test("an application that fails is reported in the display language and the change keeps waiting", async () => {
  const expected = {
    en: "Update failed: subscription request timed out",
    "zh-Hans": "更新失败：subscription request timed out",
    "zh-Hant": "更新失敗：subscription request timed out",
    ja: "更新 に失敗しました：subscription request timed out",
  };
  const button = interactiveElement("button");
  button.dataset.profileUpdate = PROFILE_ID;
  await withTwoSubscriptions(async () => {
    try {
      responses.update_profile = () => { throw new Error("subscription request timed out"); };
      await emit("cfw://subscription-updates", {
        interval: "daily", profiles: [{ id: PROFILE_ID, attempted_epoch_secs: 1_700_000_100, state: "waiting" }], updated: [],
      });
      querySelectorAllElements.set("[data-profile-update]", [button]);
      await inEveryLanguage(async (locale) => {
        await renderPage("profiles");
        await button.trigger("click");
        assert.deepEqual(
          state.logs.filter(({ source, message }) => source === "profile" && message === expected[locale]).map(({ level }) => level),
          ["error"],
          `${locale}: the failure is logged once`,
        );
        assert.equal(state.subscriptionUpdates.applying.size, 0, locale);
        assert.ok((await renderPage("profiles")).includes(`data-profile-update="${PROFILE_ID}" >`), `${locale}: the change can be applied again`);
      });
    } finally {
      querySelectorAllElements.delete("[data-profile-update]");
      delete responses.update_profile;
    }
  });
});

test("a look that saved profiles again reloads the list and says so in the display language", async () => {
  const expected = {
    en: ["Work updated automatically", "Saved nodes were removed from these groups; the new defaults apply: Auto"],
    "zh-Hans": ["Work 已自动更新", "这些代理组中的已保存节点被移除，将使用新默认值：Auto"],
    "zh-Hant": ["Work 已自動更新", "這些代理群組中的已儲存節點被移除，將使用新預設值：Auto"],
    ja: ["Work を自動更新しました", "次のグループから保存済みノードが削除されたため、新しい既定値を適用します：Auto"],
  };
  await withTwoSubscriptions(async () => {
    await inEveryLanguage(async (locale) => {
      const snapshots = count("profiles_snapshot");
      const projections = count("read_runtime_config_text");
      await emit("cfw://subscription-updates", {
        interval: "daily", profiles: [], updated: [{ id: PROFILE_ID, name: "Work", reset_proxy_groups: ["Auto"] }],
      });
      assert.equal(count("profiles_snapshot"), snapshots + 1, `${locale}: the list is read again`);
      assert.equal(count("read_runtime_config_text"), projections + 1, `${locale}: the projection is read again`);
      const logged = (level, message) => state.logs.some((entry) => entry.level === level && entry.source === "profile" && entry.message === message);
      assert.ok(logged("info", expected[locale][0]), `${locale}: the update is logged`);
      assert.ok(logged("warning", expected[locale][1]), `${locale}: the groups that lost their saved node are named`);
    });
  });
});
