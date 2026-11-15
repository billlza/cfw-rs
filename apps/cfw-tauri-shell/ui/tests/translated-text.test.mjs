// Texts that used to bypass the catalogs: what a function answers in each
// display language.
import assert from "node:assert/strict";
import test from "node:test";
import { catalogs, getLocale, setLocale, SUPPORTED_LOCALES } from "../src/i18n.js";
import { errorText } from "../src/text-format.js";
import { credentialLabel, credentialProvisionBatch } from "../src/credentials.js";
import { cutoverConfirmArguments } from "../src/migration.js";
import { SHORTCUT_ACTIONS } from "../src/automation-settings.js";
import { platformStartupDesign } from "../src/platform-presentation.js";
import { CONFIGURED_NODES_GROUP, savedProfilePolicy } from "../src/profile-policy.js";
import { state } from "../src/state.js";
import { applyConnectionsSnapshot } from "../src/controller-snapshot.js";

function inEveryLanguage(check) {
  const old = getLocale();
  try {
    for (const locale of SUPPORTED_LOCALES) {
      setLocale(locale);
      check(locale);
    }
  } finally { setLocale(old); }
}

const message = (run) => {
  try { run(); } catch (error) { return error.message; }
  return assert.fail("the call was expected to throw");
};

test("an error without a message is described in the display language", () => {
  const expected = { en: "An unknown error occurred.", "zh-Hans": "发生未知错误。", "zh-Hant": "發生未知錯誤。", ja: "不明なエラーが発生しました。" };
  inEveryLanguage((locale) => {
    for (const error of [undefined, null, "", "   ", new Error(""), {}]) assert.equal(errorText(error), expected[locale], locale);
    assert.equal(errorText(new Error("disk full")), "disk full", "a diagnostic is shown as it was reported");
  });
});

test("a credential dialog names the field and the fault in the display language", () => {
  const reference = (kind) => [{ id: "one", kind }];
  const expected = {
    en: ["Trojan Password is required", "SOCKS5 Username is larger than 255 UTF-8 bytes", "HTTP Proxy Username is invalid",
      "Shadowsocks Password contains control characters", "WireGuard key must contain 32 bytes in canonical base64",
      "WireGuard key must be a nonzero canonical base64 value",
      "Tailscale auth key must be one token of up to 256 printable ASCII characters", "Tailscale Auth Key"],
    "zh-Hans": ["Trojan 密码不能为空", "SOCKS5 用户名超过 255 个 UTF-8 字节", "HTTP 代理用户名无效",
      "Shadowsocks 密码包含控制字符", "WireGuard 密钥必须是 32 字节的规范 base64 编码",
      "WireGuard 密钥必须是不全为零的规范 base64 值",
      "Tailscale 认证密钥必须是不含空格、最多 256 个可打印 ASCII 字符的一段文本", "Tailscale 认证密钥"],
  };
  inEveryLanguage((locale) => {
    const actual = [
      message(() => credentialProvisionBatch(reference("trojan_password"), [""])),
      message(() => credentialProvisionBatch(reference("socks5_username"), ["u".repeat(256)])),
      message(() => credentialProvisionBatch(reference("http_proxy_username"), ["user:name"])),
      message(() => credentialProvisionBatch(reference("shadowsocks_password"), ["pass\u0007word"])),
      message(() => credentialProvisionBatch(reference("wireguard_private_key"), ["short"])),
      message(() => credentialProvisionBatch(reference("wireguard_private_key"), [`${"A".repeat(43)}=`])),
      message(() => credentialProvisionBatch(reference("tailscale_auth_key"), ["two tokens"])),
      credentialLabel("tailscale_auth_key"),
    ];
    if (expected[locale]) assert.deepEqual(actual, expected[locale], locale);
    const english = expected.en;
    // No language shows another one's sentence, and none shows the key.
    if (locale !== "en") actual.forEach((text, index) => assert.notEqual(text, english[index], `${locale}: ${english[index]}`));
    assert.equal(
      message(() => credentialProvisionBatch(reference("trojan_password"), ["x".repeat(16 * 1024 + 1)])),
      catalogs[locale]["{label} is larger than 16 KiB"].replace("{label}", credentialLabel("trojan_password")),
      locale,
    );
  });
});

test("the cutover confirmation says what is missing in the display language", () => {
  const now = 1_000;
  const receiptId = "3f2b8c1e-5d4a-4b6c-9e7f-0a1b2c3d4e5f";
  const cutover = {
    target: "tunnel", receiptTarget: "tunnel", receiptId, receiptIssuedAt: now - 1, receiptExpiresAt: now + 1,
    confirmedReceiptId: null, dnsReviewedReceiptId: receiptId,
  };
  const expected = {
    en: ["Cutover receipt is missing or expired; run Prepare again.", "Tick the one-way cutover confirmation for this preparation."],
    "zh-Hans": ["准备结果缺失或已过期，请重新准备。", "请勾选本次准备的单向切换确认项。"],
    "zh-Hant": ["準備結果遺失或已過期，請重新準備。", "請勾選本次準備的單向切換確認項目。"],
    ja: ["準備の結果がないか、期限が切れています。もう一度準備してください。", "この準備について、一方向の切り替えの確認にチェックを入れてください。"],
  };
  inEveryLanguage((locale) => {
    assert.deepEqual([
      message(() => cutoverConfirmArguments({ ...cutover, receiptId: null }, now)),
      message(() => cutoverConfirmArguments(cutover, now)),
    ], expected[locale], locale);
  });
});

test("table labels that are translated where they are rendered have a message in every language", () => {
  const labels = [
    ...SHORTCUT_ACTIONS.map(([, label]) => label),
    platformStartupDesign("windows", { startup_strategy: "Registry Run key" }).label,
    CONFIGURED_NODES_GROUP,
  ];
  assert.ok(labels.includes("Start / stop core") && labels.includes("Start at Login"));
  assert.equal(platformStartupDesign("macos", { launchd_strategy: "SMAppService" }).label, "launchd");
  for (const locale of SUPPORTED_LOCALES) {
    for (const label of labels) {
      assert.ok(Object.hasOwn(catalogs[locale], label), `${locale}: ${label}`);
      if (locale !== "en") assert.notEqual(catalogs[locale][label], label, `${locale}: ${label}`);
    }
  }
});

test("a connection's rate and a missing destination are worded in the display language", () => {
  const expected = {
    en: "0 B/s up · 0 B/s down", "zh-Hans": "上传 0 B/s · 下载 0 B/s",
    "zh-Hant": "上傳 0 B/s · 下載 0 B/s", ja: "アップロード 0 B/s · ダウンロード 0 B/s",
  };
  const unknown = { en: "unknown", "zh-Hans": "未知", "zh-Hant": "未知", ja: "不明" };
  const original = state.connections;
  try {
    inEveryLanguage((locale) => {
      applyConnectionsSnapshot({ connections: [
        { id: "one", upload: 0, download: 0, metadata: { host: "example.test" } },
        { id: "two", upload: 0, download: 0, metadata: {} },
      ] });
      assert.equal(state.connections[0].speed, expected[locale], locale);
      assert.deepEqual(state.connections.map(({ host }) => host), ["example.test", unknown[locale]], `${locale}: a connection without a destination`);
    });
  } finally { state.connections = original; }
});

test("the listing of a profile without groups keeps one identity in every language", () => {
  const profile = { id: "nodes", body: JSON.stringify({ outbounds: [{ type: "socks5", tag: "only" }] }) };
  inEveryLanguage((locale) => {
    const [group] = savedProfilePolicy(profile).groups;
    assert.deepEqual({ name: group.name, type: group.type }, { name: CONFIGURED_NODES_GROUP, type: "List" }, locale);
  });
});
