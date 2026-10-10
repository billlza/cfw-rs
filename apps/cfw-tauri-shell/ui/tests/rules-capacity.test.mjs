import test from "node:test";
import assert from "node:assert/strict";
import { createRulesView, RULE_PAGE_SIZE } from "../src/rules.js";
import { escapeHtml } from "../src/format.js";
import { getLocale, setLocale, SUPPORTED_LOCALES, t } from "../src/i18n.js";

test("rule search distinguishes no matches from no source rules and preserves reported errors", () => {
  const locale = getLocale();
  try {
    for (const language of SUPPORTED_LOCALES) {
      setLocale(language);
      for (const active of [false, true]) {
        const rules = [{ index: "1", type: "DOMAIN", payload: "present.example", proxy: "PROXY", hits: "—" }];
        const state = { engine: { active }, rules, savedProfilePolicy: { rules }, ruleSearch: "absent.example" };
        const view = createRulesView({ state, escapeHtml });
        assert.ok(view.renderRules().includes(t("No rules match this filter.")), `${language}, active=${active}`);
        assert.equal(rules.length, 1);
        state.savedProfilePolicyError = "Policy read failed: <denied>";
        assert.match(view.renderRules(), /Policy read failed: &lt;denied&gt;/u);
        assert.ok(!view.renderRules().includes(t("No rules match this filter.")));
        state.savedProfilePolicyError = null;
        state.ruleSearch = "";
        assert.match(view.renderRules(), /present\.example/u);
        assert.doesNotMatch(view.renderRules(), /class="empty"/u);
        rules.length = 0;
        assert.ok(view.renderRules().includes(t(active ? "No rules loaded from the controller." : "The selected profile has no explicit rules.")));
        state.savedProfilePolicyError = "Policy read failed: <denied>";
        assert.match(view.renderRules(), /Policy read failed: &lt;denied&gt;/u);
        assert.ok(!view.renderRules().includes(t("No rules match this filter.")));
      }
    }
  } finally { setLocale(locale); }
});

test("all 8192 rules remain reachable with bounded rendering and whole-profile search", () => {
  const rules = Array.from({ length: 8192 }, (_, i) => ({ index: String(i + 1), type: "DOMAIN", payload: `site-${i}.example`, proxy: "PROXY", hits: "—" }));
  const state = { engine: { active: false }, ruleSearch: "", savedProfilePolicy: { rules } };
  const view = createRulesView({ state, escapeHtml });
  let count = 0;
  for (let page = 0; page < 8192 / RULE_PAGE_SIZE; page++) {
    const html = view.renderRules();
    const rows = [...html.matchAll(/class="table-row rule-row"/gu)].length;
    assert.equal(rows, RULE_PAGE_SIZE);
    count += rows;
    view.changePage(1);
  }
  assert.equal(count, 8192);
  state.ruleSearch = "site-8191.example";
  const searched = view.renderRules();
  assert.equal([...searched.matchAll(/class="table-row rule-row"/gu)].length, 1);
  assert.match(searched, /site-8191.example/u);
});
