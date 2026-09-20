import test from "node:test";
import assert from "node:assert/strict";
import { createRulesView, RULE_PAGE_SIZE } from "../src/rules.js";
import { escapeHtml } from "../src/format.js";

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
