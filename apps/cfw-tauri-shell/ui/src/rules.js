// Bounded rule rendering keeps every saved/live rule reachable by page/search.
import { safeRegex } from "./format.js";
export const RULE_PAGE_SIZE = 256;
export function createRulesView({state,escapeHtml}) {
let page=0;let query=null;let previousSource=null;
function visibleRules(source = state.rules) {
  const regex = safeRegex(state.ruleSearch);
  return source.filter((rule) => {
    const haystack = [rule.index, rule.type, rule.payload, rule.proxy, rule.hits].filter(Boolean).join(" ");
    return !state.ruleSearch || (regex ? regex.test(haystack) : haystack.toLowerCase().includes(state.ruleSearch.toLowerCase()));
  });
}

function renderRules() {
  const live = state.engine.active;
  const source = live ? state.rules : state.savedProfilePolicy?.rules ?? [];
  const filtered = visibleRules(source);
  if (query !== state.ruleSearch || previousSource !== source) { page = 0; query = state.ruleSearch; previousSource = source; }
  const pages = Math.max(1, Math.ceil(filtered.length / RULE_PAGE_SIZE));
  page = Math.max(0, Math.min(pages - 1, page));
  const rules = filtered.slice(page * RULE_PAGE_SIZE, (page + 1) * RULE_PAGE_SIZE);
  return `
    <div class="rules-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Router</p>
          <h3>${filtered.length} / ${source.length} ${live ? "active" : "saved"} rule entries</h3>
          <p class="muted">${live ? "Live rules from the running engine." : "Saved profile rules; hit counters become available when the engine reports them."}</p>
        </div>
        <div class="search-box">
          <input value="${escapeHtml(state.ruleSearch)}" data-rule-search aria-label="Search rules" placeholder="Search rules" />
        </div>
        <div class="toolbar-actions">
          <button class="button ghost" data-action="reload-rules">Reload Rules</button>
        </div>
      </section>

      ${pages > 1 ? `<nav class="proxy-pagination" aria-label="Rule pages"><button data-rule-page="-1"${page === 0 ? " disabled" : ""}>Previous</button><span>${page + 1} / ${pages}</span><button data-rule-page="1"${page + 1 === pages ? " disabled" : ""}>Next</button></nav>` : ""}
      <section class="panel table-panel">
        <div class="connection-table">
          <div class="table-row rule-head">
            <span>#</span><span>Type</span><span>Payload</span><span>Proxy</span><span>Hits</span>
          </div>
          ${rules.map((rule) => `
            <div class="table-row rule-row">
              <span>${escapeHtml(rule.index)}</span>
              <span>${escapeHtml(rule.type)}</span>
              <span>${escapeHtml(rule.payload || "-")}</span>
              <span>${escapeHtml(rule.proxy)}</span>
              <span>${escapeHtml(rule.hits)}</span>
            </div>
          `).join("") || `<p class="empty">${escapeHtml(state.savedProfilePolicyError ?? (live ? "No rules loaded from the controller." : "The selected profile has no explicit rules."))}</p>`}
        </div>
      </section>
    </div>
  `;
}

return {renderRules,changePage:(delta)=>{page+=delta;}};
}
