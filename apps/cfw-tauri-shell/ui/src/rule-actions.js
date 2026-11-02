// The Rules page actions: opening it, reloading rules, paging and search.
import { state } from "./state.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { controllerActionAllowed } from "./engine-identity.js";
import { loadRulesSnapshot } from "./controller-reads.js";

export function createRuleActions({ renderPage, changeRulePage }) {
  const actions = {
    "open-rules": async () => {
      state.activePage = "rules";
      await loadRulesSnapshot();
      renderPage();
    },
    "reload-rules": async () => {
      if (!controllerActionAllowed(t("Rules reload"), "rules")) return;
      const loaded = await loadRulesSnapshot();
      appendLog(loaded ? "info" : "error", "rules", loaded ? t("Loaded {count} controller rules", { count: state.rules.length }) : t("Rules controller endpoint unavailable"));
      renderPage();
    },
  };

  function bindPage() {
    document.querySelectorAll("[data-rule-page]").forEach((button) => button.addEventListener("click", () => { changeRulePage(Number(button.dataset.rulePage)); renderPage(); }));

    const ruleSearch = document.querySelector("[data-rule-search]");
    if (ruleSearch) {
      ruleSearch.addEventListener("input", (event) => {
        state.ruleSearch = event.currentTarget.value;
        renderPage();
      });
    }
  }

  return { actions, bindPage };
}
