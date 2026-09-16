import { escapeHtml, errorText, formatRelativeUpdated, providerActionKey, providerBatchSummary, providerBatchSucceeded } from "./format.js";

// Resource operations are bound to the selected profile, not a transient core
// generation. An accepted online update deliberately changes that generation.
export function createProviderUI({ state, invoke, appendLog, renderPage, refreshProfile }) {
  let selectionEpoch = 0;
  let snapshotEpoch = 0;
  const profileId = () => state.profiles.find((profile) => profile.active)?.id ?? null;
  const token = () => ({ profileId: profileId(), epoch: selectionEpoch });
  const current = (value) => value.profileId === profileId() && value.epoch === selectionEpoch;
  function providerSelectionChanged() {
    selectionEpoch += 1;
    snapshotEpoch += 1;
    state.providers = [];
    state.ruleProviders = [];
    state.providerCapabilityError = null;
    state.providerActions.clear();
    state.providerBulkActions.clear();
  }
  function allowed(action) {
    if (state.engine.providerManagementAvailable === true && profileId() && !state.profilesUnavailableReason) return true;
    appendLog("info", "provider", `${action} requires an available selected profile`);
    return false;
  }
  function applyProvidersSnapshot(snapshot) {
    if (!Array.isArray(snapshot?.proxy_providers) || !Array.isArray(snapshot?.rule_providers)) throw new TypeError("provider snapshot is invalid");
    const common = (provider) => ({ name: provider.name, type: provider.kind, vehicle: provider.vehicle_type,
      updated: provider.extra?.updated_epoch_secs ? formatRelativeUpdated(provider.extra.updated_epoch_secs) : provider.updated_at ?? "unknown",
      updatable: provider.extra?.updatable === true, error: provider.extra?.update_error ?? null,
    });
    state.providers = snapshot.proxy_providers.map((provider) => ({ ...common(provider),
      health: provider.extra?.health ?? "Not tested", proxies: provider.proxies?.length ?? 0,
    }));
    state.ruleProviders = snapshot.rule_providers.map((provider) => ({ ...common(provider),
      behavior: provider.behavior ?? provider.vehicle_type, rules: provider.rules?.length ?? 0,
    }));
    state.providerCapabilityError = null;
  }
  async function loadProvidersSnapshot() {
    const captured = token();
    const epoch = ++snapshotEpoch;
    if (!captured.profileId || state.engine.providerManagementAvailable !== true) {
      state.providers = []; state.ruleProviders = [];
      state.providerCapabilityError = state.engine.providerManagementAvailable === true ? null : "Provider management is unavailable in this application.";
      return false;
    }
    try {
      const snapshot = await invoke("providers_snapshot");
      if (!current(captured) || epoch !== snapshotEpoch) return false;
      applyProvidersSnapshot(snapshot);
      return true;
    } catch (error) {
      if (!current(captured) || epoch !== snapshotEpoch) return false;
      state.providers = []; state.ruleProviders = [];
      state.providerCapabilityError = errorText(error);
      appendLog("error", "provider", state.providerCapabilityError);
      return false;
    }
  }
  async function run(action, key, bulk, operation, changesProfile) {
    if (!allowed(action)) return;
    const captured = token();
    const pending = bulk ? state.providerBulkActions : state.providerActions;
    if (pending.has(key)) return;
    pending.add(key); renderPage();
    try {
      const result = await operation();
      if (!current(captured)) return;
      if (changesProfile) await refreshProfile();
      if (!current(captured)) return;
      await loadProvidersSnapshot();
      if (!current(captured)) return;
      appendLog(result ? (providerBatchSucceeded(result) ? "info" : "error") : "info", "provider",
        result ? providerBatchSummary(action, result) : `${action} completed`);
    } catch (error) {
      if (!current(captured)) return;
      appendLog("error", "provider", `${action} failed: ${errorText(error)}`);
      await loadProvidersSnapshot();
    } finally {
      if (current(captured)) { pending.delete(key); renderPage(); }
    }
  }
  function bindProviderButtons() {
    document.querySelectorAll("[data-provider-update], [data-rule-provider-update]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const { providerUpdate, ruleProviderUpdate } = event.currentTarget.dataset;
        const name = providerUpdate ?? ruleProviderUpdate;
        await run(`${name} update`, providerActionKey(providerUpdate ? "proxy-update" : "rule-update", name), false,
          () => providerUpdate ? invoke("update_proxy_provider", { name }) : invoke("update_rule_provider", { name }), true);
      });
    });
    document.querySelectorAll("[data-provider-health]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const name = event.currentTarget.dataset.providerHealth;
        await run(`${name} health check`, providerActionKey("proxy-health", name), false,
          () => invoke("health_check_proxy_provider", { name }), false);
      });
    });
  }
  async function handleProviderAction(action) {
    if (action === "update-all-providers") {
      await run("Update All", action, true, () => invoke("update_all_providers"), true);
      return true;
    }
    if (action === "health-check-all") {
      await run("Health Check All", action, true, () => invoke("health_check_all_proxy_providers"), false);
      return true;
    }
    return false;
  }
function renderProviders() {
  const updatingAll = state.providerBulkActions.has("update-all-providers");
  const healthAll = state.providerBulkActions.has("health-check-all");
  const providerUnavailable = Boolean(state.providerCapabilityError) || state.engine.providerManagementAvailable !== true || !profileId();
  const providerUnavailableReason = state.providerCapabilityError ?? "Select a profile containing providers.";
  return `
    <div class="providers-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Providers</p>
          <h3>Proxy Providers</h3>
          <p class="muted">${providerUnavailable ? escapeHtml(providerUnavailableReason) : "Resources in the selected profile. Updates retain the current configuration if validation fails."}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button" data-action="update-all-providers" ${updatingAll || providerUnavailable || ![...state.providers, ...state.ruleProviders].some((provider) => provider.updatable) ? "disabled" : ""}>${updatingAll ? "Updating..." : "Update All"}</button>
          <button class="button ghost" data-action="health-check-all" ${healthAll || providerUnavailable || state.providers.length === 0 ? "disabled" : ""}>${healthAll ? "Checking..." : "Health Check All"}</button>
          <button class="button ghost" data-action="open-rules">Rules</button>
        </div>
      </section>

      <section class="provider-section">
        <div class="section-title">Proxy Providers</div>
        ${state.providers.length ? state.providers.map((provider) => {
          const updateKey = providerActionKey("proxy-update", provider.name);
          const healthKey = providerActionKey("proxy-health", provider.name);
          const updating = state.providerActions.has(updateKey);
          const checking = state.providerActions.has(healthKey);
          return `
            <article class="panel provider-row">
              <div>
                <p class="label">${escapeHtml(provider.vehicle)}</p>
                <h3>${escapeHtml(provider.name)}</h3>
                <p class="muted">${provider.proxies} proxies · ${escapeHtml(provider.health)} · updated ${escapeHtml(provider.updated)}</p>
                ${provider.error ? `<p class="error">${escapeHtml(provider.error)}</p>` : ""}
              </div>
              <div class="row-actions">
                <button class="button ghost" data-provider-update="${escapeHtml(provider.name)}" ${updating || providerUnavailable || !provider.updatable ? "disabled" : ""}>${updating ? "Updating" : "Update"}</button>
                <button class="button" data-provider-health="${escapeHtml(provider.name)}" ${checking || providerUnavailable ? "disabled" : ""}>${checking ? "Checking" : "Health Check"}</button>
              </div>
            </article>
          `;
        }).join("") : `
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Selected profile</p>
              <h3>${providerUnavailable ? "Proxy provider management unavailable" : "No proxy providers loaded"}</h3>
              <p class="muted">${providerUnavailable ? escapeHtml(providerUnavailableReason) : "Import a configuration containing proxy-providers to manage its nodes here."}</p>
            </div>
          </article>
        `}
      </section>

      <section class="provider-section">
        <div class="section-title">Rule Providers</div>
        ${state.ruleProviders.length ? state.ruleProviders.map((provider) => {
          const updateKey = providerActionKey("rule-update", provider.name);
          const updating = state.providerActions.has(updateKey);
          return `
            <article class="panel provider-row">
              <div>
                <p class="label">${escapeHtml(provider.behavior)}</p>
                <h3>${escapeHtml(provider.name)}</h3>
                <p class="muted">${provider.rules.toLocaleString()} rules · updated ${escapeHtml(provider.updated)}</p>
                ${provider.error ? `<p class="error">${escapeHtml(provider.error)}</p>` : ""}
              </div>
              <div class="row-actions">
                <button class="button ghost" data-rule-provider-update="${escapeHtml(provider.name)}" ${updating || providerUnavailable || !provider.updatable ? "disabled" : ""}>${updating ? "Updating" : "Update"}</button>
              </div>
            </article>
          `;
        }).join("") : `
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Selected profile</p>
              <h3>${providerUnavailable ? "Rule provider management unavailable" : "No rule providers loaded"}</h3>
              <p class="muted">${providerUnavailable ? escapeHtml(providerUnavailableReason) : "Import a configuration containing rule-providers to manage its rules here."}</p>
            </div>
          </article>
        `}
      </section>
    </div>
  `;
}

  return { renderProviders, loadProvidersSnapshot, bindProviderButtons, handleProviderAction, providerSelectionChanged };
}
