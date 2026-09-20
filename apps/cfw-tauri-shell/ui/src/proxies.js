import { t } from "./i18n.js";
// Proxy presentation and bounded latency-result updates. Network operations
// stay in the shared command/identity pipeline.
export const PROXY_PAGE_SIZE = 96;

export function proxyPage(nodes, requestedPage) {
  const pages = Math.max(1, Math.ceil(nodes.length / PROXY_PAGE_SIZE));
  const page = Math.min(pages - 1, Math.max(0, requestedPage));
  return { page, pages, total: nodes.length, nodes: nodes.slice(page * PROXY_PAGE_SIZE, (page + 1) * PROXY_PAGE_SIZE) };
}

export function indexProxyNodes(groups) {
  const index = new Map();
  for (const group of groups) {
    for (const node of group.options) {
      if (!index.has(node.name)) index.set(node.name, new Set());
      index.get(node.name).add(node);
    }
  }
  return index;
}

export function createProxyView({state, runtime, escapeHtml, delayFailureLabel, engineStateLabel, engineIsOff}) {
let indexedGroups = null;
let nodeIndex = new Map();
let pageKey = null;
let pageNumber = 0;
function indexedNodes() {
  const groups = displayedProxyGroups();
  if (indexedGroups !== groups) {
    indexedGroups = groups;
    nodeIndex = indexProxyNodes(groups);
  }
  return nodeIndex;
}
function currentPageKey(group) {
  return JSON.stringify([state.savedProfilePolicy?.profileId, group?.name, state.proxyFilter, group && hideTimedOutProxies(group)]);
}
function changePage(delta) { pageNumber += delta; }
function revealSelected(name) {
  const group = activeProxyGroup();
  pageKey = currentPageKey(group);
  pageNumber = Math.floor(Math.max(0, group?.options.findIndex((node) => node.name === name) ?? 0) / PROXY_PAGE_SIZE);
}
function delayClass(delay, failure = null) {
  if (failure) return "dead";
  if (delay === null || delay === undefined) return "pending";
  if (delay <= 0) return "dead";
  if (delay < 80) return "fast";
  if (delay < 180) return "mid";
  return "slow";
}

function delayLabel(delay, failure = null) {
  if (failure) return delayFailureLabel(failure);
  if (delay === null || delay === undefined) return state.toggles.testingDelays ? "Testing…" : t("Not tested");
  if (delay <= 0) return t("Probe failed");
  return `${delay} ms`;
}

function delayConcurrency() {
  if (typeof document !== "undefined" && document.hidden) return 2;
  const cores = Number(navigator.hardwareConcurrency) || 8;
  return Math.max(4, Math.min(16, cores));
}

function cancelDelayTest() {
  runtime.delayTestGeneration = (runtime.delayTestGeneration ?? 0) + 1;
  state.toggles.testingDelays = false;
  if (runtime.delayBatchInFlight) state.proxyDelayMessage = t("Stopping latency test after the current batch…");
}

function visibleProxyNodeNames() {
  const grid = document.querySelector("[data-proxy-node-grid]");
  if (!grid) return [];
  const viewport = grid.getBoundingClientRect();
  const visible = [];
  grid.querySelectorAll("[data-proxy-node]").forEach((el) => {
    const rect = el.getBoundingClientRect();
    if (rect.bottom >= viewport.top && rect.top <= viewport.bottom) {
      const name = el.getAttribute("data-proxy-node");
      if (name) visible.push(name);
    }
  });
  return visible;
}

function orderNamesVisibleFirst(names) {
  const visible = new Set(visibleProxyNodeNames());
  const head = [];
  const tail = [];
  for (const name of names) {
    if (visible.has(name)) head.push(name);
    else tail.push(name);
  }
  return head.length ? [...head, ...tail] : names;
}

function applyDelayToProxyNodes(name, delay, failure = null) {
  const value = typeof delay === "number" && Number.isFinite(delay) ? delay : null;
  state.proxyDelayResults.set(name, { delay: value, delayFailure: failure });
  for (const node of indexedNodes().get(name) ?? []) {
        node.delay = value;
        node.delayFailure = failure;
        node.dead = Boolean(failure) || (typeof value === "number" && value <= 0);
  }
}

function patchProxyDelayLabels(names) {
  const nameSet = names ? new Set(names) : null;
  document.querySelectorAll("[data-proxy-delay]").forEach((el) => {
    const name = el.getAttribute("data-proxy-delay");
    if (!name || (nameSet && !nameSet.has(name))) return;
    let delay = null;
    let failure = null;
    const node = indexedNodes().get(name)?.values().next().value;
    if (node) {
        delay = node.delay;
        failure = node.delayFailure;
    }
    el.className = delayClass(delay, failure);
    el.textContent = delayLabel(delay, failure);
  });
  const tool = document.querySelector('[data-action="delay-test"]');
  if (tool) {
    tool.classList.toggle("active", Boolean(state.toggles.testingDelays));
    tool.title = state.toggles.testingDelays ? "Cancel latency test" : t("Test latency");
    tool.disabled = Boolean(runtime.delayBatchInFlight && !state.toggles.testingDelays);
  }
}

function finalizeDelayTestNames(names) {
  names.forEach((name) => {
    const found = indexedNodes().get(name)?.values().next().value;
    if (found && (found.delay === null || found.delay === undefined) && !found.delayFailure) {
      applyDelayToProxyNodes(name, null, "invalid_response");
    }
  });
  patchProxyDelayLabels(names);
}

function slugDomId(value) {
  return String(value).replace(/[^a-z0-9_-]/gi, "-");
}

function proxyInitial(value) {
  return String(value).trim().slice(0, 2).toUpperCase() || "?";
}

function isManualProxyGroup(type) {
  return ["selector", "relay"].includes(String(type ?? "").toLowerCase());
}

function freshProxyControllerSnapshotAvailable() {
  return state.engine.active
    && state.mode !== null
    && ["controller live", "controller live stream"].includes(state.controllerStatus);
}

/** CFW Proxies section toolbar glyphs (Material-style: travel_explore / report / network_check / visibility). */
function proxyToolIcon(kind) {
  const common = 'width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"';
  switch (kind) {
    case "scroll":
      // travel_explore — globe + magnifier
      return `<svg ${common} fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/><circle cx="18.5" cy="18.5" r="3.2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M20.8 20.8L23 23" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;
    case "report":
      // report — octagon with !
      return `<svg ${common} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z"/></svg>`;
    case "report-off":
      return `<svg ${common} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z" opacity=".38"/></svg>`;
    case "delay":
      // network_check — signal arcs + needle
      return `<svg ${common} fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12a10 10 0 0 1 20 0"/><path d="M5 12a7 7 0 0 1 14 0"/><path d="M8.5 12a3.5 3.5 0 0 1 7 0"/><path d="M12 12V7.5" stroke-width="2"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg>`;
    case "eye":
      return `<svg ${common} fill="currentColor"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>`;
    case "eye-off":
      return `<svg ${common} fill="currentColor"><path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/></svg>`;
    default:
      return "";
  }
}

function displayedProxyGroups() {
  return freshProxyControllerSnapshotAvailable() ? state.proxyGroups : state.savedProfilePolicy?.groups ?? [];
}

function activeProxyGroup() {
  const groups = displayedProxyGroups();
  return groups.find((group) => group.name === state.activeProxyGroup)
    ?? groups.find((group) => isManualProxyGroup(group.type) && /选择|select|proxy|节点/i.test(group.name))
    ?? groups.find((group) => isManualProxyGroup(group.type) && group.name.toUpperCase() !== "GLOBAL")
    ?? groups.find((group) => isManualProxyGroup(group.type))
    ?? groups[0]
    ?? null;
}

function hideTimedOutProxies(group) {
  return state.proxyGroupHideTimeouts.get(group.name) ?? state.toggles.hideUnavailable;
}

function renderProxies() {
  const controllerLive = freshProxyControllerSnapshotAvailable();
  const groups = displayedProxyGroups();
  const activeGroup = activeProxyGroup();
  const filter = state.proxyFilter.trim().toLowerCase();
  const options = activeGroup?.options.length ? activeGroup.options : activeGroup?.observedOption ? [activeGroup.observedOption] : [];
  const visibleNodes = options.filter((node) => {
    const matchesFilter = !filter || activeGroup.name.toLowerCase().includes(filter) || (node.label ?? node.name).toLowerCase().includes(filter);
    return matchesFilter && !(hideTimedOutProxies(activeGroup) && node.delayFailure === "timeout");
  });
  const key = currentPageKey(activeGroup);
  if (key !== pageKey) { pageKey = key; pageNumber = 0; }
  const page = proxyPage(visibleNodes, pageNumber);
  pageNumber = page.page;
  const manual = Boolean(activeGroup && isManualProxyGroup(activeGroup.type) && (controllerLive || engineIsOff()) && !state.savedProxySelectionBusy);
  const hideTimedOut = activeGroup ? hideTimedOutProxies(activeGroup) : false;
  const showProxiesList = state.toggles.showProxiesList !== false;
  const blinkNode = state.proxyBlinkNode;
  const emptyMessage = controllerLive && state.proxyGroups.length === 0
    ? "Active profile has no proxy groups. Switch to a subscription with nodes."
    : state.savedProfilePolicyError ?? t("No saved nodes are available. Select or import a profile.");
  const modeUnavailableTitle = controllerLive
    ? "Switch proxy mode"
    : t("Start the engine and wait for a live controller snapshot to switch mode");
  const modeSwitch = `
      <div class="mode-switch proxy-mode-header" role="group" aria-label="${escapeHtml(t("Proxy mode"))}">
        ${["Global", "Rule", "Direct"].map((mode) => `
          <button class="${state.mode === mode ? "selected" : ""}" data-mode="${mode}" title="${modeUnavailableTitle}" ${controllerLive ? "" : "disabled"}>${escapeHtml(t(mode))} <span>${modeIcon(mode)}</span></button>
        `).join("")}
      </div>`;
  return `
    <div class="proxy-layout">
      ${modeSwitch}

      <div class="cfw-proxy-page">
        ${!controllerLive && state.savedProfilePolicy ? `<p class="muted">${escapeHtml(t("Saved configuration: {name}. Engine: {state}.", { name: state.savedProfilePolicy.name, state: engineStateLabel(state.engine) }))} ${engineIsOff() ? t("Selections apply on the next start.") : escapeHtml(state.engine.availabilityReason ?? t("Live status is unavailable."))}</p>` : ""}
        ${activeGroup ? `
          <div class="cfw-proxy-head">
            <div class="cfw-proxy-title">
              <h2>${escapeHtml(activeGroup.name)}</h2>
              <span class="proxy-type-badge">${escapeHtml(activeGroup.type?.slice(0, 1) ?? "S")}</span>
              <b>${escapeHtml(activeGroup.now ?? "")}</b>
            </div>
            <div class="cfw-proxy-tools">
              <input class="proxy-filter" data-proxy-filter placeholder="${escapeHtml(t("Filter"))}" value="${escapeHtml(state.proxyFilter)}" aria-label="${escapeHtml(t("Filter proxies"))}" />
              <button class="proxy-tool" data-action="scroll-to-selected-proxy" title="${escapeHtml(t("Scroll to selected proxy"))}">${proxyToolIcon("scroll")}</button>
              <button class="proxy-tool ${hideTimedOut ? "active" : ""}" data-action="toggle-hide-timed-out" title="${escapeHtml(t("Show/Hide timed-out proxies"))}">${proxyToolIcon(hideTimedOut ? "report-off" : "report")}</button>
              <button class="proxy-tool ${state.toggles.testingDelays ? "active" : ""}" data-action="delay-test" title="${state.toggles.testingDelays ? "Cancel latency test" : t("Test latency")}" ${runtime.delayBatchInFlight && !state.toggles.testingDelays ? "disabled" : ""}>${proxyToolIcon("delay")}</button>
              <button class="proxy-tool ${showProxiesList ? "active" : ""}" data-action="toggle-show-proxies" title="${escapeHtml(t("Show/hide proxies"))}">${proxyToolIcon(showProxiesList ? "eye" : "eye-off")}</button>
            </div>
          </div>
          ${state.proxyDelayMessage ? `<p role="status" class="muted">${escapeHtml(state.proxyDelayMessage)}</p>` : ""}
          <div class="cfw-proxy-content">
            ${showProxiesList ? `
            <div class="cfw-node-grid" data-proxy-node-grid>
              ${page.nodes.map((node) => `
                <button class="cfw-node-card ${activeGroup.now === node.name ? "selected" : ""} ${blinkNode === node.name ? "blink" : ""} ${manual ? "" : "readonly"}" data-proxy-node="${escapeHtml(node.name)}" ${manual ? `data-group="${escapeHtml(activeGroup.name)}" data-node="${escapeHtml(node.name)}"` : "disabled"} title="${manual ? "Select proxy" : t("This group type is chosen by the engine, not by the dashboard")}">
                  <i></i>
                  <span>
                    <strong>${nodePrefix(node.label ?? node.name)}${escapeHtml(node.label ?? node.name)}</strong>
                    <small>${escapeHtml(node.kind ?? "Proxy")} ${node.udp === false ? "" : "<em>UDP</em>"}</small>
                  </span>
                  <b class="${delayClass(node.delay, node.delayFailure)}" data-proxy-delay="${escapeHtml(node.name)}">${delayLabel(node.delay, node.delayFailure)}</b>
                </button>
              `).join("")}
              ${page.pages > 1 ? `<nav class="proxy-pagination" aria-label="${escapeHtml(t("Proxy pages"))}"><button data-proxy-page="-1"${page.page === 0 ? " disabled" : ""}>${escapeHtml(t("Previous"))}</button><span>${escapeHtml(t("Page {page} / {pages} · Nodes: {count}", { page: page.page + 1, pages: page.pages, count: page.total }))}</span><button data-proxy-page="1"${page.page + 1 === page.pages ? " disabled" : ""}>${escapeHtml(t("Next"))}</button></nav>` : ""}
            </div>
            ` : `<p class="empty proxy-list-hidden">${escapeHtml(t("Proxies hidden — click the eye to show this group’s nodes."))}</p>`}
            <aside class="cfw-group-rail">
              ${groups.map((group) => `
                <button class="${group.name === activeGroup.name ? "active" : ""}" data-proxy-group-tab="${escapeHtml(group.name)}" title="${escapeHtml(group.name)}">${escapeHtml(groupRailLabel(group.name))}</button>
              `).join("")}
            </aside>
          </div>
        ` : `<p class="empty">${escapeHtml(emptyMessage)}</p>`}
      </div>
    </div>
  `;
}

function modeIcon(mode) {
  return { Global: "↗", Rule: "↝", Direct: "→" }[mode] ?? "";
}

function nodePrefix(name) {
  const value = String(name ?? "");
  if (/[\u{1F1E6}-\u{1F1FF}]/u.test(value)) return "";
  if (/^(DIRECT|REJECT)$/i.test(value)) return "• ";
  return "";
}

function groupRailLabel(name) {
  const value = String(name ?? "").trim();
  if (!value) return "?";
  if (/^GLOBAL$/i.test(value)) return "GLOBAL";
  const withoutFlags = value
    .replace(/[\u{1F1E6}-\u{1F1FF}]/gu, "")
    .replace(/[|｜丨&＆/\\()[\]{}【】「」『』·•._\-:：;；,，。!！?？"'“”‘’]+/g, "")
    .replace(/\s+/g, "");
  const cjk = [...withoutFlags].filter((char) => /[\u4e00-\u9fffA-Za-z0-9]/.test(char)).join("");
  return (cjk || withoutFlags || value).slice(0, 6);
}


return { delayClass, delayLabel, delayConcurrency, cancelDelayTest, visibleProxyNodeNames, orderNamesVisibleFirst, applyDelayToProxyNodes, patchProxyDelayLabels, finalizeDelayTestNames, slugDomId, isManualProxyGroup, freshProxyControllerSnapshotAvailable, displayedProxyGroups, activeProxyGroup, hideTimedOutProxies, renderProxies, modeIcon, changePage, revealSelected };
}
