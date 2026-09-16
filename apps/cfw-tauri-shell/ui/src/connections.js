// Connection presentation owns incremental row reconciliation and row events.
// Engine identity and close commands remain in the shared controller pipeline.
export function createConnectionsView({
  state, runtime, MAX_CONNECTION_ROWS, safeRegex, escapeHtml, formatBytes, renderPage, bindPageEvents,
  controllerActionAllowed, captureEngineIdentityToken, engineIdentityTokenIsCurrent, invoke, loadControllerSnapshot, appendLog, errorText,
}) {
function visibleConnections() {
  const regex = safeRegex(state.connectionSearch);
  const rows = state.connections.filter((connection) => {
    const metadata = connection.metadata ?? {};
    const haystack = [
      connection.host,
      connection.rule,
      ...(connection.chains ?? []),
      metadata.processPath,
      metadata.process_path,
      metadata.sourceIP,
      metadata.source_ip,
      metadata.destinationIP,
      metadata.destination_ip,
      metadata.network,
      metadata.type,
    ].filter(Boolean).join(" ");
    return !state.connectionSearch || (regex ? regex.test(haystack) : haystack.toLowerCase().includes(state.connectionSearch.toLowerCase()));
  });

  const sorters = {
    host: (row) => row.host,
    speed: (row) => row.uploadSpeedBytes + row.downloadSpeedBytes,
    upload: (row) => row.uploadBytes,
    download: (row) => row.downloadBytes,
    age: (row) => Date.parse(row.start || "") || 0,
  };
  const sorter = sorters[state.connectionSort] ?? sorters.age;
  return [...rows].sort((left, right) => {
    const leftValue = sorter(left);
    const rightValue = sorter(right);
    const result = typeof leftValue === "string"
      ? leftValue.localeCompare(String(rightValue))
      : leftValue - rightValue;
    return state.connectionSortDesc ? -result : result;
  }).slice(0, MAX_CONNECTION_ROWS);
}

function connectionProcessLabel(connection) {
  const path = connection.metadata?.processPath
    ?? connection.metadata?.process_path
    ?? connection.processPath
    ?? "";
  if (!path) return "—";
  const parts = String(path).split(/[/\\]/).filter(Boolean);
  return parts[parts.length - 1] || String(path);
}

function connectionRowHtml(connection, showProcess) {
  return `
    <article class="cfw-conn-item${showProcess ? " with-process" : ""}" data-connection-id="${escapeHtml(connection.id)}">
      <div class="conn-main">
        <h3>${escapeHtml(connection.host)}</h3>
        <div class="conn-chips">
          <span class="conn1">${escapeHtml(connection.rule || "MATCH")}</span>
          ${(connection.chains ?? []).slice(0, 4).map((chain, index) => `<span class="conn${(index % 6) + 2}">${escapeHtml(chain)}</span>`).join("")}
          <span class="conn7">${escapeHtml(connection.metadata?.network ?? connection.metadata?.type ?? "tcp")}</span>
        </div>
      </div>
      ${showProcess ? `<div class="conn-process" title="${escapeHtml(connection.metadata?.processPath ?? connection.metadata?.process_path ?? "")}">${escapeHtml(connectionProcessLabel(connection))}</div>` : ""}
      <div class="conn-traffic">
        <b data-conn-up>↑ ${escapeHtml(connection.upload)}</b>
        <b data-conn-down>↓ ${escapeHtml(connection.download)}</b>
        <small data-conn-speed>${escapeHtml(connection.speed ?? "0 B/s")}</small>
      </div>
      <div class="conn-actions">
        <button data-connection-detail="${escapeHtml(connection.id)}">Info</button>
        <button data-close-connection="${escapeHtml(connection.id)}" ${state.closingConnectionIds.has(connection.id) ? "disabled" : ""}>${state.closingConnectionIds.has(connection.id) ? "Closing" : "Close"}</button>
      </div>
    </article>
  `;
}

function renderConnections() {
  const connections = visibleConnections();
  const detail = state.connections.find((connection) => connection.id === state.connectionDetailId);
  const totalUp = formatBytes(state.connectionStream.uploadTotal);
  const totalDown = formatBytes(state.connectionStream.downloadTotal);
  const showProcess = state.toggles.showProcess !== false;
  runtime.connectionRowEls = null;
  return `
    <div class="connections-layout" data-connections-root>
      <section class="cfw-conn-header">
        <h1>Connections</h1>
        <div class="cfw-conn-search">
          <span>●</span>
          <input value="${escapeHtml(state.connectionSearch)}" data-connection-search aria-label="Search connections" placeholder="Search connections" />
          ${state.connectionSearch ? '<button data-action="clear-connection-search">×</button>' : ""}
        </div>
        <strong data-conn-totals>Total: ↑ ${totalUp} ↓ ${totalDown}</strong>
      </section>

      <section class="cfw-conn-controls">
        ${[
          ["upload", "↥ ◒"],
          ["download", "↧ ◒"],
          ["upload", "↥ ▥"],
          ["download", "↧ ▥"],
          ["age", "◷"],
          ["host", "▭"],
        ].map(([sort, label]) => `
          <button class="${state.connectionSort === sort ? "selected" : ""}" data-connection-sort="${sort}">${label}</button>
        `).join("")}
        <span></span>
        <button class="danger" data-action="toggle-connection-stream">${state.connectionPaused ? "Resume" : "Pause"}</button>
        <button class="danger" data-action="close-all" data-conn-close-all ${state.closingAllConnections ? "disabled" : ""}>${state.closingAllConnections ? "Closing..." : `Close All (${connections.length})`}</button>
      </section>

      <section class="cfw-conn-scroll" data-conn-scroll>
        ${connections.map((connection) => connectionRowHtml(connection, showProcess)).join("")}
      </section>
      ${detail ? renderConnectionDetail(detail) : ""}
    </div>
  `;
}

function patchConnectionsDom() {
  const root = document.querySelector("[data-connections-root]");
  const scroll = document.querySelector("[data-conn-scroll]");
  if (!root || !scroll || state.activePage !== "connections") {
    renderPage();
    return;
  }

  const connections = visibleConnections();
  const showProcess = state.toggles.showProcess !== false;
  const totals = root.querySelector("[data-conn-totals]");
  if (totals) {
    totals.textContent = `Total: ↑ ${formatBytes(state.connectionStream.uploadTotal)} ↓ ${formatBytes(state.connectionStream.downloadTotal)}`;
  }
  const closeAll = root.querySelector("[data-conn-close-all]");
  if (closeAll) {
    closeAll.disabled = Boolean(state.closingAllConnections);
    closeAll.textContent = state.closingAllConnections
      ? "Closing..."
      : `Close All (${connections.length})`;
  }

  if (!(runtime.connectionRowEls instanceof Map)) {
    runtime.connectionRowEls = new Map();
    scroll.querySelectorAll("[data-connection-id]").forEach((el) => {
      runtime.connectionRowEls.set(el.getAttribute("data-connection-id"), el);
    });
  }

  const nextIds = new Set(connections.map((connection) => connection.id));
  for (const [id, el] of [...runtime.connectionRowEls.entries()]) {
    if (!nextIds.has(id)) {
      el.remove();
      runtime.connectionRowEls.delete(id);
    }
  }

  connections.forEach((connection, index) => {
    let el = runtime.connectionRowEls.get(connection.id);
    if (!el) {
      const wrap = document.createElement("div");
      wrap.innerHTML = connectionRowHtml(connection, showProcess).trim();
      el = wrap.firstElementChild;
      runtime.connectionRowEls.set(connection.id, el);
      bindConnectionRowEvents(el);
    }
    const up = el.querySelector("[data-conn-up]");
    const down = el.querySelector("[data-conn-down]");
    const speed = el.querySelector("[data-conn-speed]");
    if (up) up.textContent = `↑ ${connection.upload}`;
    if (down) down.textContent = `↓ ${connection.download}`;
    if (speed) speed.textContent = connection.speed ?? "0 B/s";
    const closeBtn = el.querySelector("[data-close-connection]");
    if (closeBtn) {
      const closing = state.closingConnectionIds.has(connection.id);
      closeBtn.disabled = closing;
      closeBtn.textContent = closing ? "Closing" : "Close";
    }
    const expected = scroll.children[index];
    if (expected !== el) {
      scroll.insertBefore(el, expected ?? null);
    }
  });

  const detail = state.connections.find((connection) => connection.id === state.connectionDetailId);
  const existingDetail = root.querySelector(".modal-backdrop");
  if (detail && !existingDetail) {
    root.insertAdjacentHTML("beforeend", renderConnectionDetail(detail));
    bindPageEvents();
  } else if (!detail && existingDetail) {
    existingDetail.remove();
  }
}

function scheduleConnectionsPatch() {
  if (runtime.connectionsPatchFrame !== null) return;
  runtime.connectionsPatchFrame = window.requestAnimationFrame(() => {
    runtime.connectionsPatchFrame = null;
    patchConnectionsDom();
  });
}

function connectionFacets(connections) {
  const topEntries = (items) => [...items.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 6);
  const rules = new Map();
  const chains = new Map();
  connections.forEach((connection) => {
    if (connection.rule) rules.set(connection.rule, (rules.get(connection.rule) ?? 0) + 1);
    (connection.chains ?? []).forEach((chain) => {
      chains.set(chain, (chains.get(chain) ?? 0) + 1);
    });
  });
  return {
    rules: topEntries(rules),
    chains: topEntries(chains),
  };
}

function renderConnectionDetail(connection) {
  const metadata = connection.metadata ?? {};
  const rows = [
    ["Host", connection.host],
    ["Rule", connection.rule],
    ["Chains", (connection.chains ?? []).join(" / ")],
    ["Upload", connection.upload],
    ["Download", connection.download],
    ["Speed", connection.speed],
    ...Object.entries(metadata).filter(([, value]) => value !== null && value !== undefined && value !== ""),
  ];
  return `
    <div class="modal-backdrop" data-action="close-connection-detail">
      <section class="connection-info-modal" data-modal-stop>
        <div class="modal-head">
          <h2>Connection Info</h2>
          <button data-action="close-connection-detail">×</button>
        </div>
        <dl>
          ${rows.map(([key, value]) => `
            <div>
              <dt>${escapeHtml(key)}</dt>
              <dd>${escapeHtml(String(value ?? ""))}</dd>
              <button data-copy-text="${escapeHtml(String(value ?? ""))}">Copy</button>
            </div>
          `).join("")}
        </dl>
      </section>
    </div>
  `;
}

function bindConnectionRowEvents(scope) {
  scope.querySelectorAll("[data-connection-detail]").forEach((button) => {
    button.addEventListener("click", (event) => {
      state.connectionDetailId = event.currentTarget.dataset.connectionDetail;
      renderPage();
    });
  });

  scope.querySelectorAll("[data-close-connection]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const id = event.currentTarget.dataset.closeConnection;
      if (!controllerActionAllowed(`Closing connection ${id}`, "connection")) return;
      const token = captureEngineIdentityToken();
      state.closingConnectionIds.add(id);
      renderPage();
      try {
        await invoke("close_connection", { id });
        if (!engineIdentityTokenIsCurrent(token)) return;
        await loadControllerSnapshot(true, token);
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("info", "connection", `Connection ${id} closed`);
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        state.controllerStatus = "controller offline";
        appendLog("error", "connection", `Controller close failed for ${id}: ${errorText(error)}`);
      } finally {
        if (engineIdentityTokenIsCurrent(token)) state.closingConnectionIds.delete(id);
      }
      renderPage();
    });
  });
}

return { renderConnections, scheduleConnectionsPatch, connectionFacets, bindConnectionRowEvents };
}
