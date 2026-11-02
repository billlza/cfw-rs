// The Logs page: filtering, the toolbar and the live log stream patch.
import { state, runtime, MAX_LOG_ROWS } from "./state.js";
import { escapeHtml, safeRegex } from "./text-format.js";
import { normalizeLevel } from "./app-log.js";
import { t } from "./i18n.js";

export function createLogsView({ scheduleRender }) {
  function visibleLogs() {
    const regex = safeRegex(state.logSearch);
    return state.logs.filter((line) => {
      const level = normalizeLevel(line.level);
      const matchesLevel = state.logFilter === "all" || level === state.logFilter;
      const haystack = [line.time, level, line.source, line.message, ...(line.fields ?? []).map((field) => `${field.key}=${field.value}`)].join(" ");
      const matchesSearch = !state.logSearch || (regex ? regex.test(haystack) : haystack.toLowerCase().includes(state.logSearch.toLowerCase()));
      return matchesLevel && matchesSearch;
    }).slice(0, MAX_LOG_ROWS);
  }

  function renderLogStreamHtml() {
    const logs = visibleLogs();
    return logs.map((line) => `
          <article class="log-line ${escapeHtml(line.level)}">
            <time>${escapeHtml(line.time)}</time>
            <b>${escapeHtml(line.level)}</b>
            <span>${escapeHtml(line.source)}</span>
            <p>
              ${escapeHtml(line.message)}
              ${(line.fields ?? []).length ? `<small>${line.fields.map((field) => `${escapeHtml(field.key)}=${escapeHtml(field.value)}`).join(" · ")}</small>` : ""}
            </p>
          </article>
        `).join("") || `<p class="empty">${escapeHtml(t("No logs for this filter."))}</p>`;
  }

  function logCountLabel(visibleCount) {
    return t("Log entries: {visible} / {total}", { visible: visibleCount, total: state.logs.length })
      + (state.logsPaused ? ` · ${t("Paused")}` : "");
  }

  function patchLogStream() {
    const stream = document.querySelector(".log-stream");
    if (!stream) return false;
    const heading = document.querySelector(".logs-layout .toolbar-panel h3");
    if (heading) {
      heading.textContent = logCountLabel(visibleLogs().length);
    }
    stream.innerHTML = renderLogStreamHtml();
    return true;
  }

  function scheduleLogStreamPatch() {
    if (runtime.logStreamFrame !== null) return;
    runtime.logStreamFrame = window.requestAnimationFrame(() => {
      runtime.logStreamFrame = null;
      if (state.activePage !== "logs") return;
      if (!patchLogStream()) scheduleRender();
    });
  }

  function renderLogs() {
    const logs = visibleLogs();
    return `
    <div class="logs-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">${escapeHtml(t("Diagnostics"))}</p>
          <h3>${logCountLabel(logs.length)}</h3>
        </div>
        <div class="search-box">
          <input value="${escapeHtml(state.logSearch)}" data-log-search aria-label="${escapeHtml(t("Search logs"))}" placeholder="${escapeHtml(t("Search logs or regex"))}" />
        </div>
        <div class="segmented" data-log-filters>
          ${["all", "info", "debug", "warning", "error"].map((level) => `
            <button type="button" class="${state.logFilter === level ? "selected" : ""}" data-log-filter="${level}" aria-pressed="${state.logFilter === level}">${level.toUpperCase()}</button>
          `).join("")}
        </div>
        <div class="toolbar-actions">
          <button type="button" class="button ghost" data-action="toggle-log-stream">${state.logsPaused ? t("Start") : t("Stop")}</button>
          <button type="button" class="button ghost" data-action="copy-logs">${escapeHtml(t("Copy"))}</button>
          <button type="button" class="button ghost" data-action="reveal-logs">${escapeHtml(t("Open Folder"))}</button>
          <button type="button" class="button ghost" data-action="clear-logs">${escapeHtml(t("Clear"))}</button>
        </div>
      </section>

      <section class="panel log-stream">
        ${renderLogStreamHtml()}
      </section>
    </div>
  `;
  }

  return { renderLogs, patchLogStream, scheduleLogStreamPatch };
}
