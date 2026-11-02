// Markup for the small controls the pages share: switches, row notes and icons.
import { state } from "./state.js";
import { escapeHtml } from "./text-format.js";

/// A switch row. `options.reason` marks the switch unavailable and states why,
/// both in the row and in the control's own tooltip.
export function renderToggle(key, label, hint, options = {}) {
  const reason = options.reason ?? null;
  const allowDisableWhenUnavailable = options.allowDisableWhenUnavailable === true;
  const checkedState = Boolean(state.toggles[key]);
  const disabled = options.disabled || (reason && !(allowDisableWhenUnavailable && checkedState));
  const checked = (!reason || allowDisableWhenUnavailable) && checkedState ? "checked" : "";
  return `
    <label class="toggle-row ${disabled ? "disabled" : ""}">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(reason ?? hint)}</small>
      </span>
      <input type="checkbox" data-toggle="${escapeHtml(key)}" ${checked} ${disabled ? "disabled" : ""} ${reason ? `title="${escapeHtml(reason)}"` : ""} />
      <i></i>
    </label>
  `;
}

export function renderInlineSwitch(key, label, options = {}) {
  const reason = options.reason ?? null;
  const allowDisableWhenUnavailable = options.allowDisableWhenUnavailable === true;
  const checkedState = Boolean(state.toggles[key]);
  const disabled = options.disabled || (reason && !(allowDisableWhenUnavailable && checkedState));
  const checked = (!reason || allowDisableWhenUnavailable) && checkedState ? "checked" : "";
  const title = reason ?? options.title ?? null;
  return `
    <label class="inline-switch ${disabled ? "disabled" : ""}" ${title ? `title="${escapeHtml(title)}"` : ""}>
      <span class="visually-hidden">${escapeHtml(label)}${title ? ` — ${escapeHtml(title)}` : ""}</span>
      <input type="checkbox" data-toggle="${escapeHtml(key)}" ${checked} ${disabled ? "disabled" : ""} />
      <i></i>
    </label>
  `;
}

/// Explanation line under a General row whose control the backend refuses.
export function renderRowReason(reason) {
  return `
    <div class="cfw-row cfw-row-reason">
      <div class="cfw-row-left"><small>${escapeHtml(reason)}</small></div>
      <div class="cfw-row-right"></div>
    </div>
  `;
}

export function renderCatLogo() {
  return `
    <svg class="cfw-cat-logo" viewBox="0 0 112 96" aria-hidden="true">
      <path d="M23 86c-12 0-19-8-19-17 0-9 7-15 16-15 4 0 7 1 10 3l4-43 17 16 12-1 18-17 6 72c-17 2-40 2-64 2Z" />
      <path class="cat-tail" d="M22 70c-14 4-24-4-20-15 2-6 8-9 13-7" />
      <circle cx="43" cy="45" r="4" />
      <circle cx="71" cy="45" r="4" />
      <path class="cat-mouth" d="M54 58c3 3 6 3 9 0" />
    </svg>
  `;
}

function generalIcon(kind) {
  const common = 'width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"';
  switch (kind) {
    case "terminal":
      return `<svg ${common}><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm1 3v2l3 2-3 2v2l5-3.5L5 7zm7 8h6v2h-6v-2z"/></svg>`;
    case "info":
      return `<svg ${common}><path d="M12 2a10 10 0 1 0 .001 20.001A10 10 0 0 0 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>`;
    case "device-hub":
      return `<svg ${common}><path d="M17 16h-2v-2h2v2zm-4 0h-2v-2h2v2zm-4 0H7v-2h2v2zm10-6h-2V8h2v2zm-4 0h-2V8h2v2zm-4 0H7V8h2v2zm10-6H5c-1.1 0-2 .9-2 2v14h18V6c0-1.1-.9-2-2-2zm0 14H5V6h14v10z"/></svg>`;
    case "memory":
      return `<svg ${common}><path d="M15 9H9v6h6V9zm-2 4h-2v-2h2v2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2zm-4 6H7V7h10v10z"/></svg>`;
    case "dns":
      return `<svg ${common}><path d="M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>`;
    case "history":
      return `<svg ${common}><path d="M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6a7 7 0 0 1 7-7 7 7 0 0 1 7 7 7 7 0 0 1-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.95 8.95 0 0 0 13 21a9 9 0 0 0 0-18zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>`;
    default:
      throw new TypeError(`unknown General icon: ${kind}`);
  }
}

export function generalIconButton(action, kind, title, options = {}) {
  const tone = options.tone ? ` ${options.tone}` : "";
  const active = options.active ? " active" : "";
  return `<button type="button" class="general-icon${tone}${active}" data-action="${escapeHtml(action)}" title="${escapeHtml(title)}">${generalIcon(kind)}</button>`;
}

/// A short note plus the backend's full reason, shown next to a control the
/// product cannot honour.
export function renderRowNote(short, reason) {
  return `<small class="cfw-row-note" title="${escapeHtml(reason)}">${escapeHtml(short)}</small>`;
}

export function profileMenuIcon(kind) {
  const icons = {
    check: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9.2 16.6 4.8 12.2l1.4-1.4 3 3 8.6-8.6 1.4 1.4-10 10z"/></svg>`,
    edit: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4.5 16.9 15.8 5.6l2.6 2.6L7.1 19.5H4.5v-2.6zm14.3-11.7 1.5 1.5c.4.4.4 1 0 1.4l-1.2 1.2-2.6-2.6 1.2-1.2c.4-.4 1-.4 1.4 0z"/></svg>`,
    refresh: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 5a7 7 0 0 1 6.3 4H16v2h5.5V5.5H19v1.7A9 9 0 1 0 21 12h-2a7 7 0 1 1-7-7z"/></svg>`,
    folder: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.5 6.5A2 2 0 0 1 5.5 4.5h4l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-11z"/></svg>`,
    send: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.2 11.2 20 3.5 12.3 20.8l-1.7-6.4-7.4-3.2zm4.4 2.3 4.2 1.8 3.3-7.4-7.5 5.6z"/></svg>`,
    rules: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M5 5h14v2H5V5zm0 6h14v2H5v-2zm0 6h10v2H5v-2z"/></svg>`,
    copy: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M8 7h10v12H8V7zm-3 3H4V4h11v2H5v4zm3-1h2v10h8v2H8V9z"/></svg>`,
    qr: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4 4h7v7H4V4zm2 2v3h3V6H6zm7-2h7v7h-7V4zm2 2v3h3V6h-3zM4 13h7v7H4v-7zm2 2v3h3v-3H6zm9 0h2v2h-2v-2zm4 0h2v2h-2v-2zm-4 4h2v2h-2v-2zm2 2h4v2h-4v-2zm2-4h2v4h-2v-4z"/></svg>`,
    gear: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M11 3h2l.4 2.2a6.8 6.8 0 0 1 1.8.8l2-1.1 1.4 1.4-1.1 2a6.8 6.8 0 0 1 .8 1.8L20.5 11v2l-2.2.4a6.8 6.8 0 0 1-.8 1.8l1.1 2-1.4 1.4-2-1.1a6.8 6.8 0 0 1-1.8.8L13 20.5h-2l-.4-2.2a6.8 6.8 0 0 1-1.8-.8l-2 1.1-1.4-1.4 1.1-2a6.8 6.8 0 0 1-.8-1.8L3.5 13v-2l2.2-.4a6.8 6.8 0 0 1 .8-1.8l-1.1-2 1.4-1.4 2 1.1a6.8 6.8 0 0 1 1.8-.8L11 3zm1 6.5A2.5 2.5 0 1 0 12 14a2.5 2.5 0 0 0 0-5z"/></svg>`,
    trash: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9 4h6l1 2h4v2H4V6h4l1-2zm1 5h2v9h-2V9zm4 0h2v9h-2V9zM7 9h2v9H7V9z"/></svg>`,
  };
  if (!Object.hasOwn(icons, kind)) throw new TypeError(`unknown profile menu icon: ${kind}`);
  return icons[kind];
}
