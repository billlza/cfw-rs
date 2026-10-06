/// The sidebar's page glyphs: one filled 24-unit icon per page, drawn in the
/// current colour so the stylesheet decides the tint. The paths are the
/// product's own; they carry no text and need no localization.
const PATHS = Object.freeze({
  general: "M12 3.2 2.8 11h2.5v8.2h5.2v-5.4h3v5.4h5.2V11h2.5L12 3.2z",
  proxies: "M12 2.5a9.5 9.5 0 1 0 0 19 9.5 9.5 0 0 0 0-19zm6.9 8.6h-3a15 15 0 0 0-1.2-5.2 7.6 7.6 0 0 1 4.2 5.2zM12 4.4c.9 1.1 1.7 3 2 6.7H10c.3-3.7 1.1-5.6 2-6.7zM5.1 11.1a7.6 7.6 0 0 1 4.2-5.2 15 15 0 0 0-1.2 5.2h-3zm0 1.8h3a15 15 0 0 0 1.2 5.2 7.6 7.6 0 0 1-4.2-5.2zM12 19.6c-.9-1.1-1.7-3-2-6.7h4c-.3 3.7-1.1 5.6-2 6.7zm2.7-1.5a15 15 0 0 0 1.2-5.2h3a7.6 7.6 0 0 1-4.2 5.2z",
  profiles: "M6.5 2.5h7.2L19 7.8v11.7a2 2 0 0 1-2 2H6.5a2 2 0 0 1-2-2v-15a2 2 0 0 1 2-2zm6.7 1.8v4.2h4.1l-4.1-4.2zM7.6 12.2v1.7h8.8v-1.7H7.6zm0 3.6v1.7h8.8v-1.7H7.6z",
  providers: "M8.5 11a3.3 3.3 0 1 0 0-6.6 3.3 3.3 0 0 0 0 6.6zm7 0a2.8 2.8 0 1 0 0-5.6 2.8 2.8 0 0 0 0 5.6zM2.5 18.4c0-3.1 2.7-5.4 6-5.4s6 2.3 6 5.4v1.1h-12v-1.1zm13.1 1.1v-1.3c0-1.6-.6-3-1.6-4.1 1.1-.5 2.2-.7 3.1-.7 2.4 0 4.4 1.7 4.4 4.1v2h-5.9z",
  logs: "M5 3.5h14a1.5 1.5 0 0 1 1.5 1.5v14A1.5 1.5 0 0 1 19 20.5H5A1.5 1.5 0 0 1 3.5 19V5A1.5 1.5 0 0 1 5 3.5zm2 4.2v1.8h10V7.7H7zm0 3.6v1.8h10v-1.8H7zm0 3.6v1.8h6.5v-1.8H7z",
  connections: "M10.2 13.8a1.3 1.3 0 0 1 0-1.8l3.6-3.6a3.6 3.6 0 0 1 5.1 5.1l-1.9 1.9a1.3 1.3 0 1 1-1.8-1.8l1.9-1.9a1 1 0 0 0-1.5-1.5L12 13.8a1.3 1.3 0 0 1-1.8 0zm3.6-3.6a1.3 1.3 0 0 1 0 1.8l-3.6 3.6a3.6 3.6 0 0 1-5.1-5.1L7 8.6a1.3 1.3 0 1 1 1.8 1.8l-1.9 1.9a1 1 0 0 0 1.5 1.5L12 10.2a1.3 1.3 0 0 1 1.8 0z",
  rules: "M12 2.3 4.5 5.1v5.6c0 4.9 3.2 9.4 7.5 10.7 4.3-1.3 7.5-5.8 7.5-10.7V5.1L12 2.3zm-1.2 13.1-3-3 1.3-1.3 1.7 1.7 4.2-4.2 1.3 1.3-5.5 5.5z",
  settings: "M19.4 13a7.6 7.6 0 0 0 0-2l2-1.6-1.9-3.3-2.4 1a7.5 7.5 0 0 0-1.7-1L15 3.5H9l-.4 2.6a7.5 7.5 0 0 0-1.7 1l-2.4-1-1.9 3.3 2 1.6a7.6 7.6 0 0 0 0 2l-2 1.6 1.9 3.3 2.4-1a7.5 7.5 0 0 0 1.7 1l.4 2.6h6l.4-2.6a7.5 7.5 0 0 0 1.7-1l2.4 1 1.9-3.3-2-1.6zM12 15.2a3.2 3.2 0 1 1 0-6.4 3.2 3.2 0 0 1 0 6.4z",
  feedback: "M12 2.5a9.5 9.5 0 1 0 0 19 9.5 9.5 0 0 0 0-19zm1 14.5h-2v-6h2v6zm0-7.6h-2V7.3h2v2.1z",
});

/// The glyph for a page, as inline SVG markup; an unknown page has none.
export function navIcon(pageId) {
  const path = PATHS[pageId];
  if (!path) return "";
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${path}"/></svg>`;
}

export const NAV_ICON_PAGES = Object.freeze(Object.keys(PATHS));
