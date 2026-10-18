import assert from "node:assert/strict";
import test from "node:test";
import { createConnectionsView } from "../src/connections.js";
import { escapeHtml, formatBytes, safeRegex } from "../src/format.js";
import { getLocale, setLocale, t, SUPPORTED_LOCALES } from "../src/i18n.js";

test("connection sort buttons expose localized purpose, selection and current direction", () => {
  const previousLocale = getLocale();
  const state = {
    connections: [], connectionSearch: "", connectionSort: "age", connectionSortDesc: false,
    connectionStream: {}, toggles: {}, closingConnectionIds: new Set(),
  };
  const view = createConnectionsView({ state, runtime: {}, MAX_CONNECTION_ROWS: 500, safeRegex, escapeHtml, formatBytes });
  const purposes = {
    upload: "Sort connections by uploaded data", download: "Sort connections by downloaded data",
    age: "Sort connections by start time", host: "Sort connections by host",
  };
  try {
    for (const locale of SUPPORTED_LOCALES) {
      setLocale(locale);
      for (const selected of Object.keys(purposes)) {
        for (const descending of [false, true]) {
          state.connectionSort = selected;
          state.connectionSortDesc = descending;
          const buttons = [...view.renderConnections().matchAll(/<button\b([^>]*data-connection-sort="([^"]+)"[^>]*)>([^<]*)<\/button>/gu)];
          assert.equal(buttons.length, 6);
          assert.deepEqual(buttons.map((match) => match[3]), ["↥ ◒", "↧ ◒", "↥ ▥", "↧ ▥", "◷", "▭"]);
          for (const [, attributes, sort] of buttons) {
            assert.ok(attributes.includes(`aria-label="${escapeHtml(t(purposes[sort]))}"`), `${locale}/${sort}: accessible purpose`);
            assert.ok(attributes.includes(`aria-pressed="${sort === selected}"`), `${locale}/${sort}: selected state`);
            const description = attributes.match(/aria-description="([^"]+)"/u)?.[1];
            assert.equal(description, sort === selected ? escapeHtml(t(descending ? "Descending order" : "Ascending order")) : undefined);
          }
        }
      }
      state.connectionSearch = "test";
      const clear = view.renderConnections().match(/<button\b([^>]*data-action="clear-connection-search"[^>]*)>×<\/button>/u);
      assert.ok(clear?.[1].includes(`aria-label="${escapeHtml(t("Clear connection search"))}"`));
      state.connectionSearch = "";
      assert.ok(!view.renderConnections().includes('data-action="clear-connection-search"'));
    }
  } finally { setLocale(previousLocale); }
});
