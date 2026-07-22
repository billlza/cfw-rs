import { button, heading, node } from "../dom.js";
import { formatTimestamp } from "../format.js";

export function renderLogsPage(state) {
  const rows = state.logs.map((entry) => node("div", { className: `log-row ${entry.level}` }, [
    node("time", { text: formatTimestamp(entry.at) }),
    node("span", { className: "log-source", text: entry.source }),
    node("span", { className: "log-message", text: entry.message }),
  ]));
  return node("div", { className: "logs-layout" }, [
    node("section", { className: "panel toolbar-panel" }, [
      heading("Events", "Bounded diagnostics", "Only the latest 300 validated application and engine events are retained in memory."),
      button("Clear", "clear-logs", { className: "button ghost", disabled: state.logs.length === 0 }),
    ]),
    node("section", { className: "panel log-list", attributes: { "aria-live": "polite" } }, rows.length
      ? rows
      : [node("p", { className: "empty", text: "No events recorded in this session." })]),
  ]);
}
