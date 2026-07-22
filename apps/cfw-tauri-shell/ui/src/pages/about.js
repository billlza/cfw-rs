import { button, heading, node, settingRow, statusPill } from "../dom.js";

export function renderAboutPage(state) {
  const product = state.product ?? {};
  const update = state.updateInfo;
  const updateStatus = update?.available
    ? `Version ${update.version ?? "unknown"} is available`
    : update
      ? "Up to date"
      : "Not checked";
  return node("div", { className: "about-layout" }, [
    node("section", { className: "panel hero-panel" }, [
      heading("About", product.name ?? "Clash for Mac", "macOS 15+ · Apple Silicon · GPL-3.0-or-later"),
      statusPill(product.version ? `v${product.version}` : "Version unavailable"),
    ]),
    node("section", { className: "panel settings-group" }, [
      heading("Updates", "Signed update channel", "Installation remains blocked unless the native updater verifies the release signature."),
      node("div", { className: "settings-list" }, [
        settingRow("Status", "Latest updater result", node("strong", { text: updateStatus })),
      ]),
      node("div", { className: "toolbar-actions" }, [
        button("Check for Updates", "check-updates", { disabled: Boolean(state.busyAction) }),
        state.busyAction === "install-update"
          ? button("Cancel Download", "cancel-update", { className: "button ghost" })
          : update?.available
            ? button("Install Verified Update", "install-update", { disabled: Boolean(state.busyAction) })
            : null,
        button("Quit", "quit-app", { className: "button ghost", disabled: Boolean(state.busyAction) }),
      ].filter(Boolean)),
    ]),
  ]);
}
