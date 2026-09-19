// This entry point must load before, and independently of, the dashboard bundle.
// A module evaluation failure cannot be caught by bootstrap().catch().
(() => {
  const deadlineMs = 15000;
  let finished = false;
  let failed = false;
  let failureCode = null;
  let diagnosticsUnavailable = false;
  let timer;

  function invoke(command, args) {
    const bridge = window.__TAURI_INTERNALS__;
    if (!bridge || typeof bridge.invoke !== "function") {
      return Promise.reject(new Error("Native dashboard bridge is unavailable"));
    }
    return bridge.invoke(command, args);
  }

  function report(code) {
    // Only a closed event code crosses this boundary: no JS error text, URLs,
    // credentials, profile content or DOM snapshots are written to diagnostics.
    return invoke("report_dashboard_startup", { code }).catch(() => {
      diagnosticsUnavailable = true;
      const note = document.getElementById("startup-diagnostic-status");
      if (note) note.textContent = "The diagnostic event could not be saved. Use the application menu to open available logs.";
    });
  }

  function showFailure() {
    if (document.getElementById("startup-recovery")) return;
    const panel = document.createElement("section");
    panel.id = "startup-recovery";
    panel.className = "startup-recovery";
    panel.setAttribute("role", "alert");
    const heading = document.createElement("h1");
    heading.textContent = "The dashboard could not finish starting";
    const detail = document.createElement("p");
    detail.textContent = "Reload the dashboard to retry. This does not restart the running network core.";
    const code = document.createElement("p");
    code.textContent = `Diagnostic code: ${failureCode}`;
    const status = document.createElement("p");
    status.id = "startup-diagnostic-status";
    status.textContent = diagnosticsUnavailable
      ? "The diagnostic event could not be saved. Use the application menu to open available logs."
      : "Diagnostic events are kept locally. You can also open them from the application menu.";
    const reload = document.createElement("button");
    reload.type = "button";
    reload.textContent = "Reload dashboard";
    reload.addEventListener("click", () => {
      // The native command owns migration-session admission as well as the
      // window. A failed command must never fall back to an unchecked reload.
      invoke("reload_dashboard").catch(() => {
        status.textContent = "The dashboard could not be reloaded. Reload is unavailable during migration recovery. Open diagnostic logs for details.";
      });
    });
    const logs = document.createElement("button");
    logs.type = "button";
    logs.textContent = "Open diagnostic logs";
    logs.addEventListener("click", () => {
      invoke("reveal_logs_directory").catch(() => {
        status.textContent = "Logs could not be opened. Use Clash for Mac → Open diagnostic logs from the macOS menu bar.";
      });
    });
    panel.append(heading, detail, code, reload, logs, status);
    document.body.appendChild(panel);
  }

  function fail(code) {
    if (finished || failed) return;
    failed = true;
    failureCode = code;
    window.clearTimeout(timer);
    showFailure();
    void report(code);
  }

  const errorListener = (event) => {
    if (event.target?.id === "dashboard-script" || event.error || typeof event.message === "string") {
      fail("script_failed");
    }
  };
  const rejectionListener = () => fail("unhandled_rejection");
  window.addEventListener("error", errorListener, true);
  window.addEventListener("unhandledrejection", rejectionListener);
  timer = window.setTimeout(() => fail("startup_timeout"), deadlineMs);
  window.__CFM_STARTUP__ = Object.freeze({
    ready() {
      if (finished || (failed && failureCode !== "startup_timeout")) return;
      // Slow native preparation may finish after the watchdog. Only the real
      // bootstrap completion can clear this transient failure; script errors
      // and rejected bootstrap operations remain failures.
      if (failed) document.getElementById("startup-recovery")?.remove();
      failed = false;
      finished = true;
      window.clearTimeout(timer);
      window.removeEventListener("error", errorListener, true);
      window.removeEventListener("unhandledrejection", rejectionListener);
      void report("ready");
    },
    fail() { fail("bootstrap_failed"); },
  });
  void report("script_loaded");
})();
