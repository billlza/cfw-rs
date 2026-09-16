// One bounded latency run. Identity changes and explicit cancellation stop
// further batches; untested nodes remain untested when the run budget expires.
export const MAX_DELAY_TEST_MILLISECONDS = 120_000;

export function createProxyDelayTest({ state, runtime, view, invoke, activeProfile,
  engineIsOff, controllerActionAllowed, captureEngineIdentityToken,
  engineIdentityTokenIsCurrent, appendLog, renderPage, errorText, delayFailureLabel,
  now = () => performance.now() }) {
  const { cancelDelayTest, patchProxyDelayLabels, activeProxyGroup,
    orderNamesVisibleFirst, delayConcurrency, applyDelayToProxyNodes,
    finalizeDelayTestNames } = view;
  return async function run() {

    if (state.toggles.testingDelays) {
      cancelDelayTest();
      state.proxyDelayMessage = runtime.delayBatchInFlight ? "Stopping latency test after the current batch…" : "Latency test cancelled.";
      appendLog("info", "proxy", state.proxyDelayMessage);
      renderPage();
      patchProxyDelayLabels();
      return;
    }
    if (runtime.delayBatchInFlight) return;
    const offline = engineIsOff();
    if (!offline && !controllerActionAllowed("Delay test", "proxy")) return;
    const activeGroup = activeProxyGroup();
    const policyEpoch = runtime.savedProfilePolicyEpoch;
    const engineToken = captureEngineIdentityToken();
    const profileId = offline ? state.savedProfilePolicy?.profileId : activeProfile().id;
    // CFW only latency-tests the current section's `all` list — not every group.
    const names = orderNamesVisibleFirst(
      [...new Set((activeGroup?.options ?? []).map((node) => node.name))]
        .filter((name) => !["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"].includes(String(name).toUpperCase())),
    );
    if (!names.length) {
      appendLog("warning", "proxy", "No proxy nodes available for delay test");
    } else {
      const generation = (runtime.delayTestGeneration = (runtime.delayTestGeneration ?? 0) + 1);
      const isCurrent = () => generation === runtime.delayTestGeneration
        && (offline ? engineIsOff() && policyEpoch === runtime.savedProfilePolicyEpoch
          && profileId === state.savedProfilePolicy?.profileId : engineIdentityTokenIsCurrent(engineToken));
      state.toggles.testingDelays = true;
      state.proxyDelayMessage = "Testing latency…";
      state.toggles.showProxiesList = true;
      if (activeGroup) {
        const testedNames = new Set(names);
        activeGroup.options.forEach((node) => {
          if (testedNames.has(node.name)) {
            state.proxyDelayResults.delete(node.name);
            node.delay = null;
            node.delayFailure = null;
            node.dead = false;
          }
        });
      }
      renderPage();
      let offset = 0;
      const startedAt = now();
      try {
        // No delay-test URL preference exists in 0.4.0; the command supplies
        // the pinned engine's fixed HTTPS connectivity target.
        const delayByName = new Map();
        const failureByName = new Map();
        while (offset < names.length) {
          if (!isCurrent() || now() - startedAt >= MAX_DELAY_TEST_MILLISECONDS) break;
          const concurrency = delayConcurrency();
          const chunk = names.slice(offset, offset + concurrency);
          offset += chunk.length;
          runtime.delayBatchInFlight = true;
          let results;
          try {
            results = await invoke("test_proxy_delays", {
              profileId,
              proxies: chunk,
              timeoutMs: 5000,
              concurrency,
            });
          } finally {
            runtime.delayBatchInFlight = false;
          }
          if (!isCurrent()) break;
          if (!Array.isArray(results)) throw new TypeError("Invalid latency response");
          const seen = new Set();
          for (const item of results) {
            if (!chunk.includes(item.name) || seen.has(item.name)) throw new TypeError("Latency response targets do not match the request");
            seen.add(item.name);
            if (Number.isFinite(item.delay) && item.delay > 0) {
              delayByName.set(item.name, item.delay);
              applyDelayToProxyNodes(item.name, item.delay);
            } else {
              const failure = item.error_kind ?? "invalid_response";
              failureByName.set(item.name, failure);
              applyDelayToProxyNodes(item.name, null, failure);
            }
          }
          for (const name of chunk) {
            if (!seen.has(name) && !delayByName.has(name) && !failureByName.has(name)) {
              failureByName.set(name, "invalid_response");
              applyDelayToProxyNodes(name, null, "invalid_response");
            }
          }
          patchProxyDelayLabels(chunk);
        }
        if (isCurrent()) {
          finalizeDelayTestNames(names.slice(0, offset));
          const failed = failureByName.size
            + names.slice(0, offset).filter((name) => !delayByName.has(name) && !failureByName.has(name)).length;
          const ok = delayByName.size;
          const untested = names.length - offset;
          const remaining = untested ? ` ${untested} not tested: the two-minute test limit was reached.` : "";
          const failures = new Map();
          for (const kind of failureByName.values()) {
            failures.set(kind, (failures.get(kind) ?? 0) + 1);
          }
          const failureSummary = [...failures.entries()]
            .map(([kind, count]) => `${count} ${delayFailureLabel(kind).toLowerCase()}`)
            .join(", ");
          state.proxyDelayMessage = `${ok} passed, ${failed} failed${failureSummary ? ` (${failureSummary})` : ""}.${remaining}`;
          appendLog(
            failed ? "error" : "info",
            "proxy",
            `Delay test (${activeGroup?.name ?? "group"}): ${ok} ok${failed ? `, ${failed} failed${failureSummary ? ` (${failureSummary})` : ""}` : ""} · concurrency ${delayConcurrency()}`,
          );
        }
      } catch (error) {
        if (isCurrent()) {
          finalizeDelayTestNames(names.slice(0, offset));
          state.proxyDelayMessage = `Latency test failed: ${errorText(error)}`;
          appendLog("error", "proxy", `Delay test failed: ${errorText(error)}`);
        }
      } finally {
        if ((runtime.delayTestGeneration ?? 0) === generation) {
          state.toggles.testingDelays = false;
        } else if (!state.toggles.testingDelays && state.proxyDelayMessage?.startsWith("Stopping latency")) {
          state.proxyDelayMessage = "Latency test cancelled.";
        }
        if (state.activePage === "proxies") renderPage();
      }
    }

  };
}
