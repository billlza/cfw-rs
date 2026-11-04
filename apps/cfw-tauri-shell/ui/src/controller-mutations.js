// Controller mutations run one at a time, per lane, and each one is confirmed
// by reading the controller back before it is reported as applied.
import { state, runtime } from "./state.js";
import { errorText } from "./text-format.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, engineIdentityTokenIsCurrent } from "./engine-identity.js";
import { closeConnectionsAfterProxyChange, loadControllerSnapshot } from "./controller-reads.js";
import { applyPendingControllerIntents } from "./controller-intents.js";

export function createControllerMutations({ renderPage }) {
  function controllerMutationIsCurrent(entry) {
    return engineIdentityTokenIsCurrent(entry.token)
      && runtime.controllerMutationLatestByLane.get(entry.lane) === entry.epoch;
  }

  function finishControllerMutationEntry(entry, result) {
    // The drain removed this entry's pending intent before it read the
    // controller back; a newer request of the lane may have queued its own.
    if (runtime.controllerMutationLatestByLane.get(entry.lane) === entry.epoch) {
      runtime.controllerMutationLatestByLane.delete(entry.lane);
    }
    entry.resolve(result);
    renderPage();
  }

  async function drainControllerMutationQueue() {
    if (runtime.controllerMutationRunning) return;
    runtime.controllerMutationRunning = true;
    try {
      while (runtime.controllerMutationQueue.length) {
        const entry = runtime.controllerMutationQueue.shift();
        if (!controllerMutationIsCurrent(entry)) {
          entry.resolve(false);
          continue;
        }

        let mutationError = null;
        try {
          await entry.invokeMutation();
        } catch (error) {
          mutationError = error;
        }
        if (!controllerMutationIsCurrent(entry)) {
          entry.resolve(false);
          continue;
        }

        let observedSnapshot = null;
        const controllerReadable = await loadControllerSnapshot(
          false,
          entry.token,
          () => controllerMutationIsCurrent(entry),
          (snapshot) => { observedSnapshot = snapshot; },
        );
        if (!controllerMutationIsCurrent(entry)) {
          entry.resolve(false);
          continue;
        }

        const observed = controllerReadable ? entry.readObserved(observedSnapshot) : null;
        const confirmed = controllerReadable && observed === entry.target;
        if (runtime.controllerMutationPendingByLane.get(entry.lane)?.epoch === entry.epoch) {
          runtime.controllerMutationPendingByLane.delete(entry.lane);
        }
        if (!confirmed && controllerReadable) entry.publishObserved(observed);
        applyPendingControllerIntents();

        if (mutationError) {
          const readback = controllerReadable
            ? t("controller readback reports {value1}", { value1: observed ?? "unavailable" })
            : "controller readback was unavailable";
          appendLog("error", entry.source, `${entry.failureLabel}: ${errorText(mutationError)}; ${readback}`);
          finishControllerMutationEntry(entry, false);
          continue;
        }
        if (!controllerReadable) {
          appendLog("error", entry.source, t("{failureLabel}: controller readback was unavailable", { failureLabel: entry.failureLabel }));
          finishControllerMutationEntry(entry, false);
          continue;
        }
        if (!confirmed) {
          appendLog("error", entry.source, t("{failureLabel}: controller readback reported {value2}", { failureLabel: entry.failureLabel, value2: observed ?? "unavailable" }));
          finishControllerMutationEntry(entry, false);
          continue;
        }

        if (state.toggles.breakOnProxyChange) {
          await closeConnectionsAfterProxyChange(
            entry.breakConnectionsReason,
            entry.token,
            () => controllerMutationIsCurrent(entry),
          );
        }
        if (!controllerMutationIsCurrent(entry)) {
          entry.resolve(false);
          continue;
        }
        appendLog("info", entry.source, entry.successMessage);
        finishControllerMutationEntry(entry, true);
      }
    } finally {
      runtime.controllerMutationRunning = false;
      if (runtime.controllerMutationQueue.length) void drainControllerMutationQueue();
    }
  }

  function enqueueControllerMutation(specification) {
    const token = captureEngineIdentityToken();
    if (!engineIdentityTokenIsCurrent(token)) return Promise.resolve(false);
    const epoch = runtime.controllerMutationEpoch + 1;
    runtime.controllerMutationEpoch = epoch;
    const pending = {
      epoch,
      token,
      lane: specification.lane,
      kind: specification.kind,
      target: specification.target,
      groupName: specification.groupName ?? null,
    };
    runtime.controllerMutationLatestByLane.set(specification.lane, epoch);
    runtime.controllerMutationPendingByLane.set(specification.lane, pending);
    applyPendingControllerIntents();
    renderPage();

    return new Promise((resolve) => {
      runtime.controllerMutationQueue.push({ ...specification, ...pending, resolve });
      void drainControllerMutationQueue();
    });
  }

  return { enqueueControllerMutation };
}
