// Controller mutations the user asked for and the controller has not yet
// confirmed. They are shown as requested while they are pending.
import { state, runtime } from "./state.js";
import { engineIdentityTokenIsCurrent } from "./engine-identity.js";

export function applyPendingControllerIntents() {
  for (const pending of runtime.controllerMutationPendingByLane.values()) {
    if (!engineIdentityTokenIsCurrent(pending.token)) continue;
    if (pending.kind === "mode") {
      state.mode = pending.target;
      continue;
    }
    const group = state.proxyGroups.find((item) => item.name === pending.groupName);
    if (group) group.now = pending.target;
  }
}

export function invalidateControllerMutationIntents() {
  runtime.controllerMutationLatestByLane.clear();
  runtime.controllerMutationPendingByLane.clear();
  const queued = runtime.controllerMutationQueue.splice(0);
  for (const entry of queued) entry.resolve(false);
}
