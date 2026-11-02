// The profile repository as the dashboard sees it: the profile list, the
// selected profile's saved policy, and the commands that change profiles.
import { state, runtime } from "./state.js";
import { errorText, formatBytes, formatRelativeUpdated } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { savedProfilePolicy } from "./profile-policy.js";
import { loadControllerSnapshot } from "./controller-reads.js";

export function createProfileData({ cancelDelayTest, loadProvidersSnapshot, providerSelectionChanged, loadEngineStatus, loadRuntimeProjection }) {
  async function resolveProfileSource(id) {
    const profile = state.profiles.find((item) => item.id === id);
    if (!profile) return undefined;
    if (profile.sourceUrl !== undefined) return profile.sourceUrl;
    try {
      const text = await invoke("read_profile_text", { id });
      profile.sourceUrl = text?.source_url ?? null;
      profile.sourceError = null;
    } catch (error) {
      profile.sourceError = errorText(error);
      appendLog("error", "profile", t("Could not read {name} source metadata: {sourceError}", { name: profile.name, sourceError: profile.sourceError }));
    }
    return profile.sourceUrl;
  }

  /// Applies the selected profile.
  ///
  /// With the engine running this restarts it onto a freshly projected
  /// configuration; with the engine Off the projection is validated and staged,
  /// which the log line states rather than implying a configuration was pushed.
  async function applyActiveProfile(context) {
    const applied = await invoke("apply_active_profile");
    appendLog(
      "info",
      "profile",
      t("{name}: projection {value2} ({value3}){value4}", { name: applied.name, value2: applied.applied ? t("applied and engine restarted") : t("validated and staged (engine is off)"), value3: formatBytes(applied.bytes ?? 0), value4: context ? t(" after {context}", { context }) : "" }),
    );
    await loadRuntimeProjection();
    return applied;
  }

  async function invokeProfileChange(command, args) {
    try {
      const result = await invoke(command, args);
      if (result?.reset_proxy_groups?.length) {
        appendLog("warning", "profile", t("Saved nodes were removed from these groups; the new defaults apply: {value1}", { value1: result.reset_proxy_groups.join(", ") }));
      }
      return result;
    } finally {
      await loadProfilesSnapshot();
      await loadEngineStatus();
      if (state.engine.active) await loadControllerSnapshot();
      await loadRuntimeProjection();
    }
  }

  async function selectProfileById(id) {
    const profile = state.profiles.find((item) => item.id === id);
    if (!profile) throw new Error(t("profile not found: {id}", { id: id }));
    if (profile.active) {
      appendLog("info", "profile", t("{name} is already active", { name: profile.name }));
      return false;
    }
    await invokeProfileChange("select_profile", { id });
    appendLog("info", "profile", t("{name} selected", { name: profile.name }));
    return true;
  }

  async function loadSavedProfilePolicy() {
    if (state.toggles.testingDelays) cancelDelayTest();
    const previous = state.savedProfilePolicy;
    const previousBody = runtime.savedProfilePolicyBody;
    const epoch = ++runtime.savedProfilePolicyEpoch;
    const active = state.profiles.find((profile) => profile.active);
    state.savedProfilePolicy = null;
    state.savedProfilePolicyError = null;
    if (!active) return;
    try {
      const text = await invoke("read_profile_text", { id: active.id });
      if (epoch !== runtime.savedProfilePolicyEpoch) return;
      if (text?.id !== active.id) throw new TypeError("saved profile identity changed");
      state.savedProfilePolicy = savedProfilePolicy(text);
      if (previous?.profileId !== text.id || previousBody !== text.body) {
        cancelDelayTest();
        state.proxyDelayResults.clear();
        state.proxyGroupHideTimeouts.clear();
        state.proxyDelayMessage = null;
      }
      runtime.savedProfilePolicyBody = text.body;
      for (const group of state.savedProfilePolicy.groups) {
        for (const node of group.options) {
          const measured = state.proxyDelayResults.get(node.name);
          if (measured) Object.assign(node, measured);
        }
      }
    } catch (error) {
      if (epoch !== runtime.savedProfilePolicyEpoch) return;
      state.savedProfilePolicyError = errorText(error);
      appendLog("error", "profile", state.savedProfilePolicyError);
    }
  }

  /// The repository lists validated profiles and, separately, stored profiles
  /// that fail current validation. A malformed snapshot is a repository error.
  function parseProfilesSnapshot(snapshot) {
    if (!Array.isArray(snapshot?.profiles) || !Array.isArray(snapshot?.invalid_profiles)) {
      throw new TypeError("profile snapshot is malformed");
    }
    for (const profile of [...snapshot.profiles, ...snapshot.invalid_profiles]) {
      if (profile.source_kind !== "local" && profile.source_kind !== "subscription") {
        throw new TypeError("profile snapshot has an invalid source kind");
      }
    }
    for (const profile of snapshot.invalid_profiles) {
      if (typeof profile.error !== "string" || !profile.error || typeof profile.selected !== "boolean") {
        throw new TypeError("an invalid profile in the snapshot has no validation error");
      }
    }
    return snapshot;
  }

  async function loadProfilesSnapshot() {
    try {
      const { profiles, invalid_profiles: invalidProfiles } = parseProfilesSnapshot(await invoke("profiles_snapshot"));
      const previousProfileId = state.profiles.find((profile) => profile.active)?.id ?? null;
      const known = new Map(state.profiles.map((profile) => [profile.id, profile]));
      state.profiles = profiles.map((profile) => ({
        id: profile.id,
        name: profile.name,
        updated: profile.updated_epoch_secs
          ? formatRelativeUpdated(profile.updated_epoch_secs)
          : "unknown",
        updatedEpochSecs: profile.updated_epoch_secs ?? null,
        sourceKind: profile.source_kind,
        active: Boolean(profile.active),
        // A profile list carries no subscription URL, because it can bear an
        // access token. `undefined` means "not published in a list"; it is
        // resolved by an explicit single-profile read.
        sourceUrl: known.get(profile.id)?.sourceUrl,
        sourceError: known.get(profile.id)?.sourceError ?? null,
      }));
      state.invalidProfiles = invalidProfiles.map((profile) => ({
        id: profile.id,
        name: profile.name,
        updated: profile.updated_epoch_secs
          ? formatRelativeUpdated(profile.updated_epoch_secs)
          : "unknown",
        sourceKind: profile.source_kind,
        selected: profile.selected,
        error: profile.error,
      }));
      if (previousProfileId !== (state.profiles.find((profile) => profile.active)?.id ?? null)) providerSelectionChanged();
      state.profilesUnavailableReason = null;
      await loadSavedProfilePolicy();
      await loadProvidersSnapshot();
      if (state.credentialSetup && !state.profiles.some(({ id }) => id === state.credentialSetup.profileId)) {
        state.credentialSetup = null;
      }
      return true;
    } catch (error) {
      state.profiles = [];
      state.invalidProfiles = [];
      providerSelectionChanged();
      runtime.savedProfilePolicyEpoch += 1;
      state.savedProfilePolicy = null;
      state.savedProfilePolicyError = errorText(error);
      state.profilesUnavailableReason = errorText(error);
      appendLog("error", "profile", state.profilesUnavailableReason);
      return false;
    }
  }

  return { loadProfilesSnapshot, resolveProfileSource, invokeProfileChange, selectProfileById, applyActiveProfile };
}
