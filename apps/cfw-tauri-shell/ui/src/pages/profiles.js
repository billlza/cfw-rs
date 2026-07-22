import { button, heading, node, statusPill } from "../dom.js";
import { formatBytes, profileUpdatedLabel } from "../format.js";

function profileRow(profile, busy, mutationBlocked) {
  const actions = [
    button("Credentials", "configure-profile-credentials", {
      className: "button ghost",
      disabled: busy,
      dataset: { profileId: profile.id },
    }),
    profile.active ? null : button("Select", "select-profile", {
      className: "button ghost",
      disabled: mutationBlocked,
      dataset: { profileId: profile.id },
    }),
    button("Delete", "delete-profile", {
      className: "button ghost danger",
      disabled: mutationBlocked || profile.active,
      dataset: { profileId: profile.id },
    }),
  ].filter(Boolean);
  return node("article", { className: "profile-row" }, [
    node("div", { className: "profile-row-main" }, [
      node("div", {}, [
        node("h4", { text: profile.name }),
        node("p", { className: "muted", text: `Imported JSON · ${formatBytes(profile.bytes)} · ${profileUpdatedLabel(profile.updatedEpochSeconds)}` }),
      ]),
      profile.active ? statusPill("Selected", "good") : statusPill("Unselected"),
    ]),
    node("div", { className: "toolbar-actions" }, actions),
  ]);
}

function credentialLabel(kind) {
  return kind.split("_").map((part) => part[0].toUpperCase() + part.slice(1)).join(" ");
}

function credentialSetupPanel(setup, busy, mutationBlocked) {
  if (!setup) return null;
  if (!setup.vaultAvailable) {
    return node("section", { className: "panel credential-setup warning-panel" }, [
      heading(
        "Credentials",
        `${setup.profileName} · Vault unavailable`,
        "Credential presence could not be verified. No value is being requested or treated as missing. Restore the signed native Keychain vault and retry.",
      ),
      node("div", { className: "toolbar-actions" }, [
        button("Retry vault check", "configure-profile-credentials", {
          className: "button ghost",
          disabled: busy,
          dataset: { profileId: setup.profileId },
        }),
        button("Close", "cancel-profile-credentials", {
          className: "button ghost",
          disabled: busy,
        }),
      ]),
    ]);
  }
  const fields = setup.requirements.map((reference, index) => node("label", {
    className: "credential-field",
  }, [
    node("span", {}, [
      node("b", { text: credentialLabel(reference.kind) }),
      node("small", { text: reference.id }),
    ]),
    node("input", {
      type: "password",
      disabled: mutationBlocked,
      dataset: {
        credentialSecret: "true",
        credentialIndex: index,
        credentialId: reference.id,
        credentialKind: reference.kind,
      },
      attributes: {
        autocomplete: "new-password",
        maxlength: 16384,
        required: "required",
        "aria-label": `${credentialLabel(reference.kind)} secret`,
      },
    }),
  ]));
  return node("section", { className: "panel credential-setup" }, [
    heading(
      "Credentials",
      `${setup.profileName} · ${setup.requirements.length} missing`,
      `${setup.presentCount} of ${setup.requiredCount} immutable references are already present and never need to be re-entered. Enter every missing value once. The batch is sent directly to the native Keychain vault; values are never added to the profile, UI store, App Group, logs or configuration digest.`,
    ),
    node("form", {
      dataset: {
        credentialForm: "true",
        profileId: setup.profileId,
      },
      attributes: { autocomplete: "off" },
    }, [
      node("div", { className: "credential-fields" }, fields),
      node("div", { className: "toolbar-actions" }, [
        button("Store all credentials", "provision-profile-credentials", {
          disabled: mutationBlocked,
          dataset: { profileId: setup.profileId },
        }),
        button("Cancel", "cancel-profile-credentials", {
          className: "button ghost",
          disabled: busy,
        }),
      ]),
    ]),
  ]);
}

function credentialGcPanel(preview, busy) {
  if (!preview) return null;
  const references = preview.orphanReferences.slice(0, 12).map((reference) => node("li", {
    text: `${credentialLabel(reference.kind)} · ${reference.id}`,
  }));
  if (preview.orphanReferences.length > references.length) {
    references.push(node("li", {
      text: `…and ${preview.orphanReferences.length - references.length} more`,
    }));
  }
  return node("section", { className: "panel warning-panel" }, [
    heading(
      "Credential cleanup",
      `${preview.orphanCount} unused reference${preview.orphanCount === 1 ? "" : "s"}`,
      "These immutable Keychain entries are not referenced by any selected or staged managed profile. Cleanup revalidates the repository snapshot and vault revision before one atomic deletion.",
    ),
    node("ul", { className: "credential-gc-list" }, references),
    node("div", { className: "toolbar-actions" }, [
      button("Delete unused credentials", "commit-credential-gc", {
        className: "button danger",
        disabled: busy,
        dataset: { previewId: preview.previewId },
      }),
      button("Cancel", "cancel-credential-gc", {
        className: "button ghost",
        disabled: busy,
        dataset: { previewId: preview.previewId },
      }),
    ]),
  ]);
}

export function renderProfilesPage(state) {
  const busy = Boolean(state.busyAction);
  const mutationBlocked = busy
    || state.engine.state !== "Off"
    || state.engine.desiredMode !== "off";
  const fileInput = node("input", {
    type: "file",
    accept: "application/json,.json",
    disabled: mutationBlocked,
    dataset: { profileFile: "true" },
    attributes: { "aria-label": "Choose typed proxy JSON profile" },
  });
  const importPanel = node("section", { className: "panel" }, [
    heading("Profiles", "Stage before cutover", "Import and select the typed replacement profile while the existing VPN remains untouched. Supported fields mirror safe sing-box outbound shapes for Shadowsocks, VMess, VLESS/Reality, Trojan and Hysteria2. JSON stores immutable credential_ref values only; rotating a secret requires a new UUID and profile update. Raw secrets, scripts, executables, inbounds, remote resources and legacy Clash YAML are rejected."),
    node("div", { className: "profile-import-row" }, [
      fileInput,
      button("Review unused credentials", "preview-credential-gc", {
        className: "button ghost",
        disabled: mutationBlocked,
      }),
    ]),
  ]);
  const list = state.profiles.length
    ? state.profiles.map((profile) => profileRow(profile, busy, mutationBlocked))
    : [node("p", { className: "empty", text: "No validated profiles have been imported." })];
  return node("div", { className: "profiles-layout" }, [
    importPanel,
    credentialSetupPanel(state.profileCredentialSetup, busy, mutationBlocked),
    credentialGcPanel(state.credentialGcPreview, busy),
    node("section", { className: "panel profile-list" }, [
      heading("Configuration", `${state.profiles.length} profile${state.profiles.length === 1 ? "" : "s"}`),
      ...list,
    ]),
  ]);
}
