// The Profiles page: the import controls, the profile list, invalid profiles
// and the profile inspector.
import { state } from "./state.js";
import { escapeHtml, formatBytes } from "./text-format.js";
import { t } from "./i18n.js";
import { PROFILE_SOURCE_ACCEPT } from "./profile-import.js";

export function renderProfiles() {
  const repositoryReason = state.profilesUnavailableReason
    ? t("Profile repository unavailable: {profilesUnavailableReason}", { profilesUnavailableReason: state.profilesUnavailableReason })
    : null;
  const mutationReason = repositoryReason;
  const blocked = mutationReason ? `disabled title="${escapeHtml(mutationReason)}"` : "";
  return `
    <div class="profiles-layout">
      <section class="cfw-profile-remote">
        <div class="cfw-url-box">
          <textarea data-profile-url rows="1" spellcheck="false" autocomplete="off" placeholder="${escapeHtml(t("HTTPS subscription or node link"))}" aria-label="${escapeHtml(t("Subscription URL or node link"))}" ${blocked}></textarea>
          <button class="paste-icon" data-action="paste-profile-url" title="${escapeHtml(t("Paste URL"))}" ${blocked}>▣</button>
        </div>
        <button class="cfw-big-button" data-action="import-profile" ${blocked}>${escapeHtml(t("Import Link"))}</button>
        <button class="cfw-big-button" data-action="update-all-profiles" ${blocked}>${escapeHtml(t("Update All"))}</button>
        <button class="cfw-big-button" data-action="import-profile-file" ${blocked}>${escapeHtml(t("Import File"))}</button>
        <input class="profile-file-hidden" data-profile-file type="file" accept="${PROFILE_SOURCE_ACCEPT}" aria-label="${escapeHtml(t("Local JSON, YAML, WireGuard, or node-link profile"))}" ${blocked} />
      </section>

      <p class="profile-note">${escapeHtml(t("Clash YAML imports nodes, groups, supported routing rules, DNS, and hosts. Unsupported policies are reported before saving."))}</p>
      ${mutationReason ? `<p class="profile-note">${escapeHtml(mutationReason)}</p>` : ""}

      <section class="cfw-profile-list">
        ${repositoryReason ? `
          <div class="empty-profile-state" role="alert">
            <p>${escapeHtml(repositoryReason)}</p>
            <button data-action="reload-dashboard">${escapeHtml(t("Reload profile repository"))}</button>
          </div>
        ` : state.profiles.length || state.invalidProfiles.length ? state.profiles.map((profile) => `
          <article class="cfw-profile-card ${profile.active ? "active" : ""}" data-profile-card="${escapeHtml(profile.id)}" ${profile.active ? 'aria-current="true"' : ""}>
            <i></i>
            <div class="profile-card-main">
              <h3>${escapeHtml(profile.name)}</h3>
              <p title="${escapeHtml(t("Time since this profile was saved in {product}", { product: state.payload.product.name }))}">${escapeHtml(profileSourceLabel(profile))} (${escapeHtml(profile.updated)})</p>
            </div>
            <div class="profile-card-primary">
              <button data-profile-action="edit" data-profile-id="${escapeHtml(profile.id)}" title="${escapeHtml(t("Open this profile"))}">‹›</button>
            </div>
          </article>
        `).join("") + state.invalidProfiles.map(renderInvalidProfileCard).join("") : `
          <div class="empty-profile-state">
            <p>${escapeHtml(t("No profiles found in the managed profiles directory."))}</p>
            ${state.payload.product.operating_system === "macos"
              ? `<button data-action="migrate-legacy-profiles">${escapeHtml(t("Migrate selected legacy subscription"))}</button>` : ""}
          </div>
        `}
      </section>
      ${renderProfileInspector()}
    </div>
  `;
}

/// A stored profile that fails current validation: shown with the validator
/// message, never selectable, and offering only Delete and, for a
/// subscription, copying its URL so it can be imported again.
function renderInvalidProfileCard(profile) {
  const id = escapeHtml(profile.id);
  const reason = profile.selected
    ? t("Selected, but invalid: {error}", { error: profile.error })
    : t("Invalid: {error}", { error: profile.error });
  return `
    <article class="cfw-profile-card invalid" data-invalid-profile-card="${id}" ${profile.selected ? 'aria-current="true"' : ""} title="${escapeHtml(t("This profile fails validation and cannot be selected or started."))}">
      <i></i>
      <div class="profile-card-main">
        <h3>${escapeHtml(profile.name)}</h3>
        <p>${escapeHtml(profileSourceLabel(profile))} (${escapeHtml(profile.updated)})</p>
        <p class="profile-card-invalid" role="note">${escapeHtml(reason)}</p>
      </div>
      <div class="profile-card-primary">
        ${profile.sourceKind === "subscription" ? `<button data-invalid-profile-action="show-source-url" data-profile-id="${id}" title="${escapeHtml(t("Show subscription URL"))}" aria-label="${escapeHtml(t("Show subscription URL"))}">⧉</button>` : ""}
        <button data-invalid-profile-action="delete" data-profile-id="${id}" title="${escapeHtml(t("Delete this invalid profile"))}" aria-label="${escapeHtml(t("Delete this invalid profile"))}">✕</button>
      </div>
    </article>
  `;
}

function profileSourceLabel(profile) {
  switch (profile.sourceKind) {
    case "local": return t("local file");
    case "subscription": return "subscription";
    default: throw new TypeError("profile snapshot has an invalid source kind");
  }
}

function renderProfileInspector() {
  const inspector = state.profileInspector;
  if (!inspector) return "";
  const profile = inspector.profile ?? {};
  const title = `${profile.name ?? inspector.id} · ${inspector.mode}`;
  const sourceUrl = profile.source_url ?? profile.sourceUrl ?? null;
  let body = "";
  if (inspector.mode === "edit") {
    body = `
      <dl class="detail-grid">
        <div><dt>${escapeHtml(t("Source URL"))}</dt><dd>${escapeHtml(sourceUrl ?? t("local file"))}</dd></div>
        <div><dt>${escapeHtml(t("Size"))}</dt><dd>${escapeHtml(formatBytes(profile.bytes ?? 0))}</dd></div>
        <div><dt>${escapeHtml(t("Active"))}</dt><dd>${profile.active ? "yes" : "no"}</dd></div>
      </dl>
      <textarea class="profile-editor" data-profile-editor spellcheck="false">${escapeHtml(profile.body ?? "")}</textarea>
      <div class="row-actions">
        <button class="button" data-action="save-profile-editor">${escapeHtml(t("Save JSON"))}</button>
        ${sourceUrl ? `<button class="button ghost" data-action="update-profile-from-inspector">${escapeHtml(t("Update from subscription"))}</button>` : ""}
        <button class="button ghost" data-action="close-profile-inspector">${escapeHtml(t("Close"))}</button>
      </div>
      <p class="muted">${escapeHtml(t("Changes are validated before switching the running core. Existing connections may reconnect."))}</p>
    `;
  } else if (inspector.mode === "qrcode") {
    body = inspector.svg
      ? `<div class="profile-qr">${inspector.svg}</div><p class="muted">${escapeHtml(sourceUrl ?? "")}</p>`
      : `<p class="empty">${escapeHtml(inspector.error ?? t("This local profile has no subscription URL."))}</p>`;
  } else {
    body = `
      <dl class="detail-grid">
        <div><dt>${escapeHtml(t("ID"))}</dt><dd>${escapeHtml(profile.id ?? inspector.id)}</dd></div>
        <div><dt>${escapeHtml(t("Active"))}</dt><dd>${profile.active ? "yes" : "no"}</dd></div>
        <div><dt>${escapeHtml(t("Source URL"))}</dt><dd>${escapeHtml(sourceUrl ?? t("local file"))}</dd></div>
      </dl>
    `;
  }

  return `
    <section class="panel profile-inspector">
      <div class="section-heading">
        <div>
          <p class="label">${escapeHtml(t("Profile Inspector"))}</p>
          <h3>${escapeHtml(title)}</h3>
        </div>
        <button class="button ghost" data-action="close-profile-inspector">${escapeHtml(t("Close"))}</button>
      </div>
      ${body}
    </section>
  `;
}
