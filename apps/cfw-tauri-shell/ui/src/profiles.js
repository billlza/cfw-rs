import { invoke } from "./bridge.js";
import { store } from "./store.js";
import { appendLog } from "./streams.js";

const MAX_PROFILE_BYTES = 384 * 1024;
const MAX_PROFILE_NODES = 100_000;
const ALLOWED_TOP_LEVEL = new Set(["outbounds", "route"]);
const MAX_OUTBOUNDS = 128;
const MAX_TAG_BYTES = 128;
const MAX_CREDENTIALS = 256;
const MAX_VAULT_REFERENCES = 512;
const MAX_CREDENTIAL_SECRET_BYTES = 16 * 1024;
const CREDENTIAL_KINDS = new Set([
  "shadowsocks_password",
  "vmess_uuid",
  "vless_uuid",
  "trojan_password",
  "hysteria2_password",
  "hysteria2_obfs_password",
]);
const FORBIDDEN_KEYS = new Set([
  "inbounds",
  "experimental",
  "log",
  "process_path",
  "process_name",
  "process_path_regex",
  "user",
  "user_id",
  "package_name",
  "source_mac_address",
  "script",
  "command",
  "executable",
  "url",
]);
const CREDENTIAL_KEYS = new Set([
  "access_token",
  "api_key",
  "auth_key",
  "authorization",
  "auth_str",
  "client_key",
  "client_secret",
  "password",
  "passwd",
  "pre_shared_key",
  "private_key",
  "psk",
  "refresh_token",
  "secret",
  "token",
  "uuid",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateTypedProfileEnvelope(profile) {
  if (!Array.isArray(profile.outbounds) || profile.outbounds.length === 0 || profile.outbounds.length > MAX_OUTBOUNDS) {
    throw new TypeError("Profile requires between 1 and 128 outbounds");
  }
  const tags = new Set();
  for (const outbound of profile.outbounds) {
    if (!isRecord(outbound)) throw new TypeError("Each outbound must be an object");
    if (typeof outbound.type !== "string" || outbound.type.length === 0) {
      throw new TypeError("Each outbound requires a type");
    }
    if (typeof outbound.tag !== "string"
      || outbound.tag.trim() !== outbound.tag
      || outbound.tag.length === 0
      || new TextEncoder().encode(outbound.tag).byteLength > MAX_TAG_BYTES
      || /[\u0000-\u001f\u007f]/u.test(outbound.tag)
      || tags.has(outbound.tag)) {
      throw new TypeError("Outbound tag is missing, duplicated, or invalid");
    }
    tags.add(outbound.tag);
  }
  if (profile.route !== undefined) {
    if (!isRecord(profile.route)) throw new TypeError("Route must be an object");
    for (const key of Object.keys(profile.route)) {
      if (key !== "final") throw new TypeError(`Unsupported route field: ${key}`);
    }
    if (profile.route.final !== undefined
      && (typeof profile.route.final !== "string" || !tags.has(profile.route.final))) {
      throw new TypeError("Route final must reference a declared outbound tag");
    }
  }
}

export function validateSingBoxProfileText(text) {
  const bytes = new TextEncoder().encode(text).byteLength;
  if (bytes === 0) throw new TypeError("Profile is empty");
  if (bytes > MAX_PROFILE_BYTES) throw new TypeError("Profile exceeds the 384 KiB limit");

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new TypeError("Profile must be valid JSON", { cause: error });
  }
  if (!isRecord(parsed)) throw new TypeError("Profile root must be a JSON object");
  for (const key of Object.keys(parsed)) {
    if (!ALLOWED_TOP_LEVEL.has(key)) throw new TypeError(`Unsupported top-level profile key: ${key}`);
  }

  const pending = [parsed];
  let visited = 0;
  while (pending.length) {
    const value = pending.pop();
    visited += 1;
    if (visited > MAX_PROFILE_NODES) throw new TypeError("Profile structure is too complex");
    if (Array.isArray(value)) {
      if (visited + pending.length + value.length > MAX_PROFILE_NODES) {
        throw new TypeError("Profile structure is too complex");
      }
      for (const child of value) pending.push(child);
      continue;
    }
    if (!isRecord(value)) continue;
    if (value.type === "remote") {
      throw new TypeError("Remote profile resources are unsupported");
    }
    for (const [key, child] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase();
      if (CREDENTIAL_KEYS.has(normalizedKey)) {
        throw new TypeError(`Credential requires shared Keychain support: ${key}`);
      }
      if (FORBIDDEN_KEYS.has(normalizedKey)
        || normalizedKey.endsWith("_path")
        || normalizedKey.endsWith("_url")) {
        throw new TypeError(`Forbidden profile key: ${key}`);
      }
      pending.push(child);
    }
  }
  // The renderer performs only bounded, credential-leak and executable/remote
  // resource checks. Rust is the single authoritative typed schema validator;
  // duplicating protocol field allowlists here caused the UI and engine to
  // drift and previously rejected every usable remote profile.
  validateTypedProfileEnvelope(parsed);
  return parsed;
}

function normalizedProfile(profile) {
  if (!profile || typeof profile !== "object" || typeof profile.id !== "string") {
    throw new TypeError("Native profile record is invalid");
  }
  return {
    id: profile.id.slice(0, 256),
    name: String(profile.name ?? profile.id).slice(0, 256),
    active: profile.active === true,
    bytes: Number.isFinite(Number(profile.bytes)) ? Number(profile.bytes) : 0,
    updatedEpochSeconds: Number.isFinite(Number(profile.updated_epoch_secs)) ? Number(profile.updated_epoch_secs) : null,
  };
}

function normalizedCredentialReference(reference) {
  if (!isRecord(reference)
    || typeof reference.id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(reference.id)
    || !CREDENTIAL_KINDS.has(reference.kind)) {
    throw new TypeError("Native credential reference is invalid");
  }
  return Object.freeze({ id: reference.id, kind: reference.kind });
}

function normalizeCredentialReferences(payload, maximum = MAX_CREDENTIALS) {
  if (!Array.isArray(payload) || payload.length > maximum) {
    throw new TypeError("Native credential requirements are invalid");
  }
  const references = payload.map(normalizedCredentialReference);
  const ids = new Set(references.map(({ id }) => id));
  if (ids.size !== references.length) {
    throw new TypeError("Native credential requirements contain duplicate references");
  }
  return references;
}

function normalizeCredentialPresence(payload, required) {
  if (!Array.isArray(payload) || payload.length !== required.length) {
    throw new TypeError("Native credential presence result is incomplete");
  }
  return payload.map((entry, index) => {
    if (!isRecord(entry) || typeof entry.present !== "boolean") {
      throw new TypeError("Native credential presence result is invalid");
    }
    const reference = normalizedCredentialReference(entry.reference);
    const expected = required[index];
    if (reference.id !== expected.id || reference.kind !== expected.kind) {
      throw new TypeError("Native credential presence result does not match the profile");
    }
    return { reference, present: entry.present };
  });
}

export async function loadProfiles() {
  const payload = await invoke("profiles_snapshot");
  if (!Array.isArray(payload)) throw new TypeError("Native profiles snapshot is invalid");
  const profiles = payload.map(normalizedProfile);
  const setup = store.get().profileCredentialSetup;
  store.update({
    profiles,
    profileCredentialSetup: setup && profiles.some(({ id }) => id === setup.profileId)
      ? setup
      : null,
  });
  return profiles;
}

export async function importProfileFile(file) {
  if (!(file instanceof File)) throw new TypeError("A profile file is required");
  if (!file.name.toLowerCase().endsWith(".json")) throw new TypeError("Only .json profiles are accepted");
  if (file.size > MAX_PROFILE_BYTES) throw new TypeError("Profile exceeds the 384 KiB limit");
  const body = await file.text();
  validateSingBoxProfileText(body);
  const name = file.name.normalize("NFC");
  if (name.length > 256 || /[\u0000-\u001f\u007f]/u.test(name)) {
    throw new TypeError("Profile file name is invalid");
  }
  const imported = await reconcileProfileImport(
    name,
    () => invoke("import_profile_text", { name, body }),
  );
  if (!isRecord(imported) || typeof imported.id !== "string") {
    throw new TypeError("Native profile import result is invalid");
  }
  await openProfileCredentialSetup(imported.id);
}

export async function reconcileProfileImport(
  name,
  importOperation,
  { reload = loadProfiles, log = appendLog } = {},
) {
  if (typeof name !== "string" || name.length === 0) throw new TypeError("Profile name is invalid");
  if (typeof importOperation !== "function") throw new TypeError("Profile import operation is invalid");
  const imported = await runProfileRepositoryMutation(importOperation, { reload });
  await reload();
  log("info", "profiles", `Imported validated unselected profile ${name}`);
  return imported;
}

export async function openProfileCredentialSetup(
  id,
  {
    fetchRequirements = (profileId) => invoke("profile_credential_requirements", { id: profileId }),
    queryPresence = (profileId) => invoke("profile_credential_presence", { id: profileId }),
    log = appendLog,
  } = {},
) {
  const profile = store.get().profiles.find((entry) => entry.id === id);
  if (!profile) throw new TypeError("Profile does not exist");
  const requirements = normalizeCredentialReferences(
    await fetchRequirements(id),
  );
  if (!requirements.length) {
    store.update({ profileCredentialSetup: null });
    log("info", "profiles", `Profile ${profile.name} requires no credentials`);
    return [];
  }
  let presence;
  try {
    presence = normalizeCredentialPresence(
      await queryPresence(id),
      requirements,
    );
  } catch (error) {
    store.update({
      profileCredentialSetup: {
        profileId: profile.id,
        profileName: profile.name,
        requirements: [],
        requiredCount: requirements.length,
        presentCount: null,
        vaultAvailable: false,
      },
    });
    throw error;
  }
  const missing = presence.filter(({ present }) => !present).map(({ reference }) => reference);
  store.update({
    profileCredentialSetup: missing.length
      ? {
        profileId: profile.id,
        profileName: profile.name,
        requirements: missing,
        requiredCount: requirements.length,
        presentCount: requirements.length - missing.length,
        vaultAvailable: true,
      }
      : null,
  });
  if (!missing.length) {
    log("info", "profiles", `All immutable credential references are present for ${profile.name}`);
  }
  return missing;
}

export function closeProfileCredentialSetup() {
  store.update({ profileCredentialSetup: null });
}

function normalizeCredentialGcPreview(payload) {
  if (!isRecord(payload)
    || typeof payload.preview_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(payload.preview_id)
    || !Number.isSafeInteger(payload.orphan_count)
    || payload.orphan_count < 0
    || payload.orphan_count > 512
    || !Array.isArray(payload.orphan_references)
    || payload.orphan_references.length !== payload.orphan_count) {
    throw new TypeError("Native credential cleanup preview is invalid");
  }
  return {
    previewId: payload.preview_id,
    orphanCount: payload.orphan_count,
    orphanReferences: normalizeCredentialReferences(
      payload.orphan_references,
      MAX_VAULT_REFERENCES,
    ),
  };
}

export async function previewCredentialGc(
  { preview = () => invoke("preview_credential_gc"), log = appendLog } = {},
) {
  const result = normalizeCredentialGcPreview(await preview());
  store.update({ credentialGcPreview: result.orphanCount ? result : null });
  if (!result.orphanCount) {
    log("info", "profiles", "Credential vault has no unused references");
  }
  return result;
}

export async function commitCredentialGc(
  previewId,
  { commit = (id) => invoke("commit_credential_gc", { previewId: id }), log = appendLog } = {},
) {
  const preview = store.get().credentialGcPreview;
  if (!preview || preview.previewId !== previewId) {
    throw new TypeError("Credential cleanup preview is missing or stale");
  }
  try {
    const receipt = await commit(previewId);
    if (!isRecord(receipt)
      || !Number.isSafeInteger(receipt.removed_count)
      || receipt.removed_count !== preview.orphanCount) {
      throw new TypeError("Native credential cleanup receipt does not match the preview");
    }
    log(
      "info",
      "profiles",
      `Removed ${receipt.removed_count} unused immutable credential reference${receipt.removed_count === 1 ? "" : "s"}`,
    );
    return receipt;
  } finally {
    // Server previews are one-shot. Any mismatch, TOCTOU rejection, or native
    // error requires a new preview instead of retrying stale authority.
    store.update({ credentialGcPreview: null });
  }
}

export async function cancelCredentialGc(
  previewId,
  { cancel = (id) => invoke("cancel_credential_gc", { previewId: id }) } = {},
) {
  const preview = store.get().credentialGcPreview;
  if (!preview || preview.previewId !== previewId) return;
  try {
    await cancel(previewId);
  } finally {
    store.update({ credentialGcPreview: null });
  }
}

function validateProvisionEntries(setup, entries) {
  if (!Array.isArray(entries) || entries.length !== setup.requirements.length) {
    throw new TypeError("Every credential reference must be supplied atomically");
  }
  return entries.map((entry, index) => {
    const expected = setup.requirements[index];
    if (!isRecord(entry)
      || entry.id !== expected.id
      || entry.kind !== expected.kind
      || typeof entry.secret !== "string") {
      throw new TypeError("Credential submission does not match the validated profile");
    }
    const bytes = new TextEncoder().encode(entry.secret).byteLength;
    if (bytes === 0
      || bytes > MAX_CREDENTIAL_SECRET_BYTES
      || /[\u0000-\u001f\u007f]/u.test(entry.secret)) {
      throw new TypeError("Credential is empty, oversized, or contains control characters");
    }
    return {
      reference: { id: expected.id, kind: expected.kind },
      secret: entry.secret,
    };
  });
}

export async function provisionProfileCredentials(
  profileId,
  entries,
  {
    provision = ({ profileId: id, credentials }) => invoke("provision_profile_credentials", {
      profileId: id,
      credentials,
    }),
    log = appendLog,
  } = {},
) {
  const setup = store.get().profileCredentialSetup;
  if (!setup || setup.profileId !== profileId) {
    throw new TypeError("Credential setup does not match the requested profile");
  }
  let credentials = [];
  try {
    credentials = validateProvisionEntries(setup, entries);
    const receipt = await provision({ profileId, credentials });
    if (!isRecord(receipt) || receipt.profile_id !== profileId) {
      throw new TypeError("Native credential receipt does not match the profile");
    }
    store.update({ profileCredentialSetup: null });
    log(
      "info",
      "profiles",
      `Provisioned ${credentials.length} immutable credential reference${credentials.length === 1 ? "" : "s"} for ${setup.profileName}`,
    );
  } finally {
    for (const credential of credentials) credential.secret = "";
    for (const entry of entries) {
      if (isRecord(entry) && typeof entry.secret === "string") entry.secret = "";
    }
  }
}

export async function runProfileRepositoryMutation(
  operation,
  { reload = loadProfiles } = {},
) {
  if (typeof operation !== "function") throw new TypeError("Profile repository operation is invalid");
  try {
    return await operation();
  } catch (error) {
    // Import, selection replacement, and deletion can all commit their rename
    // or unlink before a directory fsync reports failure. Refresh before
    // surfacing every mutation error so the renderer never offers a stale
    // retry against commit-uncertain state.
    try {
      await reload();
    } catch (reloadError) {
      throw new AggregateError(
        [error, reloadError],
        "Profile repository operation failed and reconciliation also failed",
      );
    }
    throw error;
  }
}

export async function reconcileProfileSelection(
  profile,
  selected,
  { reload = loadProfiles, log = appendLog } = {},
) {
  const normalized = normalizedProfile(selected);
  if (normalized.id !== profile.id || !normalized.active) {
    throw new TypeError("Native selected-profile result does not match the request");
  }
  await reload();
  log("info", "profiles", `Selected profile ${profile.name}`);
}

export async function selectProfile(id) {
  const profile = store.get().profiles.find((entry) => entry.id === id);
  if (!profile) throw new TypeError("Profile does not exist");
  if (profile.active) return;
  const selected = await runProfileRepositoryMutation(
    () => invoke("select_profile", { id }),
  );
  await reconcileProfileSelection(profile, selected);
}

export class ProfileDeletionConflictError extends Error {
  constructor(id) {
    super(`Profile ${id} was removed before the delete request completed; the profile list was refreshed`);
    this.name = "ProfileDeletionConflictError";
    this.profileId = id;
  }
}

export async function reconcileProfileDeletion(
  profile,
  deleted,
  { reload = loadProfiles, log = appendLog } = {},
) {
  if (deleted === false) {
    await reload();
    throw new ProfileDeletionConflictError(profile.id);
  }
  if (deleted !== true) {
    throw new TypeError("Native profile deletion result must be a boolean");
  }
  await reload();
  log("info", "profiles", `Deleted profile ${profile.name}`);
}

export async function deleteProfile(id) {
  const profile = store.get().profiles.find((entry) => entry.id === id);
  if (!profile) throw new TypeError("Profile does not exist");
  if (profile.active) throw new TypeError("Selected profile must be replaced before deletion");
  const deleted = await runProfileRepositoryMutation(
    () => invoke("delete_profile", { id }),
  );
  await reconcileProfileDeletion(profile, deleted);
}
