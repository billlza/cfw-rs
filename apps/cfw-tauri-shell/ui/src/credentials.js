/// Credential-vault payload validation.
///
/// A 0.4.0 profile can only reference a secret by immutable `credential_ref`, so
/// a subscription cannot carry an inline password and the engine cannot
/// authenticate until every reference is present in the signed native vault.
/// This module validates what the vault reports and what the dashboard is about
/// to send; secrets pass through it and are never stored in application state.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_CREDENTIALS = 256;
const MAX_VAULT_REFERENCES = 512;
const MAX_CREDENTIAL_SECRET_BYTES = 16 * 1024;

export const CREDENTIAL_KINDS = Object.freeze([
  "shadowsocks_password",
  "vmess_uuid",
  "vless_uuid",
  "trojan_password",
  "hysteria2_password",
  "hysteria2_obfs_password",
  "anytls_password",
  "tuic_uuid",
  "tuic_password",
]);

const KINDS = new Set(CREDENTIAL_KINDS);
const CREDENTIAL_LABELS = Object.freeze({
  anytls_password: "AnyTLS Password",
  tuic_uuid: "TUIC UUID",
  tuic_password: "TUIC Password",
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function credentialLabel(kind) {
  if (Object.hasOwn(CREDENTIAL_LABELS, kind)) return CREDENTIAL_LABELS[kind];
  return String(kind)
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

export function normalizeCredentialReference(reference) {
  if (!isRecord(reference)
    || typeof reference.id !== "string"
    || !UUID.test(reference.id)
    || !KINDS.has(reference.kind)) {
    throw new TypeError("credential reference is invalid");
  }
  return Object.freeze({ id: reference.id, kind: reference.kind });
}

export function normalizeCredentialReferences(payload, maximum = MAX_CREDENTIALS) {
  if (!Array.isArray(payload) || payload.length > maximum) {
    throw new TypeError("credential requirements are invalid");
  }
  const references = payload.map(normalizeCredentialReference);
  if (new Set(references.map(({ id }) => id)).size !== references.length) {
    throw new TypeError("credential requirements contain duplicate references");
  }
  return references;
}

export function normalizeCredentialPresence(payload, required) {
  if (!Array.isArray(payload) || payload.length !== required.length) {
    throw new TypeError("credential presence result is incomplete");
  }
  return payload.map((entry, index) => {
    if (!isRecord(entry) || typeof entry.present !== "boolean") {
      throw new TypeError("credential presence result is invalid");
    }
    const reference = normalizeCredentialReference(entry.reference);
    const expected = required[index];
    if (reference.id !== expected.id || reference.kind !== expected.kind) {
      throw new TypeError("credential presence result does not match the profile");
    }
    return { reference, present: entry.present };
  });
}

export function normalizeCredentialGcPreview(payload) {
  if (!isRecord(payload)
    || typeof payload.preview_id !== "string"
    || !UUID.test(payload.preview_id)
    || !Number.isSafeInteger(payload.orphan_count)
    || payload.orphan_count < 0
    || payload.orphan_count > MAX_VAULT_REFERENCES
    || !Array.isArray(payload.orphan_references)
    || payload.orphan_references.length !== payload.orphan_count) {
    throw new TypeError("credential cleanup preview is invalid");
  }
  return {
    previewId: payload.preview_id,
    orphanCount: payload.orphan_count,
    // Two profile audiences may intentionally own the same public UUID. GC is
    // binding-scoped, so repeated references in this display-only projection
    // are valid and must not make an otherwise exact preview unusable.
    orphanReferences: payload.orphan_references.map(normalizeCredentialReference),
  };
}

/// Builds the provisioning batch. Every missing reference must be supplied in
/// one request, in the order the vault reported them, so a partial batch cannot
/// leave a profile half-provisioned.
export function credentialProvisionBatch(requirements, secrets) {
  if (!Array.isArray(secrets) || secrets.length !== requirements.length) {
    throw new TypeError("every credential reference must be supplied at once");
  }
  return requirements.map((reference, index) => {
    const secret = secrets[index];
    if (typeof secret !== "string") throw new TypeError("credential value is invalid");
    const bytes = new TextEncoder().encode(secret).byteLength;
    if (bytes === 0) throw new TypeError(`${credentialLabel(reference.kind)} is required`);
    if (bytes > MAX_CREDENTIAL_SECRET_BYTES) {
      throw new TypeError(`${credentialLabel(reference.kind)} is larger than 16 KiB`);
    }
    if (/[\u0000-\u001f\u007f]/u.test(secret)) {
      throw new TypeError(`${credentialLabel(reference.kind)} contains control characters`);
    }
    return { reference: { id: reference.id, kind: reference.kind }, secret };
  });
}

export function normalizeCredentialReceipt(receipt, profileId) {
  if (!isRecord(receipt) || receipt.profile_id !== profileId) {
    throw new TypeError("credential receipt does not match the profile");
  }
  return receipt;
}

export function normalizeGcReceipt(receipt, expectedCount) {
  if (!isRecord(receipt)
    || !Number.isSafeInteger(receipt.removed_count)
    || receipt.removed_count !== expectedCount) {
    throw new TypeError("credential cleanup receipt does not match the preview");
  }
  return receipt;
}
