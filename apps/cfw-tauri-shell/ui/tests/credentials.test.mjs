import assert from "node:assert/strict";
import test from "node:test";

import {
  CREDENTIAL_KINDS,
  credentialLabel,
  credentialProvisionBatch,
  normalizeCredentialGcPreview,
  normalizeCredentialPresence,
  normalizeCredentialReferences,
  normalizeCredentialReceipt,
  normalizeGcReceipt,
} from "../src/credentials.js";

const FIRST = { id: "34db18b6-9903-4e9f-8854-15648e19e4f3", kind: "trojan_password" };
const SECOND = { id: "5d1f4e9c-1c1a-4a2b-8f3d-2b6f9c0a7e11", kind: "vmess_uuid" };
const ANYTLS = { id: "6e2f5a7c-8d91-4b3a-9c52-0a1b2c3d4e5f", kind: "anytls_password" };
const TUIC_UUID = { id: "7f3a6b8d-9e12-4c4b-ad63-1b2c3d4e5f60", kind: "tuic_uuid" };
const TUIC_PASSWORD = { id: "8a4b7c9e-0f23-4d5c-be74-2c3d4e5f6071", kind: "tuic_password" };

test("credential references must be immutable UUIDs of a known kind", () => {
  assert.deepEqual(
    normalizeCredentialReferences([FIRST, SECOND, ANYTLS, TUIC_UUID, TUIC_PASSWORD]),
    [FIRST, SECOND, ANYTLS, TUIC_UUID, TUIC_PASSWORD],
  );
  assert.deepEqual(CREDENTIAL_KINDS.slice(-3), ["anytls_password", "tuic_uuid", "tuic_password"]);
  assert.deepEqual(normalizeCredentialReferences([]), []);
  for (const rejected of [
    [{ id: "not-a-uuid", kind: "trojan_password" }],
    [{ id: FIRST.id, kind: "root_shell" }],
    [{ id: FIRST.id }],
    [FIRST, FIRST],
    "nope",
  ]) {
    assert.throws(() => normalizeCredentialReferences(rejected), /credential/u);
  }
});

test("presence results must answer exactly the profile's references, in order", () => {
  const presence = normalizeCredentialPresence(
    [{ reference: FIRST, present: true }, { reference: SECOND, present: false }],
    [FIRST, SECOND],
  );
  assert.deepEqual(presence.map(({ present }) => present), [true, false]);

  assert.throws(
    () => normalizeCredentialPresence([{ reference: FIRST, present: true }], [FIRST, SECOND]),
    /incomplete/u,
  );
  assert.throws(
    () => normalizeCredentialPresence(
      [{ reference: SECOND, present: true }, { reference: FIRST, present: true }],
      [FIRST, SECOND],
    ),
    /does not match/u,
  );
  assert.throws(
    () => normalizeCredentialPresence([{ reference: FIRST }], [FIRST]),
    /invalid/u,
  );
});

test("a provisioning batch must supply every missing reference at once", () => {
  const batch = credentialProvisionBatch([FIRST, SECOND], ["one", "two"]);
  assert.deepEqual(batch, [
    { reference: FIRST, secret: "one" },
    { reference: SECOND, secret: "two" },
  ]);
  assert.throws(() => credentialProvisionBatch([FIRST, SECOND], ["one"]), /at once/u);
  assert.throws(() => credentialProvisionBatch([FIRST], [""]), /required/u);
  assert.throws(() => credentialProvisionBatch([FIRST], ["bad\u0085secret"]), /control characters/u);
  assert.throws(() => credentialProvisionBatch([FIRST], ["a\u0000b"]), /control characters/u);
  assert.throws(() => credentialProvisionBatch([FIRST], ["x".repeat(16 * 1024 + 1)]), /16 KiB/u);
  assert.throws(() => credentialProvisionBatch([FIRST], [42]), /invalid/u);
});

test("a receipt must belong to the profile that was provisioned", () => {
  assert.doesNotThrow(() => normalizeCredentialReceipt({ profile_id: "p1" }, "p1"));
  assert.throws(() => normalizeCredentialReceipt({ profile_id: "p2" }, "p1"), /does not match/u);
  assert.throws(() => normalizeCredentialReceipt(null, "p1"), /does not match/u);
});

test("a cleanup preview must be internally consistent before it is shown", () => {
  const preview = normalizeCredentialGcPreview({
    preview_id: "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b",
    orphan_count: 1,
    orphan_references: [FIRST],
  });
  assert.equal(preview.orphanCount, 1);
  assert.deepEqual(preview.orphanReferences, [FIRST]);

  assert.throws(
    () => normalizeCredentialGcPreview({
      preview_id: "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b",
      orphan_count: 2,
      orphan_references: [FIRST],
    }),
    /invalid/u,
  );
  assert.throws(() => normalizeCredentialGcPreview({ preview_id: "nope", orphan_count: 0, orphan_references: [] }), /invalid/u);
  assert.doesNotThrow(() => normalizeGcReceipt({ removed_count: 1 }, 1));
  assert.throws(() => normalizeGcReceipt({ removed_count: 2 }, 1), /does not match/u);
});

test("cleanup keeps same-reference entries from distinct profile audiences", () => {
  const preview = normalizeCredentialGcPreview({
    preview_id: "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b",
    orphan_count: 2,
    orphan_references: [FIRST, FIRST],
  });
  assert.equal(preview.orphanCount, 2);
  assert.deepEqual(preview.orphanReferences, [FIRST, FIRST]);
});

test("credential kinds are labelled for a person, not for a schema", () => {
  assert.equal(credentialLabel("socks5_username"), "SOCKS5 Username");
  assert.equal(credentialLabel("socks5_password"), "SOCKS5 Password");
  assert.equal(credentialLabel("hysteria2_obfs_password"), "Hysteria2 Obfs Password");
  assert.equal(credentialLabel("vmess_uuid"), "Vmess Uuid");
  assert.equal(credentialLabel("anytls_password"), "AnyTLS Password");
  assert.equal(credentialLabel("tuic_uuid"), "TUIC UUID");
  assert.equal(credentialLabel("tuic_password"), "TUIC Password");
});

test("SOCKS5 credentials preserve text and enforce 255-byte authentication fields", () => {
  const references = normalizeCredentialReferences([
    { id: FIRST.id, kind: "socks5_username" },
    { id: SECOND.id, kind: "socks5_password" },
  ]);
  assert.deepEqual(
    credentialProvisionBatch(references, [" user ", "pass:word@value"]),
    [{ reference: references[0], secret: " user " }, { reference: references[1], secret: "pass:word@value" }],
  );
  for (const reference of references) {
    for (const value of ["x", "x".repeat(255), "界".repeat(85)]) {
      assert.equal(credentialProvisionBatch([reference], [value])[0].secret, value);
    }
    for (const value of ["x".repeat(256), "界".repeat(86)]) {
      assert.throws(() => credentialProvisionBatch([reference], [value]), /255 UTF-8 bytes/u);
    }
    assert.throws(() => credentialProvisionBatch([reference], [""]), /required/u);
    assert.throws(() => credentialProvisionBatch([reference], ["bad\nvalue"]), /control/u);
  }
});
