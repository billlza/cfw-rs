import assert from "node:assert/strict";
import test from "node:test";

import {
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

test("credential references must be immutable UUIDs of a known kind", () => {
  assert.deepEqual(normalizeCredentialReferences([FIRST, SECOND]), [FIRST, SECOND]);
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

test("credential kinds are labelled for a person, not for a schema", () => {
  assert.equal(credentialLabel("hysteria2_obfs_password"), "Hysteria2 Obfs Password");
  assert.equal(credentialLabel("vmess_uuid"), "Vmess Uuid");
});
