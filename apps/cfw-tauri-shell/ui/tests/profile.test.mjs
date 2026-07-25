import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ProfileDeletionConflictError,
  cancelCredentialGc,
  commitCredentialGc,
  openProfileCredentialSetup,
  provisionProfileCredentials,
  previewCredentialGc,
  reconcileProfileImport,
  reconcileProfileDeletion,
  reconcileProfileSelection,
  runProfileRepositoryMutation,
  validateSingBoxProfileText,
} from "../src/profiles.js";
import { store } from "../src/store.js";

test("accepts a bounded sing-box routing profile", () => {
  const profile = validateSingBoxProfileText(JSON.stringify({
    outbounds: [{ type: "direct", tag: "direct" }],
    route: { final: "direct" },
  }));
  assert.equal(profile.route.final, "direct");
});

test("accepts typed credential references without accepting raw secrets", () => {
  const fixture = readFileSync(
    new URL("../../../../contracts/typed-profile-v1.json", import.meta.url),
    "utf8",
  );
  const profile = validateSingBoxProfileText(fixture);
  assert.equal(profile.outbounds[0].credential_ref.kind, "vmess_uuid");
  assert.equal(profile.outbounds[0].transport.path, "/transport");
  assert.equal(profile.outbounds[0].transport.headers.Host, "vmess.example.com");
  assert.equal(profile.outbounds[1].tls.reality.enabled, true);
  assert.throws(
    () => validateSingBoxProfileText(JSON.stringify({
      outbounds: [{ type: "vless", tag: "proxy", uuid: "raw-secret" }],
    })),
    /Credential requires shared Keychain support/u,
  );
});

test("rejects legacy, executable and non-JSON profiles", () => {
  const unsafeProfiles = [
    '{"inbounds":[]}',
    '{"route":{"script":"ignored"}}',
    '{"route":{"command":"/bin/sh"}}',
    '{"certificate":{"certificate_path":"/tmp/untrusted.pem"}}',
    '{"route":{"rules":[{"process_path_regex":".*"}]}}',
    '{"route":{"rule_set":[{"type":"remote","url":"http://169.254.169.254/latest"}]}}',
    '{"outbounds":[{"type":"urltest","download_url":"https://example.test"}]}',
    '{"outbounds":[{"type":"socks","password":"not-on-disk"}]}',
    '{"outbounds":[{"type":"vmess","uuid":"not-on-disk"}]}',
    '{"dns":{"servers":[{"address":"https://169.254.169.254"}]},"outbounds":[{"type":"direct","tag":"direct"}]}',
    '{"outbounds":[{"type":"hysteria","tag":"proxy","auth_str":"secret"}]}',
    '{"outbounds":[{"type":"direct","tag":"direct","tls":{"client_key":"secret"}}]}',
    '{"outbounds":[{"type":"direct","tag":"direct","headers":{"Authorization":"secret"}}]}',
    '{"unknown":true}',
    "proxies: []",
  ];
  for (const profile of unsafeProfiles) {
    assert.throws(() => validateSingBoxProfileText(profile), TypeError);
  }
});

test("rejects profiles larger than four MiB", () => {
  const oversized = JSON.stringify({ route: { final: "x".repeat(384 * 1024) } });
  assert.throws(() => validateSingBoxProfileText(oversized), /384 KiB/u);
});

test("rejects profiles with an excessive node count", () => {
  // Two bytes per node keeps the fixture well under the 384 KiB byte ceiling so
  // the rejection can only come from the node budget, mirroring the
  // authoritative Rust validator contract.
  const complex = JSON.stringify({ route: { rules: Array.from({ length: 100_001 }, () => 0) } });
  assert.ok(new TextEncoder().encode(complex).byteLength < 384 * 1024);
  assert.throws(() => validateSingBoxProfileText(complex), /too complex/u);
});

test("reports a stale profile deletion instead of logging false success", async () => {
  const calls = { reload: 0, log: 0 };
  await assert.rejects(
    reconcileProfileDeletion(
      { id: "profile-1", name: "Race" },
      false,
      {
        reload: async () => { calls.reload += 1; },
        log: () => { calls.log += 1; },
      },
    ),
    (error) => error instanceof ProfileDeletionConflictError && error.profileId === "profile-1",
  );
  assert.deepEqual(calls, { reload: 1, log: 0 });
});

test("rejects a malformed native deletion result without refreshing or logging", async () => {
  const calls = { reload: 0, log: 0 };
  await assert.rejects(
    reconcileProfileDeletion(
      { id: "profile-1", name: "Malformed" },
      null,
      {
        reload: async () => { calls.reload += 1; },
        log: () => { calls.log += 1; },
      },
    ),
    /must be a boolean/u,
  );
  assert.deepEqual(calls, { reload: 0, log: 0 });
});

test("resnapshots after an import failure before allowing a user retry", async () => {
  const calls = { reload: 0, log: 0 };
  const commitUncertain = new Error("commit state must be resnapshotted before retry");
  await assert.rejects(
    reconcileProfileImport(
      "Profile.json",
      async () => { throw commitUncertain; },
      {
        reload: async () => { calls.reload += 1; },
        log: () => { calls.log += 1; },
      },
    ),
    (error) => error === commitUncertain,
  );
  assert.deepEqual(calls, { reload: 1, log: 0 });
});

test("resnapshots commit-uncertain selection and deletion failures", async () => {
  for (const operation of ["select", "delete"]) {
    const calls = { reload: 0 };
    const commitUncertain = new Error(`${operation} commit is uncertain`);
    await assert.rejects(
      runProfileRepositoryMutation(
        async () => { throw commitUncertain; },
        { reload: async () => { calls.reload += 1; } },
      ),
      (error) => error === commitUncertain,
    );
    assert.deepEqual(calls, { reload: 1 });
  }
});

test("preserves both mutation and reconciliation failures", async () => {
  const mutation = new Error("mutation failed");
  const reload = new Error("reload failed");
  await assert.rejects(
    runProfileRepositoryMutation(
      async () => { throw mutation; },
      { reload: async () => { throw reload; } },
    ),
    (error) => error instanceof AggregateError
      && error.errors[0] === mutation
      && error.errors[1] === reload,
  );
});

test("accepts only an identity-matched active selection response", async () => {
  const calls = { reload: 0, log: 0 };
  const profile = { id: "profile-1", name: "Profile" };
  await reconcileProfileSelection(
    profile,
    {
      id: "profile-1",
      name: "Profile",
      active: true,
      bytes: 10,
      updated_epoch_secs: 1,
    },
    {
      reload: async () => { calls.reload += 1; },
      log: () => { calls.log += 1; },
    },
  );
  assert.deepEqual(calls, { reload: 1, log: 1 });

  await assert.rejects(
    reconcileProfileSelection(
      profile,
      {
        id: "profile-2",
        name: "Other",
        active: true,
        bytes: 10,
        updated_epoch_secs: 1,
      },
      {
        reload: async () => { calls.reload += 1; },
        log: () => { calls.log += 1; },
      },
    ),
    /does not match/u,
  );
  assert.deepEqual(calls, { reload: 1, log: 1 });
});

test("provisions the exact credential set once and clears renderer-held secrets", async () => {
  const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const requirements = [
    { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", kind: "trojan_password" },
    { id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", kind: "hysteria2_obfs_password" },
  ];
  store.update({
    profileCredentialSetup: { profileId, profileName: "Secure", requirements },
  });
  const entries = [
    { ...requirements[0], secret: "first-secret" },
    { ...requirements[1], secret: "second-secret" },
  ];
  let submitted;
  await provisionProfileCredentials(profileId, entries, {
    provision: async (request) => {
      submitted = structuredClone(request);
      return { profile_id: profileId };
    },
    log: () => {},
  });

  assert.deepEqual(submitted, {
    profileId,
    credentials: [
      { reference: requirements[0], secret: "first-secret" },
      { reference: requirements[1], secret: "second-secret" },
    ],
  });
  assert.deepEqual(entries.map(({ secret }) => secret), ["", ""]);
  assert.equal(store.get().profileCredentialSetup, null);
});

test("credential setup requests only missing references and never re-prompts present entries", async () => {
  const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const present = { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", kind: "trojan_password" };
  const missing = { id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", kind: "vless_uuid" };
  store.update({
    profiles: [{ id: profileId, name: "Mixed" }],
    profileCredentialSetup: null,
  });

  const result = await openProfileCredentialSetup(profileId, {
    fetchRequirements: async () => [present, missing],
    queryPresence: async () => [
      { reference: present, present: true },
      { reference: missing, present: false },
    ],
    log: () => assert.fail("mixed presence must open setup rather than log readiness"),
  });

  assert.deepEqual(result, [missing]);
  assert.deepEqual(store.get().profileCredentialSetup, {
    profileId,
    profileName: "Mixed",
    requirements: [missing],
    requiredCount: 2,
    presentCount: 1,
    vaultAvailable: true,
  });
});

test("credential presence failure is not converted into false missing state", async () => {
  const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const reference = { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", kind: "trojan_password" };
  const unavailable = new Error("vault unavailable");
  store.update({
    profiles: [{ id: profileId, name: "Unavailable" }],
    profileCredentialSetup: null,
  });

  await assert.rejects(
    openProfileCredentialSetup(profileId, {
      fetchRequirements: async () => [reference],
      queryPresence: async () => { throw unavailable; },
    }),
    (error) => error === unavailable,
  );
  assert.deepEqual(store.get().profileCredentialSetup, {
    profileId,
    profileName: "Unavailable",
    requirements: [],
    requiredCount: 1,
    presentCount: null,
    vaultAvailable: false,
  });
});

test("clears renderer-held secrets when validation or native provisioning fails", async () => {
  const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const requirement = {
    id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    kind: "trojan_password",
  };
  store.update({
    profileCredentialSetup: {
      profileId,
      profileName: "Secure",
      requirements: [requirement],
    },
  });
  const invalid = [{ ...requirement, secret: "contains\ncontrol" }];
  await assert.rejects(
    provisionProfileCredentials(profileId, invalid, { provision: async () => assert.fail() }),
    /contains control/u,
  );
  assert.equal(invalid[0].secret, "");

  const nativeFailure = new Error("vault unavailable");
  const rejected = [{ ...requirement, secret: "ephemeral-value" }];
  await assert.rejects(
    provisionProfileCredentials(profileId, rejected, {
      provision: async () => { throw nativeFailure; },
    }),
    (error) => error === nativeFailure,
  );
  assert.equal(rejected[0].secret, "");
  assert.equal(store.get().profileCredentialSetup.profileId, profileId);
});

test("credential GC requires an exact preview and one-shot matching commit receipt", async () => {
  const previewId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const orphan = {
    id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    kind: "trojan_password",
  };
  const preview = await previewCredentialGc({
    preview: async () => ({
      preview_id: previewId,
      orphan_count: 1,
      orphan_references: [orphan],
    }),
    log: () => assert.fail("non-empty preview must not log no-op success"),
  });
  assert.deepEqual(preview, {
    previewId,
    orphanCount: 1,
    orphanReferences: [orphan],
  });

  let committed;
  await commitCredentialGc(previewId, {
    commit: async (id) => {
      committed = id;
      return { removed_count: 1 };
    },
    log: () => {},
  });
  assert.equal(committed, previewId);
  assert.equal(store.get().credentialGcPreview, null);
});

test("credential GC drops stale authority after commit failure or explicit cancel", async () => {
  const previewId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const preview = {
    previewId,
    orphanCount: 1,
    orphanReferences: [{
      id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      kind: "trojan_password",
    }],
  };
  store.update({ credentialGcPreview: preview });
  const stale = new Error("repository snapshot changed");
  await assert.rejects(
    commitCredentialGc(previewId, { commit: async () => { throw stale; } }),
    (error) => error === stale,
  );
  assert.equal(store.get().credentialGcPreview, null);

  store.update({ credentialGcPreview: preview });
  let cancelled;
  await cancelCredentialGc(previewId, {
    cancel: async (id) => { cancelled = id; },
  });
  assert.equal(cancelled, previewId);
  assert.equal(store.get().credentialGcPreview, null);
});

test("credential GC rejects malformed or duplicate orphan previews", async () => {
  const reference = {
    id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    kind: "trojan_password",
  };
  await assert.rejects(
    previewCredentialGc({
      preview: async () => ({
        preview_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        orphan_count: 2,
        orphan_references: [reference, reference],
      }),
    }),
    /duplicate references/u,
  );
});
