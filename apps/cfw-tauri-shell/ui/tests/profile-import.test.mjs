import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

import {
  MAX_PROFILE_SOURCE_BYTES,
  PROFILE_SOURCE_ACCEPT,
  isProfileSourcePath,
  isSubscriptionSource,
  readProfileSourceFile,
} from "../src/profile-import.js";

test("subscription URLs and node links use distinct native import boundaries", () => {
  assert.equal(isSubscriptionSource("https://subscription.example/list?token=synthetic"), true);
  assert.equal(isSubscriptionSource("HTTPS://subscription.example/list"), true);
  assert.equal(isSubscriptionSource("http://subscription.example/list"), true, "native HTTPS policy must reject HTTP");
  for (const source of ["socks://user:password@proxy.example:1080", "socks5://proxy.example:1080", "trojan://password@proxy.example:443", "file:///private/source", "not-a-link"]) {
    assert.equal(isSubscriptionSource(source), false, "local parser must not fetch non-HTTP sources");
  }
});

test("file picker and drag-drop admit supported profile source extensions", () => {
  for (const extension of ["json", "yaml", "yml", "txt"]) {
    assert.ok(PROFILE_SOURCE_ACCEPT.split(",").includes(`.${extension}`));
    assert.equal(isProfileSourcePath(`/private/source.${extension.toUpperCase()}`), true);
  }
  for (const path of ["/private/workbook.xlsx", "/private/document.pdf", "/private/source.yaml.zip"]) {
    assert.equal(isProfileSourcePath(path), false);
  }
});

test("local reads preserve credential UTF-8 bytes and never use lossy File.text", async () => {
  const body = "socks5:// synthetic-user : 密码 :???@proxy.example:1080";
  const file = new File([body], "nodes.txt");
  file.text = () => { assert.fail("lossy text reader must not run"); };
  assert.equal(await readProfileSourceFile(file), body);
  const invalid = new File([new Uint8Array([0xc3, 0x28])], "nodes.yaml");
  await assert.rejects(readProfileSourceFile(invalid), /must be UTF-8/);
});

test("oversized sources and Excel files fail before allocation", async () => {
  let reads = 0;
  const file = {
    name: "source.txt",
    size: MAX_PROFILE_SOURCE_BYTES + 1,
    arrayBuffer: () => { reads += 1; assert.fail("oversized source must not be read"); },
  };
  await assert.rejects(readProfileSourceFile(file), /byte limit/);
  assert.equal(reads, 0);
  await assert.rejects(readProfileSourceFile({ ...file, size: 1, name: "nodes.xlsx" }), /Excel workbooks/);
  const exact = new File(["x".repeat(MAX_PROFILE_SOURCE_BYTES)], "source.txt");
  assert.equal((await readProfileSourceFile(exact)).length, MAX_PROFILE_SOURCE_BYTES);
  const understated = { name: "source.txt", size: 1, arrayBuffer: async () => new ArrayBuffer(MAX_PROFILE_SOURCE_BYTES + 1) };
  await assert.rejects(readProfileSourceFile(understated), /byte limit/);
});

test("file read failures remain observable and source limits match native admission", async () => {
  const failure = new Error("source read was aborted");
  await assert.rejects(readProfileSourceFile({ name: "source.txt", size: 1, arrayBuffer: async () => { throw failure; } }), (error) => error === failure);
  const native = readFileSync(new URL("../../src/subscription_import.rs", import.meta.url), "utf8");
  assert.match(native, /MAX_SUBSCRIPTION_DOCUMENT_BYTES: usize = 512 \* 1024;/u);
  assert.equal(MAX_PROFILE_SOURCE_BYTES, 512 * 1024);
});
