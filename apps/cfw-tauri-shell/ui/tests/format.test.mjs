import assert from "node:assert/strict";
import test from "node:test";

import { formatUpdateProgress, redactDiagnosticText } from "../src/format.js";

test("formats updater progress using the native total field", () => {
  assert.equal(
    formatUpdateProgress({ downloaded: 512, total: 1024 }),
    "Downloaded 512 of 1024 bytes",
  );
  assert.equal(formatUpdateProgress({ downloaded: 512, total: null }), "Downloaded 512 bytes");
  assert.equal(formatUpdateProgress({ downloaded: -1, total: 1024 }), null);
  assert.equal(
    formatUpdateProgress({ phase: "stopping-network", downloaded: 1024, total: 1024 }),
    "Stopping the network engine before installing the update",
  );
});

test("redacts GitHub, AWS, and Azure signed URL credentials", () => {
  const secrets = [
    "github-sig",
    "generic-signature",
    "aws-signature",
    "aws-credential",
    "azure-expiry",
    "azure-permission",
    "azure-version",
    "detached-signature",
  ];
  const diagnostic = redactDiagnosticText(
    "https://example.test/archive?sig=github-sig&signature=generic-signature"
      + "&X-Amz-Signature=aws-signature&X-Amz-Credential=aws-credential"
      + "&se=azure-expiry&sp=azure-permission&sv=azure-version"
      + " signature=detached-signature",
  );

  for (const secret of secrets) assert.equal(diagnostic.includes(secret), false);
  assert.equal(diagnostic.match(/\[redacted\]/gu)?.length, secrets.length);
});
