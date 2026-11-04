// Exercises the renderer's view of an in-app installation against a scripted
// host. The host owns the installation; these tests pin what the dashboard
// shows for each release and phase, and the exact shape of a host failure.
// support/update-install-harness.mjs holds the scripted host.
import assert from "node:assert/strict";
import { t } from "../src/i18n.js";
import {
  IDLE_UPDATE_INSTALL, installAfterCheck, normalizeInstallFailure,
} from "../src/update-install.js";
import {
  CANCELLED, INSTALL_OFFER, NETWORK, NEWER, NOTHING_PRESENTED, READY, UNAUTHENTIC, UNEXPECTED,
  UPDATE, failed, failure, macFailureText, macUpdateInstallView, test, withdrawn,
} from "./support/update-install-harness.mjs";

test("an installable release offers the installation and keeps the download page", () => {
  const view = macUpdateInstallView(UPDATE, IDLE_UPDATE_INSTALL);
  assert.deepEqual(view, {
    status: null, primary: INSTALL_OFFER, cancel: false, busy: false, offerDownloadPage: true,
  });
});

test("a copy that cannot replace itself is offered only the download page", () => {
  for (const install of [{ supported: false, code: "not_in_applications" }, null, undefined]) {
    const view = macUpdateInstallView({ ...UPDATE, install }, IDLE_UPDATE_INSTALL);
    assert.equal(view.primary, null);
    assert.equal(view.offerDownloadPage, true);
    assert.equal(view.busy, false);
  }
  assert.equal(macUpdateInstallView({ available: false }, IDLE_UPDATE_INSTALL).primary, null);
  assert.equal(macUpdateInstallView(null, IDLE_UPDATE_INSTALL).primary, null);
});

test("download and verification show progress, allow cancellation and block other actions", () => {
  const downloading = { ...IDLE_UPDATE_INSTALL, phase: "downloading", version: "0.5.0", downloaded: 30, total: 120 };
  assert.deepEqual(macUpdateInstallView(UPDATE, downloading), {
    status: t("Downloading update… {percent}%", { percent: 25 }),
    primary: null, cancel: true, busy: true, offerDownloadPage: false,
  });
  assert.equal(
    macUpdateInstallView(UPDATE, { ...downloading, total: null }).status,
    t("Downloading update…"),
  );
  assert.equal(
    macUpdateInstallView(UPDATE, { ...downloading, downloaded: 500 }).status,
    t("Downloading update… {percent}%", { percent: 100 }),
    "a reply that overshoots its announced size never shows more than 100%",
  );
  assert.deepEqual(macUpdateInstallView(UPDATE, { ...downloading, phase: "verifying" }), {
    status: t("Verifying update…"),
    primary: null, cancel: true, busy: true, offerDownloadPage: false,
  });
});

test("a staged release asks for the disconnecting step explicitly", () => {
  assert.deepEqual(macUpdateInstallView(UPDATE, READY), {
    status: t("v{version} is ready to install. Clash for Mac will stop the core, quit, and reopen.", { version: "0.5.0" }),
    primary: { action: "commit", label: t("Install and Relaunch") },
    cancel: true, busy: false, offerDownloadPage: false,
  });
  const installing = macUpdateInstallView(UPDATE, { ...READY, phase: "installing" });
  assert.equal(installing.primary, null);
  assert.equal(installing.cancel, false);
  assert.equal(installing.busy, true);
});

test("a running or staged installation is shown whatever release is presented", () => {
  for (const phase of ["downloading", "verifying", "ready", "installing"]) {
    const install = { ...IDLE_UPDATE_INSTALL, phase, version: "0.5.0", downloaded: 30, total: 120 };
    const shown = macUpdateInstallView(UPDATE, install);
    assert.notDeepEqual(shown, macUpdateInstallView(UPDATE, IDLE_UPDATE_INSTALL), phase);
    for (const presented of [NEWER, UNAUTHENTIC, NOTHING_PRESENTED, { available: false, error: "offline" }, null]) {
      assert.deepEqual(macUpdateInstallView(presented, install), shown, `${phase}: ${JSON.stringify(presented)}`);
    }
  }
  const staged = macUpdateInstallView(NEWER, READY);
  assert.equal(
    staged.status,
    t("v{version} is ready to install. Clash for Mac will stop the core, quit, and reopen.", { version: "0.5.0" }),
    "the status names the staged release, not the presented one",
  );
  assert.deepEqual(staged.primary, { action: "commit", label: t("Install and Relaunch") });
  assert.equal(staged.cancel, true);
});

test("an attempt that ended without a staged release withdraws both offers", () => {
  const network = failed(NETWORK);
  for (const presented of [UPDATE, NEWER, NOTHING_PRESENTED, null]) {
    assert.deepEqual(
      macUpdateInstallView(presented, network),
      withdrawn(macFailureText(network.failure)),
      `failed: ${JSON.stringify(presented)}`,
    );
    assert.deepEqual(
      macUpdateInstallView(presented, CANCELLED),
      withdrawn(t("Update download cancelled")),
      `cancelled: ${JSON.stringify(presented)}`,
    );
  }
  assert.ok(macUpdateInstallView(UPDATE, network).status.endsWith("(network)"));
});

test("a fresh check supersedes how an earlier attempt ended", () => {
  for (const ended of [failed(NETWORK), { ...CANCELLED }]) {
    for (const presented of [UPDATE, NEWER, NOTHING_PRESENTED]) {
      assert.deepEqual(installAfterCheck(ended, presented), IDLE_UPDATE_INSTALL);
    }
    assert.deepEqual(macUpdateInstallView(UPDATE, installAfterCheck(ended, UPDATE)), {
      status: null, primary: INSTALL_OFFER, cancel: false, busy: false, offerDownloadPage: true,
    });
  }
});

test("a check never disturbs a running or staged installation", () => {
  for (const phase of ["downloading", "verifying", "ready", "installing"]) {
    const install = {
      ...IDLE_UPDATE_INSTALL, phase, version: "0.5.0", downloaded: 30, total: 120,
      failure: failure("engine_stop_failed", "engine"),
    };
    for (const presented of [UPDATE, NEWER, UNAUTHENTIC, NOTHING_PRESENTED]) {
      assert.equal(installAfterCheck(install, presented), install, `${phase}: ${JSON.stringify(presented)}`);
    }
  }
});

test("an authenticity failure outlives every check that presents the same release", () => {
  const forged = failed(failure("signature_mismatch", "authenticity"));
  const view = macUpdateInstallView(UPDATE, forged);
  assert.deepEqual(view, withdrawn(macFailureText(forged.failure)));
  assert.ok(view.status.endsWith("(signature_mismatch)"));

  for (const presentedAgain of [UPDATE, UNAUTHENTIC, { ...UPDATE, install: null }]) {
    assert.equal(installAfterCheck(forged, presentedAgain), forged, JSON.stringify(presentedAgain));
  }
  for (const other of [NEWER, NOTHING_PRESENTED, { available: false, version: "0.5.0" }]) {
    assert.deepEqual(installAfterCheck(forged, other), IDLE_UPDATE_INSTALL, JSON.stringify(other));
  }
});

test("the host's verdict on a release that failed authentication withdraws both offers", () => {
  const verdict = macFailureText(failure("release_failed_authentication", "authenticity"));
  assert.deepEqual(macUpdateInstallView(UNAUTHENTIC, IDLE_UPDATE_INSTALL), withdrawn(verdict));
  assert.equal(
    verdict,
    `${t("The downloaded update is not the signed release and was discarded. Do not install it from another source.")} (release_failed_authentication)`,
  );
  assert.equal(
    macUpdateInstallView({ ...UNAUTHENTIC, install: { supported: true, code: "release_failed_authentication" } }, IDLE_UPDATE_INSTALL).primary,
    null,
    "the verdict wins over a contradictory support flag",
  );
  assert.equal(
    macUpdateInstallView({ ...UNAUTHENTIC, available: false }, IDLE_UPDATE_INSTALL).status,
    null,
    "a verdict on a release that is not presented says nothing",
  );
  assert.equal(
    macUpdateInstallView({ ...UPDATE, install: { supported: false, code: "not_in_applications" } }, IDLE_UPDATE_INSTALL).offerDownloadPage,
    true,
    "any other reason leaves the download page",
  );
});

test("host failures are accepted only in their exact shape", () => {
  assert.deepEqual(
    normalizeInstallFailure({ code: "archive_layout_invalid", category: "package" }),
    failure("archive_layout_invalid", "package"),
  );
  assert.deepEqual(
    normalizeInstallFailure({ code: "network", category: "network", detail: "ignored", attempts: 3 }),
    failure("network", "network"),
    "only the two fields the host defines are kept",
  );
  const categories = ["state", "busy", "environment", "network", "storage", "authenticity", "package", "engine", "internal"];
  const sentences = categories.map((category) => {
    assert.deepEqual(normalizeInstallFailure({ code: "some_code", category }), failure("some_code", category));
    return macFailureText(failure("some_code", category));
  });
  assert.equal(new Set(sentences).size, categories.length, "every category has its own sentence");
  for (const sentence of sentences) assert.ok(sentence.endsWith(" (some_code)"), sentence);
  assert.equal(
    macFailureText(failure("install_already_active", "busy")),
    `${t("Another update operation is in progress. Try again in a moment.")} (install_already_active)`,
  );

  for (const invalid of [
    null, undefined, "network", new Error("boom"),
    { code: "network", category: "unknown" },
    { code: "network", category: ["network"] },
    { code: "<script>", category: "network" },
    { code: "", category: "network" },
    { code: "x".repeat(65), category: "network" },
    { code: "network", category: "__proto__" },
    { category: "network" },
  ]) {
    assert.deepEqual(normalizeInstallFailure(invalid), UNEXPECTED, JSON.stringify(invalid));
  }
  assert.ok(macFailureText(UNEXPECTED).endsWith("(unexpected_error)"));
  assert.ok(macFailureText(UNEXPECTED, "bridge closed").endsWith("(unexpected_error: bridge closed)"));
});
