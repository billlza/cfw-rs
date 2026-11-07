import test from "node:test";
import assert from "node:assert/strict";
import { createConnectionDiagnostics } from "../src/connection-diagnostics.js";
import { httpVerdict, normalizedIp, udpComparison } from "../src/connection-diagnostics-model.js";
import { probeWebRtc } from "../src/connection-webrtc.js";

const report = () => ({ observed_at_ms: 1793836800000, route: { kind: "engine_proxy", port: 7890 },
  system_egress: { status: "observed", value: { ip: "192.0.2.1", country: "GB" } },
  routed_egress: { status: "observed", value: { ip: "198.51.100.1", country: "JP" } },
  ipv4: { status: "observed", value: "198.51.100.1" }, ipv6: { status: "failed", reason: "connection_failed" },
  services: [{ name: "Claude", host: "claude.ai", response: { status: "observed", value: { http_status: 403, elapsed_ms: 128 } }, egress: { status: "failed", reason: "http_refused" } }],
});
const setup = (invoke) => {
  const state = { engine: { active: true, generation: 1 }, proxyGroups: [{ name: "default", now: "one" }] };
  const runtime = { engineIdentityEpoch: 1 };
  const view = createConnectionDiagnostics({ state, runtime, invoke, renderPage() {}, requestId: () => "test-request" });
  return { state, runtime, view };
};

test("opening diagnostics is passive; IPs are absent from markup until explicitly revealed", async () => {
  const calls = [];
  const { view } = setup(async (command) => { calls.push(command); return report(); });
  view.render();
  assert.deepEqual(calls, []);
  await view.actions["diagnostic-run"]();
  assert.deepEqual(calls, ["connection_diagnostics"]);
  const hidden = view.render();
  assert.ok(!hidden.includes("192.0.2.1") && !hidden.includes("198.51.100.1"));
  assert.match(hidden, /Access refused or challenged/u);
  assert.doesNotMatch(hidden, /Trust score|No leaks|73/u);
  view.actions["diagnostic-hide"]();
  assert.match(view.render(), /198\.51\.100\.1/u);
});

test("pending requests are deduplicated and engine or selection changes reject their results", async () => {
  let finish;
  let calls = 0;
  const { state, view } = setup(() => { calls++; return new Promise((resolve) => { finish = resolve; }); });
  const running = view.actions["diagnostic-run"]();
  await view.actions["diagnostic-run"]();
  assert.equal(calls, 1);
  state.proxyGroups[0].now = "two";
  finish(report());
  await running;
  assert.match(view.render(), /network configuration changed/u);
  view.actions["diagnostic-hide"]();
  assert.doesNotMatch(view.render(), /198\.51\.100\.1/u);
});

test("cancellation reaches the owned request and a late result never appears", async () => {
  let finish;
  const calls = [];
  const { view } = setup((command, args) => {
    calls.push([command, args]);
    return command === "connection_diagnostics" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve();
  });
  const running = view.actions["diagnostic-run"]();
  await view.actions["diagnostic-cancel"]();
  assert.deepEqual(calls[1], ["cancel_connection_diagnostics", { requestId: "test-request" }]);
  finish(report()); await running;
  assert.match(view.render(), /Cancelled/u);
  assert.doesNotMatch(view.render(), /Service connectivity/u);
});

test("endpoint text is escaped and errors never echo untrusted content", async () => {
  const hostile = report(); hostile.services[0].name = '<img src=x onerror="attack">';
  const { view } = setup(async () => hostile);
  await view.actions["diagnostic-run"]();
  assert.doesNotMatch(view.render(), /<img/u);
  assert.match(view.render(), /&lt;img/u);
  const failed = setup(async () => { throw new Error("token=private <img>"); }).view;
  await failed.actions["diagnostic-run"]();
  assert.doesNotMatch(failed.render(), /token=private|<img/u);
  assert.match(failed.render(), /could not be completed/u);
});

test("HTTP challenges, authentication and throttling do not become availability success", () => {
  assert.equal(httpVerdict(200).tone, "ok");
  for (const code of [302, 401, 403, 429, 503]) assert.notEqual(httpVerdict(code).tone, "ok");
});

test("IP classifications stay attributed, preserve zero and clear the previous result on failure", async () => {
  let click;
  let fail = false;
  const originalDocument = globalThis.document;
  globalThis.document = { querySelectorAll: () => [{ dataset: { diagnosticIp: "0" }, addEventListener: (_event, listener) => { click = listener; } }] };
  const calls = [];
  try {
    const { view } = setup(async (command, args) => {
      calls.push([command, args]);
      if (command === "connection_diagnostics") return report();
      assert.equal(command, "connection_ip_information");
      assert.equal(args.ip, "198.51.100.1");
      if (fail) throw new Error("provider_rate_limited");
      return { ip: args.ip, company: "<img src=x>", isp: "Example", asn: "AS64496", city: null, region: null, country: "Japan", timezone: "Asia/Tokyo",
        risk: { is_mobile: false, is_vpn: false, is_tor: false, is_proxy: false, is_datacenter: false, risk_score: 0 } };
    });
    await view.actions["diagnostic-run"]();
    assert.equal(calls.length, 1);
    view.bindPage(); await click();
    const result = view.render();
    assert.match(result, /IPQuery risk score<\/dt><dd>0<\/dd>/u);
    assert.match(result, /Not marked by source/u);
    assert.match(result, /not a risk probability or an official Claude score/u);
    assert.match(result, /ipquery\.io\/sources/u);
    assert.doesNotMatch(result, /198\.51\.100\.1|<img/u);
    fail = true;
    await click();
    assert.match(view.render(), /refused further lookups/u);
    assert.doesNotMatch(view.render(), /IPQuery risk score<\/dt>|Not marked by source/u);
  } finally {
    if (originalDocument === undefined) delete globalThis.document;
    else globalThis.document = originalDocument;
  }
});

test("UDP comparisons normalize IPv6 and do not compare different address families", () => {
  assert.equal(normalizedIp("2001:db8::1"), normalizedIp("2001:0DB8:0:0:0:0:0:1"));
  assert.equal(normalizedIp("2001:::1"), null);
  assert.equal(normalizedIp("999.1.2.3"), null);
  assert.equal(udpComparison(["2001:db8::1"], report()), "unconfirmed");
  assert.equal(udpComparison(["198.51.100.1"], report()), "matched");
  assert.equal(udpComparison(["198.51.100.1", "2001:db8::1"], report()), "unconfirmed");
  assert.equal(udpComparison(["192.0.2.1"], report()), "different");
});

test("WebRTC is bounded, closes resources, and never treats missing candidates as protection", async () => {
  let peer;
  class Peer {
    closed = false; channelClosed = false;
    constructor() { peer = this; }
    createDataChannel() { return { close: () => { this.channelClosed = true; } }; }
    async createOffer() { return {}; }
    async setLocalDescription() {}
    close() { this.closed = true; }
  }
  const complete = probeWebRtc({ PeerConnection: Peer, timeoutMs: 100 });
  peer.onicecandidate({ candidate: { type: "host", protocol: "udp", address: "192.168.1.2" } });
  peer.onicecandidate({ candidate: null });
  assert.equal((await complete).reason, "no_udp_candidate");
  assert.ok(peer.closed && peer.channelClosed);
  const timed = await probeWebRtc({ PeerConnection: Peer, timeoutMs: 5 });
  assert.equal(timed.status, "failed"); assert.equal(timed.reason, "timeout");
  assert.ok(peer.closed && peer.channelClosed);
  const abort = new AbortController();
  const cancelled = probeWebRtc({ PeerConnection: Peer, signal: abort.signal });
  abort.abort(); assert.equal((await cancelled).reason, "cancelled");
  assert.ok(peer.closed && peer.channelClosed);
  assert.equal((await probeWebRtc({ PeerConnection: null })).status, "unsupported");
});

test("successful WebRTC reports only server-reflexive UDP candidates and closes the peer", async () => {
  let peer;
  class Peer {
    constructor() { peer = this; }
    createDataChannel() { return { close() {} }; }
    async createOffer() { return {}; }
    async setLocalDescription() {}
    close() { this.closed = true; }
  }
  const running = probeWebRtc({ PeerConnection: Peer });
  for (const type of ["host", "srflx", "srflx"]) peer.onicecandidate({ candidate: { type, protocol: "udp", address: "198.51.100.1" } });
  peer.onicecandidate({ candidate: null });
  assert.deepEqual(await running, { status: "observed", addresses: ["198.51.100.1"] });
  assert.equal(peer.closed, true);
});
