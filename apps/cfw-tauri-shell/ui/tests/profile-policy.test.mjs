import assert from "node:assert/strict";
import test from "node:test";

import { savedProfilePolicy } from "../src/profile-policy.js";

test("automatic groups remain automatic while offline and do not invent a selected or healthy node", () => {
  for (const [type, label] of [["urltest", "URLTest"], ["fallback", "Fallback"]]) {
  const view = savedProfilePolicy({ id: "profile", name: "Auto", proxy_selections: { Auto: "Node" }, body: JSON.stringify({ outbounds: [
    { type: "socks5", tag: "Node" },
    { type, tag: "Auto", outbounds: ["Node"] },
  ] }) });
  assert.equal(view.groups[0].type, label);
  assert.equal(view.groups[0].now, null);
  assert.equal(view.groups[0].options[0].delay, null);
  }
});

test("saved nodes and rules remain visible without inventing live state or exposing credentials", () => {
  const view = savedProfilePolicy({ id: "profile", name: "Work", source_url: "https://example.com/private-token", body: JSON.stringify({
    outbounds: [
      { type: "socks5", tag: "Node", server: "private-endpoint.example", server_port: 1080, authentication: { password_credential_ref: "private-reference" }, network: "tcp" },
      { type: "direct", tag: "DIRECT" },
      { type: "selector", tag: "PROXY", outbounds: ["Node", "DIRECT"], default: "DIRECT" },
    ],
    route: { final: "PROXY", rules: [{ type: "process_name", value: "Example Client", outbound: "PROXY" }] },
  }) });
  assert.equal(view.groups[0].name, "PROXY");
  assert.equal(view.groups[0].now, "DIRECT");
  assert.equal(view.groups[0].options[0].udp, false);
  assert.equal(view.groups[0].options[0].delay, null);
  assert.equal(view.rules[0].type, "PROCESS-NAME");
  assert.equal(view.rules[1].type, "MATCH");
  assert.equal(view.rules[0].hits, "—");
  const serialized = JSON.stringify(view);
  for (const privateValue of ["private-token", "private-endpoint", "private-reference"]) assert.ok(!serialized.includes(privateValue));
  assert.throws(() => savedProfilePolicy({ id: "profile", body: "{}" }), /no outbound/u);
});

test("saved node choice overrides the imported default without rewriting the document", () => {
  const body = JSON.stringify({outbounds: [
    {type: "direct", tag: "DIRECT"}, {type: "block", tag: "REJECT"},
    {type: "selector", tag: "PROXY", outbounds: ["DIRECT", "REJECT"], default: "DIRECT"},
  ]});
  const view = savedProfilePolicy({id: "work", name: "Work", body, proxy_selections: {PROXY: "REJECT"}});
  assert.equal(view.groups[0].now, "REJECT");
  assert.equal(JSON.parse(body).outbounds[2].default, "DIRECT");
});

test("GEOSITE rules are labelled and are not country rules", () => {
  const policy = savedProfilePolicy({ id: "p", name: "Profile", body: JSON.stringify({
    outbounds: [{ type: "socks5", tag: "Node", server: "node.example.com", server_port: 1080 }, { type: "direct", tag: "DIRECT" }],
    route: { final: "Node", rules: [
      { type: "geo_site", value: "cn", outbound: "DIRECT" },
      { type: "geo_ip", value: "CN", outbound: "DIRECT" },
      { type: "domain_suffix", value: "example.com", outbound: "Node" },
    ] },
  }) });
  assert.deepEqual(policy.rules.map((rule) => rule.type), ["GEOSITE", "GEOIP", "DOMAIN-SUFFIX", "MATCH"]);
  assert.deepEqual(policy.geoipCountries, ["CN"]);
});

test("a malformed saved profile is refused, never shown as an empty policy", () => {
  const refuse = (profile, message) => assert.throws(() => savedProfilePolicy(profile), { name: "TypeError", message });
  refuse(null, "saved profile response is invalid");
  refuse({ id: 7, body: "{}" }, "saved profile response is invalid");
  refuse({ id: "profile", body: null }, "saved profile response is invalid");
  refuse({ id: "profile", body: JSON.stringify({}) }, "saved profile has no outbound policy");
  refuse({ id: "profile", body: JSON.stringify({ outbounds: [] }) }, "saved profile has no outbound policy");
  refuse({ id: "profile", body: JSON.stringify({ outbounds: [{ type: "direct" }] }) }, "saved outbound is invalid");
  refuse({ id: "profile", body: JSON.stringify({ outbounds: [{ tag: "x", type: 1 }] }) }, "saved outbound is invalid");
  refuse({ id: "profile", body: JSON.stringify({ outbounds: [{ tag: "Proxy", type: "selector" }] }) }, "saved group has no members");
  refuse({ id: "profile", body: JSON.stringify({ outbounds: [{ tag: "Proxy", type: "selector", outbounds: [] }] }) }, "saved group has no members");
});
