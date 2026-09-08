import assert from "node:assert/strict";
import test from "node:test";

import { savedProfilePolicy } from "../src/profile-policy.js";

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
