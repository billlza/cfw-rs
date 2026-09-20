// Display only saved routing policy. No controller status, credential values,
// server addresses or subscription URLs are part of this view.
export function savedProfilePolicy(profile) {
  if (!profile || typeof profile.id !== "string" || typeof profile.body !== "string") {
    throw new TypeError("saved profile response is invalid");
  }
  const document = JSON.parse(profile.body);
  if (!Array.isArray(document.outbounds) || document.outbounds.length === 0) {
    throw new TypeError("saved profile has no outbound policy");
  }
  const labels = new Map((document.providers?.proxies ?? []).flatMap((provider) =>
    provider.members.map((member) => [member.tag, `${member.name} · ${provider.name}`])));
  const nodes = new Map(document.outbounds.map((outbound) => {
    if (typeof outbound.tag !== "string" || typeof outbound.type !== "string") {
      throw new TypeError("saved outbound is invalid");
    }
    return [outbound.tag, { name: outbound.tag, label: labels.get(outbound.tag) ?? outbound.tag, kind: outbound.type, udp: outbound.type !== "http" && outbound.network !== "tcp", delay: null }];
  }));
  const groups = document.outbounds.filter(({ type, hidden }) => !hidden && ["selector", "urltest", "fallback", "loadbalance"].includes(type)).map((outbound) => {
    if (!Array.isArray(outbound.outbounds) || outbound.outbounds.length === 0) {
      throw new TypeError("saved group has no members");
    }
    return {
      name: outbound.tag,
      type: {selector: "Selector", urltest: "URLTest", fallback: "Fallback", loadbalance: "LoadBalance"}[outbound.type],
      now: outbound.type !== "selector" ? null : profile.proxy_selections?.[outbound.tag] ?? outbound.default ?? outbound.outbounds[0],
      options: outbound.outbounds.map((name) => {
        const node = nodes.get(name);
        if (!node) throw new TypeError("saved selector member is missing");
        return node;
      }),
    };
  });
  if (groups.length === 0) {
    groups.push({ name: "Configured nodes", type: "List", now: document.route?.final ?? document.outbounds[0].tag, options: [...nodes.values()] });
  }
  const rules = (document.route?.rules ?? []).map((rule, index) => ({
    index: String(index + 1),
    type: rule.type === "geo_ip" ? "GEOIP" : rule.type.replaceAll("_", "-").toUpperCase(),
    payload: rule.value,
    proxy: rule.outbound,
    hits: "—",
  }));
  if (document.route?.final) {
    rules.push({ index: String(rules.length + 1), type: "MATCH", payload: "", proxy: document.route.final, hits: "—" });
  }
  const geoipCountries = [...new Set(rules.filter((rule) => rule.type === "GEOIP" && rule.payload !== "LAN").map((rule) => rule.payload))];
  return { profileId: profile.id, name: profile.name, groups, rules, geoipCountries, nodeLabels: Object.fromEntries(labels) };
}
