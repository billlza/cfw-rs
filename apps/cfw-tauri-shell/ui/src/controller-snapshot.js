// Projects controller snapshots into dashboard state, and clears that state
// when the controller cannot be trusted.
import { state } from "./state.js";
import { formatBytes } from "./text-format.js";
import { latestDelay } from "./proxy-delay.js";
import { isManualProxyGroup } from "./proxies.js";

export function applyControllerSnapshot(snapshot) {
  if (!snapshot) return;

  const config = snapshot.config ?? {};
  const mode = config.mode ? config.mode[0].toUpperCase() + config.mode.slice(1).toLowerCase() : null;
  state.mode = ["Global", "Rule", "Direct"].includes(mode) ? mode : null;
  // Clash API describes the loopback inbound. LAN sharing has its own listener
  // and source policy, whose state comes from the runtime settings transaction.
  state.toggles.allowLan = state.runtimeSettings?.settings.allow_lan ?? false;
  state.logLevel = config["log-level"] ?? config.log_level ?? null;

  const proxyNodes = new Map((snapshot.proxies?.proxies ?? []).map((node) => [node.name, node]));
  const groups = snapshot.proxies?.groups ?? [];
  const groupsByName = new Map(groups.map((group) => [group.name, group]));
  const previousDelays = new Map();
  if (state.toggles.testingDelays) {
    state.proxyGroups.forEach((group) => {
      group.options.forEach((node) => {
        previousDelays.set(node.name, node.delay);
      });
    });
  }
  // Always replace — empty groups must clear stale iKuuu UI after a failed/empty profile.
  state.proxyGroups = groups.map((group) => {
    const projectNode = (name) => {
      const node = proxyNodes.get(name);
      const nestedGroup = groupsByName.get(name);
      let delay = latestDelay(node?.history ?? nestedGroup?.history ?? []);
      if (state.toggles.testingDelays && previousDelays.has(name)) {
        // Keep in-flight Pending / partial results while a delay test runs.
        delay = previousDelays.get(name);
      }
      const measured = state.proxyDelayResults.get(name);
      return {
        name,
        label: state.savedProfilePolicy?.nodeLabels?.[name] ?? name,
        delay: measured ? measured.delay : delay,
        delayFailure: measured?.delayFailure ?? null,
        dead: Boolean(measured?.delayFailure),
        kind: node?.kind ?? node?.type ?? nestedGroup?.kind ?? group.kind ?? "Proxy",
        udp: node?.udp ?? null,
      };
    };
    const options = (group.options ?? []).map(projectNode);
    const observedOption = options.length === 0
      && !isManualProxyGroup(group.kind)
      && typeof group.now === "string"
      && proxyNodes.has(group.now)
      ? projectNode(group.now)
      : null;
    return {
      name: group.name,
      type: group.kind,
      now: group.now ?? group.options?.[0] ?? "DIRECT",
      options,
      observedOption,
    };
  });

  applyConnectionsSnapshot(snapshot.connections);
  state.controllerStatus = "controller live";
}

export function applyConnectionsSnapshot(snapshot) {
  if (!snapshot) return;

  const now = Date.now();
  const elapsed = state.connectionStream.at ? Math.max(0.25, (now - state.connectionStream.at) / 1000) : 0;
  const uploadTotal = snapshot.upload ?? snapshot.uploadTotal ?? snapshot.upload_total ?? 0;
  const downloadTotal = snapshot.download ?? snapshot.downloadTotal ?? snapshot.download_total ?? 0;
  const previousRows = state.connectionStream.rows ?? new Map();
  const connections = snapshot.connections ?? [];
  state.connections = connections.map((connection) => {
    const metadata = connection.metadata ?? {};
    const host = metadata.host || metadata.destinationIP || metadata.destination_ip || "unknown";
    const rulePayload = connection.rulePayload ?? connection.rule_payload;
    const rule = [connection.rule, rulePayload].filter(Boolean).join(",");
    const previous = previousRows.get(connection.id);
    const uploadBytes = connection.upload ?? 0;
    const downloadBytes = connection.download ?? 0;
    const uploadSpeed = previous && elapsed ? Math.max(0, (uploadBytes - previous.upload) / elapsed) : 0;
    const downloadSpeed = previous && elapsed ? Math.max(0, (downloadBytes - previous.download) / elapsed) : 0;
    return {
      id: connection.id,
      host,
      rule: rule || "MATCH",
      chains: connection.chains ?? [],
      upload: formatBytes(uploadBytes),
      download: formatBytes(downloadBytes),
      uploadBytes,
      downloadBytes,
      uploadSpeedBytes: uploadSpeed,
      downloadSpeedBytes: downloadSpeed,
      speed: `${formatBytes(uploadSpeed)}/s up · ${formatBytes(downloadSpeed)}/s down`,
      age: connection.start ? connection.start.slice(11, 19) : "live",
      start: connection.start,
      metadata,
    };
  });

  if (elapsed) {
    state.traffic.upload = Math.max(0, (uploadTotal - state.connectionStream.uploadTotal) / elapsed / 1024 / 1024);
    state.traffic.download = Math.max(0, (downloadTotal - state.connectionStream.downloadTotal) / elapsed / 1024 / 1024);
  }
  state.connectionStream = {
    at: now,
    uploadTotal,
    downloadTotal,
    rows: new Map(connections.map((connection) => [connection.id, { upload: connection.upload, download: connection.download }])),
  };
  state.controllerStatus = "controller live stream";
}

export function controllerModeFromSnapshot(snapshot) {
  const value = snapshot?.config?.mode;
  if (typeof value !== "string" || !value.length) return null;
  const mode = value[0].toUpperCase() + value.slice(1).toLowerCase();
  return ["Global", "Rule", "Direct"].includes(mode) ? mode : null;
}

export function controllerSelectorFromSnapshot(snapshot, groupName) {
  const group = (snapshot?.proxies?.groups ?? []).find((item) => item?.name === groupName);
  if (!group) return null;
  if (typeof group.now === "string") return group.now;
  if (typeof group.options?.[0] === "string") return group.options[0];
  return "DIRECT";
}

/// Nothing controller-backed survives an unreachable controller: an empty page
/// is honest, stale proxy groups are not.
export function clearControllerBackedState() {
  state.mode = null;
  state.logLevel = null;
  state.toggles.allowLan = false;
  state.proxyGroups = [];
  state.activeProxyGroup = null;
  state.proxyBlinkNode = null;
  state.connections = [];
  state.rules = [];
  state.connectionStream = {
    at: 0,
    uploadTotal: 0,
    downloadTotal: 0,
    rows: new Map(),
  };
  state.traffic.upload = 0;
  state.traffic.download = 0;
  state.connectionDetailId = null;
  state.closingConnectionIds.clear();
  state.closingAllConnections = false;
}
