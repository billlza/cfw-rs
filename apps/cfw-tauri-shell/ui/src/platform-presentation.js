// Presentation comes from the validated host identity, never from the browser's
// user agent. These labels do not grant network or native-component capabilities.
const MACOS = Object.freeze({
  name: "macOS",
  systemDns: "This app never writes host DNS, because the legacy restore value carries no per-service ownership identity. Clear or set custom DNS per service in System Settings › Network › Details › DNS.",
  globalShortcutHint: "Global shortcuts work while this app is in the background. Include Command, Option or Control; leave a field empty to disable it.",
  shortcutExample: "Command+Option+P",
  networkRuleHint: "The first matching rule applies after a network change or when enabled. Manual Stop stays stopped on the same network. Rules run while CFM is open.",
  wifiNameUnavailable: "macOS is not providing the Wi-Fi name. Rules for a named Wi-Fi network cannot match until the name is available.",
  wifiAccessAction: "Allow Wi-Fi name access…",
  wifiAccessNotice: "Respond to the macOS permission prompt, then refresh network status.",
  startAtLogin: "Start with macOS",
  localProxyUnavailable: "The signed ProxyAgent has not reported local proxy capability.",
  systemProxyUnavailable: "The signed ProxyAgent has not reported capability.",
  tunnelUnavailable: "The signed Packet Tunnel System Extension has not reported capability.",
  combinedUnavailable: "TUN Mode and System Proxy cannot run together until both report capability.",
  tunnelInfoHint: "The Packet Tunnel runs as a signed NetworkExtension System Extension and must be approved once in System Settings.",
  tunnelInfo: "TUN Mode runs the packet tunnel as a signed NetworkExtension System Extension. macOS asks for approval once, under System Settings › General › Login Items & Extensions; until it is approved the switch stays unavailable.",
  copyProxyCommands: "Copy proxy export commands for Terminal",
  copiedProxyCommands: "Copied proxy export commands for Terminal",
  updateEnvironmentFailure: "This copy cannot update itself. Download the disk image and replace the app in Applications.",
  updateStorageFailure: "The update could not be stored on this Mac. Free some disk space and try again.",
  updatePackageFailure: "This release cannot be installed on this Mac.",
  updateInstalling: "Installing update… Clash for Mac will reopen automatically.",
  updateReady: "v{version} is ready to install. Clash for Mac will stop the core, quit, and reopen.",
});
const WINDOWS = Object.freeze({
  name: "Windows",
  systemDns: "This app does not change Windows network adapter DNS settings. Manage DNS for each active adapter in Windows Settings → Network & internet.",
  globalShortcutHint: "Global shortcuts work while this app is in the background. Include Control, Alt or Super (Windows key); leave a field empty to disable it.",
  shortcutExample: "Control+Alt+P",
  networkRuleHint: "The first matching rule applies after a network change or when enabled. Manual Stop stays stopped on the same network. Rules run while CFW is open.",
  wifiNameUnavailable: "Windows controls access to Wi-Fi names in Location settings. Review those settings if a named Wi-Fi rule cannot read its network, then refresh network status.",
  wifiAccessAction: "Open Windows Location settings",
  wifiAccessNotice: "Review Windows Location settings, then refresh network status.",
  startAtLogin: "Start with Windows",
  localProxyUnavailable: "Local proxy is unavailable in this Windows session.",
  systemProxyUnavailable: "System Proxy is unavailable in this Windows session.",
  tunnelUnavailable: "TUN Mode is unavailable in this Windows build.",
  combinedUnavailable: "TUN Mode and System Proxy cannot run together in this Windows build. Turn one off first.",
  tunnelInfoHint: "TUN Mode routes device traffic through a Windows virtual network adapter.",
  tunnelInfo: "TUN Mode uses a Windows virtual network adapter to route traffic. The switch is available only when Windows tunnel support is ready.",
  copyProxyCommands: "Copy proxy commands for PowerShell",
  copiedProxyCommands: "Copied proxy commands for PowerShell",
  updateEnvironmentFailure: "This copy cannot update itself. Download the Windows installer from the release page and run it.",
  updateStorageFailure: "The update could not be stored on this Windows PC. Free some disk space and try again.",
  updatePackageFailure: "This release cannot be installed on this Windows PC.",
  updateInstalling: "Installing update… Clash for Windows will reopen automatically.",
  updateReady: "v{version} is ready to install. Clash for Windows will stop the core, quit, and reopen.",
});

export function platformPresentation(operatingSystem) {
  switch (operatingSystem) {
    case "macos": return MACOS;
    case "windows": return WINDOWS;
    default: throw new TypeError("host operating system is invalid");
  }
}

// The native payload names the platform's startup mechanism differently.
// Resolve it once at the UI boundary instead of rendering a missing Mac field.
export function platformStartupDesign(operatingSystem, design) {
  platformPresentation(operatingSystem);
  const windows = operatingSystem === "windows";
  const value = windows ? design?.startup_strategy : design?.launchd_strategy;
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError("host startup strategy is invalid");
  }
  return { label: windows ? "Start at Login" : "launchd", value };
}

export function proxyEnvironmentCommands(operatingSystem, port) {
  platformPresentation(operatingSystem);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError("proxy command port is invalid");
  }
  const variables = [
    ["https_proxy", `http://127.0.0.1:${port}`],
    ["http_proxy", `http://127.0.0.1:${port}`],
    ["all_proxy", `socks5://127.0.0.1:${port}`],
  ];
  return variables.map(([name, value]) => operatingSystem === "windows"
    ? `$env:${name} = "${value}"`
    : `export ${name}=${value}`).join("\n");
}
