// Presentation comes from the validated host identity, never from the browser's
// user agent. These labels do not grant network or native-component capabilities.
const MACOS = Object.freeze({
  name: "macOS",
  startAtLogin: "Start with macOS",
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
  startAtLogin: "Start with Windows",
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
