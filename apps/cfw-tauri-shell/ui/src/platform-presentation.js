// Presentation comes from the validated host identity, never from the browser's
// user agent. These labels do not grant network or native-component capabilities.
const MACOS = Object.freeze({
  name: "macOS",
  startAtLogin: "Start with macOS",
  copyProxyCommands: "Copy proxy export commands for Terminal",
  copiedProxyCommands: "Copied proxy export commands for Terminal",
});
const WINDOWS = Object.freeze({
  name: "Windows",
  startAtLogin: "Start with Windows",
  copyProxyCommands: "Copy proxy commands for PowerShell",
  copiedProxyCommands: "Copied proxy commands for PowerShell",
});

export function platformPresentation(operatingSystem) {
  switch (operatingSystem) {
    case "macos": return MACOS;
    case "windows": return WINDOWS;
    default: throw new TypeError("host operating system is invalid");
  }
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
