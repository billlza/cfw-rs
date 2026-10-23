# Desktop platform observations

`cfw-platform` exposes shared, fallible observations of the OS version, ordered
UI languages and physical network context. Keep these synchronous native calls
on the shell's observation/preparation workers. They do not establish engine
authority, network reachability or a hard execution deadline.

The macOS management APIs retain their existing implementations and are exported
only on macOS. Windows cannot accidentally invoke `launchctl`, Unix process-group
cleanup, Apple signature verification or Mac legacy-service migration.

Windows observations use the existing pinned Rust Windows bindings:

- `RtlGetVersion` checks the native result and reports the running kernel version.
  Feature availability must be checked independently.
- `GetUserPreferredUILanguages` preserves language priority. Its bounded read may
  retry a documented buffer-growth race; malformed output and native errors are
  errors, not an empty preference list. The application propagates these failures
  and distinguishes failed display/application from preferences already saved.
- `GetAdaptersAddresses` and `GetIfEntry2` select an active hardware Ethernet or
  Wi-Fi interface. Virtual, filtered, paused and disconnected interfaces are
  excluded. Addresses undergoing DAD, duplicates and invalid addresses do not
  trigger automation. Preferred and deprecated addresses remain usable. Native
  records, linked lists and address buffers are bounded and checked. A usable
  gateway, configured interface metric and GUID determine selection; this is
  physical-network context, not proof of the effective default route.
- The selected Wi-Fi adapter is matched by GUID to a WinRT connection profile.
  `GetConnectedSsid` reads its name without scanning or querying BSSIDs. WinRT
  objects remain inside the worker's initialized apartment. Unsupported names,
  missing profiles, native errors and inconsistent observations remain errors.
- The explicit Wi-Fi access action opens Windows location privacy settings.
  Successful launching does not prove permission was granted. Observation does
  not invoke this action automatically.

The Windows CI package tests exercise real version/language/adapter/profile APIs
and malformed native records. A hosted VM may report no physical adapter; that
documented absence is distinct from native failure. These tests do not establish
physical Wi-Fi behavior, service authority, proxy/TUN ownership, desktop UI parity,
sleep/wake recovery, installation or release acceptance.

Microsoft documents the [address readiness states](https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_dad_state),
[gateway records](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_gateway_address_lh)
and [SSID-only API recommendation](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes).
