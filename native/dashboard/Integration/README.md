# CFM Component Integration Test

This is a local **TEST DATA component-boundary harness**, not a product preview,
release candidate, production Tauri/Rust host, or network/VPN acceptance result.
It opens the repository's current, unmodified `ui/dist` in a real WKWebView and
presents the real SwiftUI components through their C ABI. No layout, app.js, CSS,
or product operation toolbar is replaced or injected.

Build and launch from the repository:

```sh
native/dashboard/Integration/build-and-run.sh
# Build a separate bundle without opening it or touching any running test app:
native/dashboard/Integration/build-and-run.sh --build-only
```

All generated files stay beneath a unique `target/050-completion/component-integration-*`
directory. The bundle is named `CFM Component Integration Test.app`, with a visible
`CFM Component Integration Test — TEST DATA` window title. The script never installs
anything into Applications or replaces a Preview. `running.json` contains its PID
and parent window number; `intents.jsonl` records fixture commands and native/channel
lifecycle. `build-receipt.json` records the exact copied frontend hashes and source
HEAD. Failed build directories are preserved.

The temporary app links only `libCFMNativeDashboard`, AppKit and WebKit. It does not
load the production Rust host, CFWNativeBridge, Keychain, or network configuration.
WebKit uses a nonpersistent store; a mandatory content rule blocks HTTP(S)/WS(S),
and navigation is restricted to the copied UI directory. The content-rule cache
is also stored under the run directory. Unknown business commands explicitly fail.
Only local fixture state can change; none of the profiles contain servers or secrets.

The real bundled Tauri JavaScript `Channel` serializes itself using `__CHANNEL__:id`.
The harness implements `transformCallback`/`unregisterCallback`, ordered `{index,message}`
packets, and `{index,end:true}` cleanup. Native settings submit keeps its Channel alive;
only native closure ends it. Page reload invalidates prior document channels and
closes native components. Native anchor placement borrows the actual WKWebView pointer.

Suggested checks using the visible window:

- Open Profiles and right-click `TEST DATA · 本地配置 B`. Check menu placement,
  keyboard arrows/Escape, local-source disabled reasons, and Edit returning to the
  original HTML editor. Selecting a profile changes only the in-memory fixture.
- Open Network settings through its existing entry. Check native text fields,
  checkbox style, tab order, draft retention, theme, and Cancel/Apply.
- Port `7899` deliberately rejects the fixture write with a TEST DATA error, so
  identical validation/failure retries can be inspected. A valid port such as
  `7901` writes only the in-memory fixture and closes via the existing frontend flow.
- Settings theme/language changes affect only fixture preferences. The displayed
  engine always remains Off; attempts to start an engine are explicitly rejected.
- Command+Q uses the normal application menu. Edit menu provides native clipboard
  keyboard actions for WKWebView and AppKit controls.

Screenshots, keyboard checks and VoiceOver must use this live window. Offscreen
rendering is not evidence that AppKit controls render or behave correctly. Even a
successful harness run does not establish the production Tauri/Rust lifecycle,
network functionality, performance improvement, release eligibility, or 0.5 completion.

Diagnostic fixture support preserves the original frontend handlers. `open_page`
accepts only the nine source-defined page IDs and records in-memory navigation;
`report_dashboard_startup` accepts only the closed startup-code set. Runtime config
text is generated from the current in-memory effective snapshot, including the
saved mixed port and log level.

The injected bridge observes capture-phase clicks (only `data-page`/`data-action`),
keydown keys, and bounded error/rejection messages. Listeners are passive and do not
cancel, redirect, synthesize, or await events. Each document records at most 1000
observations; identifier/key fields are capped at 64 Unicode scalars, error text
at 512. Envelope rejection reasons are separately recorded. No production scripts,
handlers, CSS, or DOM layout are modified by this instrumentation.
