# Local 0.5 UI preview

**Status — user rejected this visual direction on 2026-09-22.** The one-page
Overview and sample-data preview are retained only as integration experiments.
They are not the requested 0.5 UI. Preserve the complete 0.4 layout, details and
interaction paths while adopting native component materials; the binding contract
is `docs/planning/0.5.0-ui-fidelity-contract.md`. Do not present this experiment as
the corrected design or expand it into a replacement workflow.

This independently installed AppKit launcher loads the same `CFMNativeDashboard`
library as the real native host integration. It is a UI review application, not
a functional VPN client or a signed release candidate. The default state says it
has no network-service observation. Example states, languages and appearance can
be selected from its menus; a persistent titlebar notice labels all sample data.

All network controls are disabled. The launcher has no production Rust host,
coordinator, native network framework, service installation, updater or Keychain
code. It does not read production settings or profiles. AppKit may store window
preferences under the independent `com.bill.clashformac.ui-preview` identity.
The normal CFM app remains installed and running separately.

Build with the selected Xcode (Apple Silicon, current Swift SDK):

```sh
/bin/bash native/dashboard/Preview/build-preview.sh /absolute/new/output-directory
```

The output must not exist; builds never overwrite an installed app. The script
builds the real SwiftUI library with warnings as errors, puts resources in the
application bundle, compiles this thin launcher, signs the new output ad hoc and
runs its AppKit self-check. This local signature is not Developer ID notarization.

`CFMNativePreview --self-check` creates the actual window and toolbar, checks the
packaged localization resources, sends 20 locale/example frames through ABI v2,
requires all requested controls to be rejected before their callback, and proves
exactly one close callback. It does not operate network services. The visible
window, resource lookup and persistent sample notice still need a visual check
after installation; tests do not prove release/VPN acceptance.
