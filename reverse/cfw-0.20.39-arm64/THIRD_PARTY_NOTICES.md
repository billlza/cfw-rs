# Clash for Windows reference-artifact notice

This directory contains extracted reference material from the upstream Clash
for Windows 0.20.39 Apple Silicon distribution. It is behavioral reference
material only and is not product source, a linked dependency, or a runtime
payload of `cfw-rs`.

## Verbatim upstream metadata

The retained upstream `asar/package.json` declares:

```json
{
  "name": "clash_win",
  "version": "0.20.39",
  "author": "Fndroid",
  "license": "MIT"
}
```

The original upstream repository was
`https://github.com/Fndroid/clash_for_windows_pkg`. It is no longer available.
The sample identity recorded at inspection time is:

- distribution: `Clash.for.Windows-0.20.39-arm64.dmg`;
- distribution SHA-256:
  `479d9cef5932d70506592869b01e6e12a4c61411307c0d83615ba3f6c2b41631`;
- embedded `Contents/Resources/app.asar` SHA-256:
  `b6905dc463f622e5c09f49810e83abc7aba4eaa346fe026869aecb3a5e8a526c`.

The extracted files retained here do not include a separate upstream
copyright line or year. The project therefore does not infer either from the
`author` field. The exact metadata and the MIT terms are preserved in
[`LICENSE.MIT`](./LICENSE.MIT).

## Distribution boundary

Release packaging must exclude this entire `reverse/` tree from the app,
System Extension, ProxyAgent, updater, and DMG payloads. If a published source
archive intentionally includes the reference tree, it must preserve this
notice, `LICENSE.MIT`, the upstream `package.json`, and the recorded artifact
identity. License/SBOM review must verify that boundary; the presence of this
notice alone is not release evidence.
