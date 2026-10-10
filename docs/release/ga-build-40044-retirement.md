# GA build 40044 retirement

Build 40044 is classified as
`retired_product_change_after_install_before_ga_runtime_acceptance`. Its
consumed application lineage is retired because the installed migration handoff
misclassified the parent process's normal exit. Correcting that behavior changes
application code; release-tooling repairs and recoverable package attempts are
not the reason for this successor.

## Preserved application and release evidence

The frozen artifact source remains commit
`7735b3d895c0b1a1819c46bacd5e41682e82d721`, with release-source SHA-256
`dcf901dceaf376d16217c969bbf16d8e70858fc06fa31be25ecc4110f1083469`.
The candidate-freeze intent SHA-256 is
`04da32e344eaff168dcc3f2cacb0559da9c7a7ee38d5335a1d8a53aff38792eb`.
The notarized application tree, measured by `sha256-tree-v2`, is
`41ae01c3903f8ab644d74c5ff185a282a5978e4b0a8376198518046408745248`.
Application notarization was accepted under submission
`c7d898fb-09c3-40b2-8998-f805b94afa08`; the earlier unbound upload attempt and its
explicit same-archive adoption evidence remain preserved.

Prepackage completed with manifest SHA-256
`51819bc2ae673600d197b179dc8563e9fdb434a15d0dfd780bc1be14380d6e17`.
Both package sets completed and bind that exact application:

- DMG SHA-256:
  `057b7b2daf8d4a478c6458ab5a16677a3f13f4c8855c370715b16173ba1e4bfe`;
  DMG set seal SHA-256:
  `6bc55512971e0313c3f64bec9d6c56763661d0e9abc00563303fc92860073d17`;
  accepted DMG notarization submission:
  `d8388d75-97d2-4ad7-b7f7-360f83f96ac2`.
- Updater archive SHA-256:
  `12451660f6e55ffd84700f36b65f6bbcddfec5432b65794317f2aa840d67a344`;
  updater set seal SHA-256:
  `f704c6b5c091f9c4ba5ec3e882d4b40d563e0280ec008bddc107212a34791db0`.

The guarded 40043-to-40044 installation completed under transaction
`1e4a7108-6363-44b2-83b6-241f6b9ba9e7`. Its service transaction
`f57387ec-6f4a-4cf2-9ea3-1b0e67386631` reached `recommissioned`, and the
exported journals retain the original candidate and predecessor identities.
The installed 40044 application, outgoing 40043 side backup and every original
installation/service journal remain preserved.

## Confirmed product failure

On 2026-09-07, the retained `migration-process-exit-observation-05.json`
kqueue observation held the dashboard parent and handoff child through their
exits. The parent exited normally with status 0; the child exited about 66 ms
later. The corresponding private stderr, `migration-parent-child-05.stderr`,
reported a kernel identity query failure with `ESRCH` during post-parent window
activation. The observer completed only after both exits, excluding observer
cleanup as the cause.

The Darwin process reader called `kill(pid, 0)` after `proc_pidinfo` reported
failure. A normally exiting process can remain as an unreaped process entry,
so signalability is not the identity-query result. The correction must preserve
the original query error, recognize kernel-reported absence or an exited
process, and continue rejecting permission errors, malformed observations and
identity changes. Ticket consumption, UID, PID, executable and process-start
bindings remain required.

No Tunnel Confirm or legacy retirement deletion occurred. No GA acceptance
seal, final publication seal or public v0.4.0 release was created. Failed
handoff observations, migration state, vault data and the protected Clash for
Windows installation remain intact; the failure is not runtime acceptance.

## Product-change successor

Build 40045 is the single active successor and 40044 is its observed installed
predecessor. The new candidate requires its own exact-source hosted CI,
complete unsigned application, freeze, signing and notarization, source/legal
closure, packaging, guarded 40044-to-40045 installation, ordinary GA runtime
acceptance and publication verification. Existing release-tooling fixes and
the ordinary-GA versus assurance boundary carry forward unchanged. Source and
CI retries before freeze do not consume additional build numbers.

The frozen checkout `target/release-worktrees/40044`, candidate root
`target/candidates/0.4.0/ga/40044`, signed application, DMG/updater sets, failed
attempts, receipts and installed journals must not be rebuilt, re-signed,
overwritten or relabelled as 40045 evidence. Earlier retirement documents keep
their historical successor descriptions; the allocation ledger defines the
current active build.
