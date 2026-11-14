# CFM / CFW control-plane branch governance (2026-10-21)

## Verdict and evidence boundary

The repository has a large number of Windows development checkpoint branches,
but **25 inspected checkpoint refs were ancestors of**
lza/cfw-0.5.0-windows (PR #8) at the time of this review. They are **already
integrated in Git history**: merging or cherry-picking them again is unnecessary.

The lza/cfw-0.5.0-windows-shell branch and the canonical Windows branch
pointed to the **same commit** (56505c013b8d6558d96241622b6574f22cbdeb02)
during inspection. One separate experimental branch,
lza/cfw-worker-retirement, diverged (one unique branch-side commit and three
unique Windows-side commits by the ancestor comparison). Its code delta is a
native Windows process-retirement diagnostic/probe, **not another production
mobile-egress controller**. The experiment is not eligible for automatic merge.

See control-plane-branch-map.json for the exact 25 branch names and the
read-only tool under tools/branch-governance/ for a repeatable audit. This is
a date-stamped observation; active branches move and must be rechecked before
any cleanup or merge decision.

## Distinct systems — do not conflate controller names

| Area | Review branch | Ownership and scope | Status at inspection |
| --- | --- | --- | --- |
| macOS GA / shared product | main | Frozen v0.5.0 macOS release remains unchanged | Published |
| Windows desktop / SCM / global authority | lza/cfw-0.5.0-windows (PR #8) | Local machine network, service identity, lifecycle, updater | Draft, incomplete acceptance |
| CFM physical-network identity | fix/macos-network-identity-ipv6 (PR #9) | OS-provided Wi-Fi and IPv6 observations for local policy | Independent Mac PR; no device API |
| Mobile egress operator observer | feat/mobile-egress-observer (PR #10) | Read-only WireGuard usage alerts and vendor archive intake | Draft, no VPS enforcement |
| Windows process-retirement probe | lza/cfw-worker-retirement | Diagnostic tests only | Isolated experiment |

The existing Rust cfw-controller crate provides **local Clash-compatible
controller/stream functionality**. It is not a remote administrator of M7 Pro,
a multi-tenant VPS authority or a billing/control-plane database.

CFM network automation can react to a physical interface; it does not thereby
certify that the interface is a NETGEAR MR7450, nor that a given IP belongs
to a cellular operator. Windows SCM authorization controls local Windows
services and **must not** become authority for VPS customer accounts.

The intended future remote system has clear independent boundaries:

1. **VPS admission/enforcement (not yet implemented)**: individual authenticated
   peers, atomic quotas, hard rate and connection limits, fail-closed service
   restart, revocation and a global carrier-data cutoff. These policies live
   on the VPS or trusted egress, not merely a laptop screen.
2. **UK cellular egress**: a vendor-supported M7 Pro Agent if such an execution
   path is independently demonstrated; otherwise a dedicated gateway or a
   temporary Mac egress PoC. No root/debug/program execution has been proven on
   MR7450-100EUS_01.15.
3. **Mac operator control surface**: query signed/read-only VPS telemetry,
   analyze anomalies, alert the operator, and eventually request authorized
   emergency policies. An offline Mac cannot disable the VPS rules.
4. **CFM / CFW users**: peer identity and traffic reporting must be separate
   from the client's local proxies and OS privilege boundary; no embedded
   shared administrator credentials or unauthenticated SOCKS listeners.

A monitoring result cannot establish that user traffic is lawful, and
unencrypted traffic contents are not a default monitoring input.

## Mythic Beasts deployment prerequisites

Mythic Beasts officially offers IPv6 on its VPS services while public IPv4 is
optional. Do **not** assume that this customer's VPS already has IPv4 or a
particular OS/image, WireGuard interface, firewall tool or free bandwidth.
The provider has documented web/serial/VNC out-of-band console recovery and
an authenticated VPS provisioning API. None of these facts establishes
permission to change this particular VPS without explicit account access.

Read-only validation before any deployment:

- Confirm actual VPS ID, OS/kernel, public IPv4/IPv6, upstream firewall and
  available monthly bandwidth **without sharing any login secret in Git**.
- Confirm a working out-of-band console/rescue path before firewall changes.
- Confirm whether mobile SIM service terms permit the intended sharing
  arrangement and whether UK immigration/commercial/communications rules
  allow the proposed activity. Do not open public peer registration yet.
- Confirm telemetry role only allows a fixed narrow observation command. A
  read-only observer must never be able to start/stop the data plane.
- Explicitly test both IPv4 and IPv6 traffic and the M7 Pro SIM uplink
  bottleneck. WireGuard transfer counters are not carrier-billed usage.

References:
- https://www.mythic-beasts.com/sales/ipv6/
- https://www.mythic-beasts.com/support/servers/consoles
- https://www.mythic-beasts.com/support/api/vps/quickstart

## Required change workflow

- Use **one active Windows PR** (#8) and keep its historical milestone branches
  unchanged; their commits are already represented. Never remerge snapshot
  branches merely to shorten a branch list.
- Use **one canonical egress-observer PR** (#10). New observer code, parser
  tests, offline firmware-intake tests and its policy documentation go under
  tools/mobile-egress-guard, not copies in Windows backend or signed CFM.
- Keep PR #9 separate because it changes released-product networking
  observation and requires macOS app / physical-network validation. A code
  relationship is not justification for mixing release ownership.
- Preserve the standalone worker-retirement experiment; assess its native
  retirement probe on a Windows runner against the **current** PR #8 head
  before proposing an additive test commit. No relaxation of cleanup proofs.
- Any actual VPS enforcement module needs its own implementation, tests, audit
  trail, explicit policy identity, and an approval gate before a production
  server mutation. Never interpret passing read-only monitoring CI as
  enforcement or carrier usage protection.
- Do not delete branches, force-update PR heads, merge draft PRs, or adjust
  release tags solely as a side effect of this governance review. Check for
  active worktrees/agents and fresh SHA/CI evidence first.

## Reproduce branch ancestry without mutation

From a clone with all relevant remote-tracking refs already fetched:

    python3 tools/branch-governance/audit.py \
      --repository . \
      --manifest docs/planning/control-plane-branch-map.json \
      --remote origin \
      --strict

The tool only runs read-only Git observations and outputs JSON. It does **not**
fetch refs, push, delete, merge, install software or change network state.
A missing ref is an error rather than evidence that it is obsolete. A staged
Windows snapshot not contained in the canonical Windows branch fails --strict
and must be reconciled by review. Diverged experimental/review branches are
reported without automatically failing or merging them.

For a deliberately updated local clone, fetch the relevant branches under
review separately. That Git fetch mutates *local remote-tracking refs*, not the
GitHub branches themselves. CI tests use synthetic local Git histories and do
not require live repository/account permissions. Real M7 Pro and VPS behavior
are outside this branch-audit contract.
