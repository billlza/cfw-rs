# GA build 40039 retirement

Build 40039 is classified as
`retired_product_change_notarization_outcome_unknown`. Its application lineage
is consumed and retired; the original Apple notarization transaction remains
quarantined. These are separate facts. Neither the successor allocation nor
this document establishes an accepted, rejected, cancelled or absent Apple
submission.

## Immutable consumed lineage

The candidate-freeze intent binds build 40039 to:

- repository commit:
  `bdea6f5b45edb20f51fd4df0efe2b404f25300a9`;
- release-source SHA-256:
  `f982918081c456199ee8421354ac687ccf49166da601a80bed514364b2fd2f7f`;
- product-input document SHA-256:
  `afd79ec4524e17b18a2ee42f52d14dc799cf5362d41433cc9e953537b36c72fd`;
- frozen product-input semantic SHA-256:
  `b2d86b55c97723e0c778f1649bd1cac8fbbd63e781025ccf243dc0e5234ee156`;
- candidate-freeze intent SHA-256:
  `c6254c1f50e5db02bb91026d724b4d760e0606691f9ef0cfcebfb805d8e26a71`;
- pre-sign application tree SHA-256:
  `5fb4feee53d46888e8ee5b9b96730093585fdba6a246869705c5ae1fa99e1c52`.

The frozen checkout at `target/release-worktrees/40039` and its candidate root
`target/candidates/0.4.0/ga/40039` remain unchanged. Canonical
`signing-output` exists, but there is no canonical notarized `signed`
application, prepackage seal, package set, installed-runtime acceptance,
publication seal or public 0.4.0 release for this build. The signed bytes,
source, original cache authorization, recovery authorization, journals,
receipts and failed evidence attempts must be retained, not copied forward as
successful evidence for another candidate.

## Original notarization outcome

The app-notary journal progressed through `prepared`,
`pre_submission_policy_compatibility_applied` and `submitting`, then retained
`outcome_unknown` without a submission ID. Event `00000004.json` has SHA-256
`2ce84811a74d62fd724d24429d8d0e978010c175138cc23f97688d4730abd567`.
Do not edit that event, invent a submission ID or fresh-submit this archive.

A read-only query on 2026-09-02 for the previously observed identifier
`a9f40363-cc12-4b91-9d29-f4bd25cf54e6`, using the fixed
`clashformac-notary` profile, exited 69 and reported that the submission does
not exist or does not belong to the team. The current history response had no
40039 match in its returned 100 records. This is not proof of a global absence,
a rejection or a cancellation, and it does not resolve the unknown journal.
Only further read-only reconciliation of the original transaction is allowed.

## Product-change successor

The source now adds anonymous and authenticated SOCKS5 profiles, native
credential injection, engine projection and import/UI support. Those modules
are absent from the frozen 40039 source; adding them necessarily changes the
application bytes. Build 40040 is therefore the single active successor for
this new product input, not a retry of the old notarization transaction.

The original 40039 lineage must never be rebuilt, re-signed, resubmitted,
installed, promoted, relabelled or published. Earlier retirement documents
retain their historical successor descriptions; current activity is determined
only by the versioned allocation ledger and its source verifier.

Build 40040 requires a clean exact-source CI result, a new complete unsigned
tree and freeze, new signing/notarization, source and license closure, package
seals, one-machine ordinary-GA acceptance, and publication verification.
Source, CI and read-only preflight retries before freeze retain build 40040 and
use new attempt identities. Assurance-only qualification remains separate.
