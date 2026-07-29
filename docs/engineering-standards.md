# Engineering standards

These standards govern every change in this repository. They exist so the
codebase stays maintainable, testable, explainable, and honest about failure.
When a rule here conflicts with getting a change merged quickly, the rule wins.

## Priorities

1. Long-term correctness over fast completion.
2. Exposing a real error over hiding it behind a fallback.
3. Fixing the root cause over minimizing the diff — while still keeping the
   change scoped.
4. Keeping a test meaningful over making it pass.
5. Actually fixing a warning over suppressing it.
6. Reusing the existing architecture over inventing a parallel one.

## Naming and history

- Branch names, commit messages, tags, release notes, and pull-request titles
  and bodies use neutral product, feature, fix, or release semantics only.
- No tool, vendor, or origin identifiers appear in branch names, history, or
  repository content.

## Working principles

Before changing code, understand the user-visible goal, the existing module
boundaries, the data/control/error flow, the current test strategy, and the
migration cost of the change. Do not modify code purely from an error message
without understanding the cause.

Deliverables are judged by whether a future maintainer can understand them,
not by whether the current case passes.

## Forbidden implementation patterns

- **Broad fallbacks.** No silently returning defaults after a failure, no
  pretending success, no masking real errors with empty collections, `null`,
  `0`, or `false`, no nondeterministic "try A, else B, else C" chains unless
  the sequence is an explicit, documented product requirement (for example the
  bounded DNS resolver failover, which is specified, bounded, and tested).
- **Swallowed errors.** No empty catch blocks, no log-and-continue on a
  critical path, no wrapping unknown failures into harmless states. Every
  error has a type, context, and an owning boundary.
- **Defensive patching.** No scattering optionals, assertions, or catches to
  silence a symptom; no weakening the type system to make an error disappear.
- **Architecture pollution.** No cross-layer calls, no business logic in
  views or command glue, no circular dependencies, no second copy of existing
  logic, no grab-bag `utils` modules.
- **Fake fixes.** No editing tests instead of the bug (unless the test itself
  is wrong), no weakening assertions, no skipping or quarantining failing
  tests, no disabling lints, no lowering compiler strictness, no suppress
  comments, no mocks that hide a real integration problem.
- **Unowned compatibility layers.** Any compatibility shim states its
  boundary, its migration plan, and its removal path. Half-migrated states do
  not persist across releases.

## Error handling

Fail fast, explicitly, observably, and locatably.

Allowed: catching a known error at a declared boundary, converting a
lower-level error into a domain error, adding context and rethrowing, explicit
validation at input/network/file/database boundaries, and recovery flows that
are explicit, bounded, business-approved, and tested.

Not allowed: silent recovery, fallbacks that hide bugs, dressing a system
error up as a normal business branch, or error surfaces that make success,
emptiness, permission failure, network failure, data corruption, and internal
error indistinguishable to the caller.

Every new error path must answer: what does it mean, who handles it, is it
retried, is it shown to the user, is it logged, and which test covers it?
Error text that can reach the user or a log must never contain secrets; in
this codebase that includes subscription URLs, node passwords, and UUID
credentials, which are redacted or reported by category only.

## Code quality

- Names carry business meaning; functions stay small and single-purpose.
- Types are precise; heterogeneous maps are not used where a struct fits.
- Side effects and I/O live at declared boundaries, separate from pure logic.
- No dead code, duplicated logic, debug leftovers, unused dependencies,
  unused imports, unawaited futures, unclosed resources, or race conditions.
- Existing project conventions win by default. When an existing convention is
  demonstrably wrong or dangerous, fix it as a scoped, verifiable change and
  say so — do not silently diverge from it.

## Architecture

Every change declares the layer it touches (schema/domain, configuration,
persistence, service, runtime, command surface, UI shell, tests, or
infrastructure adapter) and respects the one-way dependency direction
documented in [architecture.md](./architecture.md). Cross-cutting concerns
(logging, authorization, configuration) stay at their declared boundaries
instead of leaking into call sites.

A new module needs: one clear responsibility, a conventional name and
location, no overlap with an existing module, a real caller, test coverage,
and no needless growth of the public surface. Refactors move in small verified
steps: protect behavior with tests first, then move code, then delete the old
path in the same effort.

## Testing and verification

Run the checks relevant to the change before delivering. For this workspace
the baseline is the CI parity set, in order:

```sh
cargo fmt --all -- --check
cargo metadata --locked --filter-platform aarch64-apple-darwin --format-version 1
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo deny --locked --target aarch64-apple-darwin check
```

Deliveries carry zero errors and zero warnings. A third-party warning is
either fixed at its source (correct usage, configuration, upgrade, or
replacement) or reported as an explicit blocker with its origin and a
reproduction command — never claimed as resolved.

New and changed tests make real assertions and cover the success path, the
key boundaries, the failure paths, regressions, and — where relevant —
security, concurrency, and migration behavior.

## Dependencies

Prefer the standard library and dependencies already in the workspace. A new
dependency must justify itself against maintenance status, security exposure,
license compatibility (see [deny.toml](../deny.toml)), runtime cost, and
lock-in, and must not duplicate an existing capability. Heavyweight
dependencies are not added for small problems. Every dependency change passes
`cargo deny` and lands with the updated `Cargo.lock`.

## Performance and resources

Watch for repeated network requests, unnecessary full scans, blocking the
main thread, unbounded caches or queues, unreleased resources, large copies,
and missing timeouts or cancellation. Any new cache, queue, retry, or
concurrency mechanism declares its invalidation strategy, capacity bound, and
failure behavior.

## Security

Changes that touch input parsing, credentials, files, network, command
execution, serialization, or logging get a security review. Injection, SSRF,
path traversal, deserialization abuse, secret leakage into logs or errors,
permission bypass, unsafe randomness, unsafe temporary files, and unsafe
defaults are checked explicitly at the boundary — "the caller guarantees it"
is not an accepted argument. Untrusted documents (for example subscription
payloads) are parsed only with bounded size, bounded node counts, and bounded
recursion depth.

## Data and contracts

Changes to persisted formats, schemas, or public contracts state how old data
is handled, whether a migration is needed, whether it is repeatable and
rollback-safe, and what happens to existing fixtures and clients. Persisted
formats and public contracts do not change silently.

## User-visible behavior

When behavior changes, the change records the old behavior, the new behavior,
the reason, the edge cases, and whether it is breaking. Failure states are
never presented as empty states; product semantics are not bent for
implementation convenience.

## Delivery checklist

A change is complete only when all of the following hold:

- the root cause is fixed, not the symptom;
- the change fits the existing architecture and removes code it obsoletes;
- there are no duplicated logic paths, silent fallbacks, swallowed errors,
  weakened types, or suppressed diagnostics;
- all relevant checks above pass with no errors and no warnings;
- there is no known security regression or obvious performance regression;
- a future maintainer can understand the change from the code and its tests.

If any item fails, the work is not done. External blockers are reported with
their cause and a reproduction path instead of being papered over.
