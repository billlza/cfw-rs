# Performance And Stability Targets

The user-facing target is at least 3x better performance and stability than
CFW 0.20.39 on Apple Silicon. Until we have a measured baseline from the
original app on the same machine, the Rust code exposes strict interim budgets
through `QualityTargets::macos_arm64_3x()`.

## Interim Budgets

- Cold start p95: `<= 700 ms`
- Page switch p95: `<= 16 ms`
- System proxy toggle p95: `<= 150 ms`
- Profile apply p95: `<= 450 ms`
- Idle RSS: `<= 90 MB`
- Log ingest: `>= 10,000 events/sec`
- Crash-free sessions: `>= 99.95%`

## Stability Invariants

- System proxy must restore on normal exit, crash recovery and failed apply.
- Profile apply must be transactional: validate, stage, apply, then commit.
- Helper installation must be idempotent and auditable.
- TUN startup failure must restore the previous routing/proxy state.
- `clash://` must be single-instance safe and never create competing cores.

## Baseline Plan

1. Capture CFW 0.20.39 baseline on the same Apple Silicon Mac.
2. Measure cold start, navigation, proxy toggle, profile apply and memory.
3. Stress logs and connections with fixed synthetic replay files.
4. Convert every measured baseline into CI gates:
   latency `new p95 <= old p95 / 3`, throughput `new >= old * 3`,
   failure rate `new <= old / 3`.
5. Keep fallback behavior explicit instead of hiding failures with broad
   catch-all patches.

