# Performance And Stability Targets

Clash for Mac aims to be **stronger than CFW** on Apple Silicon through architecture
(Tauri shell, Rust clash-rs default, arm64-only), not through unverified 「3×」slogans.

Interim budgets below are engineering guardrails
(`QualityTargets::macos_arm64_3x()`). They are **not** a published 3× claim.

## Interim Budgets (guardrails only)

- Cold start p95: `<= 700 ms`
- Page switch p95: `<= 16 ms`
- System proxy toggle p95: `<= 150 ms`
- Profile apply p95: `<= 450 ms`
- Idle RSS: `<= 90 MB`
- Log ingest: `>= 10,000 events/sec`
- Crash-free sessions: `>= 99.95%`

## CI gate (`cfw-perf-gate`)

- Script: [`scripts/cfw_perf_gate.sh`](../scripts/cfw_perf_gate.sh)
- Platform: **Apple Silicon only** (`scripts/assert_apple_silicon.sh`)
- Behavior: records controller probe JSON under `target/perf-gate/`
- Soft skip when no live controller is available
- Output always sets `"claim_3x_cfw": false` unless a future comparator proves otherwise
- **Never fail CI solely for missing a 3× claim**

## Stability Invariants

- System proxy must restore on normal exit, crash recovery and failed apply.
- Profile apply must be transactional: validate, stage, apply, then commit.
- Helper installation must be idempotent and auditable.
- TUN startup failure must restore the previous routing/proxy state.
- `clash://` must be single-instance safe and never create competing cores.

## Baseline Plan (required before advertising 3×)

1. Capture CFW 0.20.39 baseline on the same Apple Silicon Mac.
2. Measure cold start, navigation, proxy toggle, profile apply and memory.
3. Stress logs and connections with fixed synthetic replay files.
4. Convert every measured baseline into CI gates:
   latency `new p95 <= old p95 / 3`, throughput `new >= old * 3`,
   failure rate `new <= old / 3`.
5. Keep fallback behavior explicit instead of hiding failures with broad
   catch-all patches.
