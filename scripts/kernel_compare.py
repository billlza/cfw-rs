#!/usr/bin/env python3
"""Compare clash-rs (new) vs mihomo (old) with measured timings.

Uses high localhost ports so it will not touch a user's live Clash instance.
Outputs JSON suitable for embedding / UI display.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_CLASH_RS = REPO / "apps/cfw-tauri-shell/resources/cores/clash-rs"
DEFAULT_MIHOMO = REPO / "apps/cfw-tauri-shell/resources/cores/clash-darwin"


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def write_config(path: Path, mixed_port: int, controller_port: int) -> None:
    path.write_text(
        f"""mixed-port: {mixed_port}
external-controller: 127.0.0.1:{controller_port}
mode: rule
log-level: warning
allow-lan: false
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,DIRECT
""",
        encoding="utf-8",
    )


def wait_controller(base: str, timeout_s: float = 8.0) -> float | None:
    started = time.perf_counter()
    deadline = started + timeout_s
    while time.perf_counter() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/configs", timeout=0.4) as resp:
                resp.read()
            return (time.perf_counter() - started) * 1000.0
        except Exception:
            time.sleep(0.05)
    return None


def request_ms(url: str, timeout: float = 2.0) -> tuple[bool, float]:
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            resp.read()
        return True, (time.perf_counter() - started) * 1000.0
    except Exception:
        return False, (time.perf_counter() - started) * 1000.0


def probe_endpoints(base: str, samples: int = 20) -> dict:
    paths = ("/configs", "/proxies", "/connections", "/version")
    out = {}
    for path in paths:
        ok_times = []
        fail = 0
        for _ in range(samples):
            ok, ms = request_ms(f"{base}{path}", timeout=1.5)
            if ok:
                ok_times.append(ms)
            else:
                fail += 1
            time.sleep(0.02)
        out[path] = {
            "samples": samples,
            "failures": fail,
            "success_rate": round((samples - fail) / samples, 4),
            "p50_ms": round(statistics.median(ok_times), 3) if ok_times else None,
            "p95_ms": round(percentile(ok_times, 95), 3) if ok_times else None,
        }
    return out


def weak_net_probe(base: str, bursts: int = 40, timeout: float = 0.08) -> dict:
    """Simulate weak / lossy conditions with aggressive short timeouts + concurrency bursts."""
    successes = 0
    latencies = []
    for i in range(bursts):
        # Alternate between configs and proxies to stress the API under time pressure.
        path = "/configs" if i % 2 == 0 else "/proxies"
        ok, ms = request_ms(f"{base}{path}", timeout=timeout)
        if ok:
            successes += 1
            latencies.append(ms)
        time.sleep(0.01)
    return {
        "bursts": bursts,
        "timeout_s": timeout,
        "successes": successes,
        "success_rate": round(successes / bursts, 4),
        "p50_ms": round(statistics.median(latencies), 3) if latencies else None,
        "p95_ms": round(percentile(latencies, 95), 3) if latencies else None,
    }


def delay_probe(base: str, samples: int = 8) -> dict:
    ok_times = []
    fail = 0
    for _ in range(samples):
        url = f"{base}/proxies/DIRECT/delay?url=http://www.gstatic.com/generate_204&timeout=1500"
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                payload = json.loads(resp.read().decode("utf-8") or "{}")
            elapsed = (time.perf_counter() - started) * 1000.0
            delay = payload.get("delay")
            if isinstance(delay, (int, float)) and delay > 0:
                ok_times.append(float(delay))
            else:
                # zero / missing counts as soft fail for reliability view
                fail += 1
                ok_times.append(elapsed)
        except Exception:
            fail += 1
        time.sleep(0.05)
    return {
        "samples": samples,
        "failures": fail,
        "success_rate": round((samples - fail) / samples, 4),
        "p50_ms": round(statistics.median(ok_times), 3) if ok_times else None,
        "p95_ms": round(percentile(ok_times, 95), 3) if ok_times else None,
    }


def run_core(name: str, binary: Path, mixed_port: int, controller_port: int) -> dict:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise FileNotFoundError(f"missing executable core: {binary}")

    work = Path(tempfile.mkdtemp(prefix=f"cfw-{name}-bench-"))
    config = work / "config.yaml"
    write_config(config, mixed_port, controller_port)
    log_path = work / "core.log"
    base = f"http://127.0.0.1:{controller_port}"

    cold_starts = []
    for run_idx in range(3):
        log_file = open(log_path, "ab")
        proc = subprocess.Popen(
            [str(binary), "-d", str(work), "-f", str(config)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=str(work),
        )
        ready_ms = wait_controller(base, timeout_s=10.0)
        if ready_ms is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            log_file.close()
            raise RuntimeError(f"{name} controller not ready (run {run_idx + 1})")
        cold_starts.append(ready_ms)
        if run_idx < 2:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            time.sleep(0.2)
        else:
            # keep last instance for endpoint probes
            keep_proc = proc
            keep_log = log_file

    endpoints = probe_endpoints(base, samples=24)
    weak = weak_net_probe(base, bursts=48, timeout=0.08)
    delay = delay_probe(base, samples=8)

    keep_proc.send_signal(signal.SIGTERM)
    try:
        keep_proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        keep_proc.kill()
    keep_log.close()

    configs_p95 = endpoints["/configs"]["p95_ms"]
    return {
        "name": name,
        "binary": str(binary),
        "cold_start_ms": {
            "runs": [round(v, 3) for v in cold_starts],
            "p50_ms": round(statistics.median(cold_starts), 3),
            "p95_ms": round(percentile(cold_starts, 95), 3),
            "mean_ms": round(statistics.mean(cold_starts), 3),
        },
        "controller_api": endpoints,
        "weak_net": weak,
        "delay_probe": delay,
        "summary": {
            "controller_p95_ms": configs_p95,
            "weak_net_success_rate": weak["success_rate"],
            "delay_success_rate": delay["success_rate"],
        },
    }


def ratio(old: float | None, new: float | None) -> float | None:
    if old is None or new is None or new == 0:
        return None
    return round(old / new, 3)


def delta_pp(new: float | None, old: float | None) -> float | None:
    if new is None or old is None:
        return None
    return round((new - old) * 100.0, 2)


def compare(clash_rs: dict, mihomo: dict) -> dict:
    rs_cold = clash_rs["cold_start_ms"]["mean_ms"]
    mh_cold = mihomo["cold_start_ms"]["mean_ms"]
    rs_api = clash_rs["controller_api"]["/configs"]["p95_ms"]
    mh_api = mihomo["controller_api"]["/configs"]["p95_ms"]
    rs_weak = clash_rs["weak_net"]["success_rate"]
    mh_weak = mihomo["weak_net"]["success_rate"]
    rs_delay = clash_rs["delay_probe"]["success_rate"]
    mh_delay = mihomo["delay_probe"]["success_rate"]

    speedup_cold = ratio(mh_cold, rs_cold)
    speedup_api = ratio(mh_api, rs_api)
    weak_pp = delta_pp(rs_weak, mh_weak)
    delay_pp = delta_pp(rs_delay, mh_delay)

    return {
        "headline": {
            "cold_start_speedup_x": speedup_cold,
            "controller_api_speedup_x": speedup_api,
            "weak_net_success_delta_pp": weak_pp,
            "delay_success_delta_pp": delay_pp,
            "winner_speed": "clash-rs"
            if (speedup_cold or 0) >= 1.0 and (speedup_api or 0) >= 1.0
            else "mixed",
            "winner_reliability": "clash-rs"
            if (weak_pp or 0) >= 0 and (delay_pp or 0) >= 0
            else "mixed",
        },
        "narrative": {
            "speed": (
                f"Cold start mean: clash-rs {rs_cold} ms vs mihomo {mh_cold} ms"
                + (f" ({speedup_cold}× faster)" if speedup_cold else "")
                + f". Controller /configs p95: clash-rs {rs_api} ms vs mihomo {mh_api} ms"
                + (f" ({speedup_api}× faster)." if speedup_api else ".")
            ),
            "stability": (
                f"Delay probe success: clash-rs {rs_delay:.0%} vs mihomo {mh_delay:.0%}"
                + (f" ({delay_pp:+.1f} pp)." if delay_pp is not None else ".")
            ),
            "weak_net": (
                f"Short-timeout burst success: clash-rs {rs_weak:.0%} vs mihomo {mh_weak:.0%}"
                + (f" ({weak_pp:+.1f} pp)." if weak_pp is not None else ".")
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clash-rs", type=Path, default=DEFAULT_CLASH_RS)
    parser.add_argument("--mihomo", type=Path, default=DEFAULT_MIHOMO)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO / "apps/cfw-tauri-shell/resources/benchmarks/kernel-compare-latest.json",
    )
    args = parser.parse_args()

    # High ports — avoid user's live 9090/7905.
    clash_rs = run_core("clash-rs", args.clash_rs, mixed_port=18110, controller_port=19110)
    mihomo = run_core("mihomo", args.mihomo, mixed_port=18111, controller_port=19111)
    comparison = compare(clash_rs, mihomo)

    payload = {
        "schema": 1,
        "product": "Clash for Mac",
        "measured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": {
            "os": sys.platform,
            "machine": os.uname().machine if hasattr(os, "uname") else "unknown",
        },
        "claim_3x_cfw": False,
        "note": "Measured clash-rs vs mihomo on this Apple Silicon host. Not a CFW 3× claim.",
        "cores": {
            "clash_rs": clash_rs,
            "mihomo": mihomo,
        },
        "comparison": comparison,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["comparison"]["headline"], indent=2))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
