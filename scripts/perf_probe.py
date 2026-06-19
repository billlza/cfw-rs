#!/usr/bin/env python3
import argparse
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_APP = os.path.join(REPO_ROOT, "target", "release", "bundle", "macos", "Clash for Mac.app")
DEFAULT_BASE = "http://127.0.0.1:9090"
DEFAULT_RSS_MATCH = "clash-for-mac,Clash for Mac/cores/clash-darwin"
ENDPOINTS = ("/configs", "/proxies", "/providers/proxies", "/rules", "/connections")
UI_TARGETS = (
    ("page_switch_p95_ms", "page switch p95"),
    ("proxy_toggle_p95_ms", "proxy toggle p95"),
    ("profile_apply_p95_ms", "profile apply p95"),
)
CONNECTION_COUNT_TOLERANCE = 0.05


def request_json(base_url, path, timeout=2.0, secret=None):
    started = time.perf_counter()
    request = urllib.request.Request(f"{base_url}{path}")
    if secret:
        request.add_header("Authorization", f"Bearer {secret}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return elapsed_ms, json.loads(body.decode("utf-8") or "{}")


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def endpoint_probe(base_url, path, samples, secret=None):
    timings = []
    last_payload = None
    errors = []
    for _ in range(samples):
        try:
            elapsed_ms, payload = request_json(base_url, path, secret=secret)
            timings.append(elapsed_ms)
            last_payload = payload
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            errors.append(str(error))
        time.sleep(0.03)
    return {
        "path": path,
        "samples": len(timings),
        "errors": errors[:3],
        "p50_ms": round(statistics.median(timings), 3) if timings else None,
        "p95_ms": round(percentile(timings, 95), 3) if timings else None,
        "max_ms": round(max(timings), 3) if timings else None,
        "summary": summarize_payload(path, last_payload),
    }


def summarize_payload(path, payload):
    if not isinstance(payload, dict):
        return {}
    if path == "/rules":
        return {"rules": len(payload.get("rules") or [])}
    if path == "/proxies":
        proxies = payload.get("proxies") or {}
        groups = [name for name, item in proxies.items() if isinstance(item, dict) and item.get("all")]
        return {"proxies": len(proxies), "groups": len(groups)}
    if path == "/providers/proxies":
        return {"providers": len(payload.get("providers") or {})}
    if path == "/connections":
        return {"connections": len(payload.get("connections") or [])}
    return {key: payload.get(key) for key in ("mode", "mixed-port", "log-level") if key in payload}


def count_equivalent(baseline, candidate, tolerance=0.0):
    if baseline is None or candidate is None:
        return False
    if baseline == candidate:
        return True
    delta = abs(float(candidate) - float(baseline))
    allowed = max(1.0, abs(float(baseline)) * tolerance)
    return delta <= allowed


def summary_equivalence(path, baseline, candidate):
    baseline = baseline or {}
    candidate = candidate or {}
    if path == "/configs":
        keys = ("mode", "mixed-port", "log-level")
        mismatches = [
            key for key in keys
            if baseline.get(key) != candidate.get(key)
        ]
        if mismatches:
            return False, f"config fields differ: {', '.join(mismatches)}"
        return True, "configs match"
    if path == "/rules":
        if baseline.get("rules") != candidate.get("rules"):
            return False, f"rules count differs: {baseline.get('rules')} != {candidate.get('rules')}"
        return True, "rule counts match"
    if path == "/proxies":
        for key in ("proxies", "groups"):
            if baseline.get(key) != candidate.get(key):
                return False, f"{key} count differs: {baseline.get(key)} != {candidate.get(key)}"
        return True, "proxy and group counts match"
    if path == "/providers/proxies":
        if baseline.get("providers") != candidate.get("providers"):
            return False, f"provider count differs: {baseline.get('providers')} != {candidate.get('providers')}"
        return True, "provider counts match"
    if path == "/connections":
        if not count_equivalent(
            baseline.get("connections"),
            candidate.get("connections"),
            CONNECTION_COUNT_TOLERANCE,
        ):
            return (
                False,
                f"connection count differs beyond {CONNECTION_COUNT_TOLERANCE:.0%}: "
                f"{baseline.get('connections')} != {candidate.get('connections')}",
            )
        return True, "connection counts match within tolerance"
    return baseline == candidate, "payload summaries match" if baseline == candidate else "payload summaries differ"


def process_rss(match_terms):
    current_pid = os.getpid()
    output = subprocess.run(
        ["ps", "-axo", "pid=,rss=,command="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    rows = []
    for line in output.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid, rss_kb, command = parts
        if int(pid) == current_pid or "scripts/perf_probe.py" in command:
            continue
        if any(term and term in command for term in match_terms):
            rows.append({"pid": int(pid), "rss_mb": round(int(rss_kb) / 1024.0, 2), "command": command})
    return rows


def executable_for_app(app_bundle):
    return os.path.join(app_bundle, "Contents", "MacOS", "clash-for-mac")


def kill_processes(match_terms):
    for term in match_terms:
        if term:
            subprocess.run(["pkill", "-f", term], check=False)


def cold_start_once(app_bundle, base_url, timeout_s, launch_mode, kill_terms, secret=None):
    kill_processes(kill_terms)
    time.sleep(0.8)
    started = time.perf_counter()
    if launch_mode == "exec":
        subprocess.Popen(
            [executable_for_app(app_bundle)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    else:
        subprocess.run(["open", "-n", "-a", app_bundle], check=True)
    deadline = started + timeout_s
    attempts = 0
    while time.perf_counter() < deadline:
        attempts += 1
        try:
            _, payload = request_json(base_url, "/configs", timeout=0.5, secret=secret)
            if isinstance(payload, dict):
                return {
                    "ready": True,
                    "ms": round((time.perf_counter() - started) * 1000.0, 3),
                    "attempts": attempts,
                }
        except Exception:
            time.sleep(0.05)
    return {"ready": False, "ms": round((time.perf_counter() - started) * 1000.0, 3), "attempts": attempts}


def cold_start_probe(app_bundle, base_url, timeout_s, launch_mode, runs, kill_terms, secret=None):
    results = []
    for _ in range(runs):
        results.append(cold_start_once(app_bundle, base_url, timeout_s, launch_mode, kill_terms, secret=secret))
    ready_ms = [item["ms"] for item in results if item.get("ready")]
    return {
        "launch_mode": launch_mode,
        "runs": results,
        "ready_runs": len(ready_ms),
        "p50_ms": round(statistics.median(ready_ms), 3) if ready_ms else None,
        "p95_ms": round(percentile(ready_ms, 95), 3) if ready_ms else None,
        "max_ms": round(max(ready_ms), 3) if ready_ms else None,
    }


def endpoint_by_path(result):
    return {item["path"]: item for item in result.get("endpoints", [])}


def rss_total(result):
    rows = result.get("rss") or []
    return round(sum(float(row.get("rss_mb") or 0.0) for row in rows), 2)


def metric_value(result, key):
    metrics = result.get("ui_metrics") or {}
    value = metrics.get(key)
    if value is not None:
        return value
    short_key = key.removesuffix("_p95_ms")
    nested = metrics.get(short_key)
    if isinstance(nested, dict):
        return nested.get("p95_ms") or nested.get("p95")
    return None


def coverage_summary(result):
    measured_paths = [
        item.get("path") for item in result.get("endpoints", [])
        if item.get("samples") and not item.get("errors")
    ]
    measured_path_set = set(measured_paths)
    return {
        "controller_endpoints": {
            "measured": all(path in measured_path_set for path in ENDPOINTS),
            "required": list(ENDPOINTS),
            "measured_paths": measured_paths,
        },
        "cold_start": {"measured": bool(result.get("cold_start", {}).get("ready_runs"))},
        "rss": {"measured": bool(result.get("rss"))},
        "page_switch": {"measured": metric_value(result, "page_switch_p95_ms") is not None},
        "proxy_toggle": {"measured": metric_value(result, "proxy_toggle_p95_ms") is not None},
        "profile_apply": {"measured": metric_value(result, "profile_apply_p95_ms") is not None},
    }


def missing_check(metric, baseline, candidate, reason):
    return {
        "metric": metric,
        "baseline": baseline,
        "candidate": candidate,
        "passed": False,
        "reason": reason,
    }


def compare_against_baseline(candidate, baseline):
    checks = []
    baseline_endpoints = endpoint_by_path(baseline)
    candidate_endpoints = endpoint_by_path(candidate)
    for path in ENDPOINTS:
        baseline_endpoint = baseline_endpoints.get(path, {})
        candidate_endpoint = candidate_endpoints.get(path, {})
        base_p95 = baseline_endpoint.get("p95_ms")
        cand_p95 = candidate_endpoint.get("p95_ms")
        if not base_p95 or not cand_p95:
            checks.append(missing_check(
                f"{path} p95 latency",
                base_p95,
                cand_p95,
                "missing endpoint latency sample",
            ))
            continue
        speedup = base_p95 / cand_p95
        equivalent, payload_reason = summary_equivalence(
            path,
            baseline_endpoint.get("summary"),
            candidate_endpoint.get("summary"),
        )
        checks.append({
            "metric": f"{path} p95 latency",
            "baseline": base_p95,
            "candidate": cand_p95,
            "speedup": round(speedup, 3),
            "payload_equivalent": equivalent,
            "payload_reason": payload_reason,
            "passed": speedup >= 3.0 and equivalent,
        })

    base_cold = baseline.get("cold_start", {}).get("p95_ms")
    cand_cold = candidate.get("cold_start", {}).get("p95_ms")
    if base_cold and cand_cold:
        speedup = base_cold / cand_cold
        checks.append({
            "metric": "cold start p95",
            "baseline": base_cold,
            "candidate": cand_cold,
            "speedup": round(speedup, 3),
            "passed": speedup >= 3.0,
        })
    else:
        checks.append(missing_check("cold start p95", base_cold, cand_cold, "missing cold-start sample"))

    base_rss = rss_total(baseline)
    cand_rss = rss_total(candidate)
    if base_rss and cand_rss:
        reduction = base_rss / cand_rss
        budget = candidate.get("targets", {}).get("idle_rss_mb", 90)
        checks.append({
            "metric": "idle RSS total",
            "baseline": base_rss,
            "candidate": cand_rss,
            "reduction": round(reduction, 3),
            "passed": reduction >= 3.0 or cand_rss <= budget,
        })
    else:
        checks.append(missing_check("idle RSS total", base_rss, cand_rss, "missing RSS process sample"))

    for key, label in UI_TARGETS:
        base_metric = metric_value(baseline, key)
        cand_metric = metric_value(candidate, key)
        if base_metric and cand_metric:
            speedup = float(base_metric) / float(cand_metric)
            checks.append({
                "metric": label,
                "baseline": base_metric,
                "candidate": cand_metric,
                "speedup": round(speedup, 3),
                "passed": speedup >= 3.0,
            })
        else:
            checks.append(missing_check(label, base_metric, cand_metric, "missing UI metric sample"))

    return {
        "baseline_label": baseline.get("label", "baseline"),
        "candidate_label": candidate.get("label", "candidate"),
        "checks": checks,
        "coverage": {
            "baseline": coverage_summary(baseline),
            "candidate": coverage_summary(candidate),
        },
        "passed": bool(checks) and all(item["passed"] for item in checks),
    }


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def split_terms(value):
    return [term.strip() for term in (value or "").split(",") if term.strip()]


def main():
    parser = argparse.ArgumentParser(description="Probe and compare Clash runtime performance.")
    parser.add_argument("--label", default="candidate")
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    parser.add_argument("--secret")
    parser.add_argument("--samples", type=int, default=40)
    parser.add_argument("--cold-start", action="store_true")
    parser.add_argument("--cold-start-runs", type=int, default=1)
    parser.add_argument("--launch-mode", choices=("open", "exec"), default="open")
    parser.add_argument("--app", default=DEFAULT_APP)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--rss-match", default=DEFAULT_RSS_MATCH)
    parser.add_argument("--kill-match", default=DEFAULT_RSS_MATCH)
    parser.add_argument("--baseline-json")
    parser.add_argument("--ui-metrics-json")
    parser.add_argument("--out")
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()

    rss_terms = split_terms(args.rss_match)
    kill_terms = split_terms(args.kill_match)
    result = {
        "product": "Clash for Mac",
        "label": args.label,
        "base_url": args.base_url,
        "samples": args.samples,
        "targets": {
            "cold_start_p95_ms": 700,
            "page_switch_p95_ms": 16,
            "proxy_toggle_p95_ms": 150,
            "profile_apply_p95_ms": 450,
            "idle_rss_mb": 90,
        },
    }
    if args.cold_start:
        result["cold_start"] = cold_start_probe(
            args.app,
            args.base_url,
            args.timeout,
            args.launch_mode,
            max(1, args.cold_start_runs),
            kill_terms,
            secret=args.secret,
        )
    result["endpoints"] = [endpoint_probe(args.base_url, path, args.samples, secret=args.secret) for path in ENDPOINTS]
    result["rss"] = process_rss(rss_terms)
    if args.ui_metrics_json:
        result["ui_metrics"] = load_json(args.ui_metrics_json)
    result["coverage"] = coverage_summary(result)
    result["timestamp"] = int(time.time())

    if args.baseline_json:
        result["comparison"] = compare_against_baseline(result, load_json(args.baseline_json))

    if args.out:
        write_json(args.out, result)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.fail_on_regression and result.get("comparison") and not result["comparison"]["passed"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
