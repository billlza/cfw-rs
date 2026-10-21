#!/usr/bin/env python3
"""Read-only WireGuard peer accounting for a macOS operator console.

This is an observer, NOT an enforcement point or a mobile-carrier data meter.
Hard quotas and revocation belong on the VPS even while the Mac is offline.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

MAX_INPUT = 524_288
MAX_PEERS = 256
MAX_COUNTER = (1 << 64) - 1
IFACE = re.compile(r"[a-zA-Z0-9_-]{1,15}\Z")
SSH_ALIAS = re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")
PEER_ID = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


class GuardError(Exception):
    """A rejected observation or unsafe local state."""


def reject_duplicate_json(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("duplicate JSON field")
        result[key] = value
    return result


def bounded_json(raw: bytes) -> object:
    if len(raw) > MAX_INPUT:
        raise GuardError("JSON exceeds input bound")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_json)
    except (UnicodeError, ValueError) as exc:
        raise GuardError("invalid JSON") from exc


def exactly(value: object, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise GuardError("document fields do not match the required schema")
    return value


def bounded_integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive) or value > MAX_COUNTER:
        raise GuardError("invalid integer or limit")
    return value


def key_digest(public_key: str) -> str:
    if not isinstance(public_key, str):
        raise GuardError("WireGuard peer key is invalid")
    try:
        decoded = base64.b64decode(public_key, validate=True)
        if len(decoded) != 32 or base64.b64encode(decoded).decode() != public_key:
            raise GuardError("WireGuard peer key is noncanonical")
    except (ValueError, binascii.Error) as exc:
        raise GuardError("WireGuard peer key is invalid") from exc
    return hashlib.sha256(decoded).hexdigest()


def load_policy(path: Path) -> dict:
    data = exactly(bounded_json(path.read_bytes()), {"version", "interface", "peers"})
    if data["version"] != 1 or type(data["version"]) is not int:
        raise GuardError("unsupported policy version")
    if not isinstance(data["interface"], str) or not IFACE.fullmatch(data["interface"]):
        raise GuardError("invalid WireGuard interface")
    peers = data["peers"]
    if not isinstance(peers, list) or not 1 <= len(peers) <= MAX_PEERS:
        raise GuardError("invalid policy peer count")
    by_digest = {}
    ids = set()
    for entry in peers:
        peer = exactly(entry, {"id", "public_key", "session_limit_bytes", "rate_limit_bps"})
        alias = peer["id"]
        if not isinstance(alias, str) or not PEER_ID.fullmatch(alias) or alias in ids:
            raise GuardError("invalid or repeated peer id")
        digest = key_digest(peer["public_key"])
        if digest in by_digest:
            raise GuardError("duplicate peer key")
        bounded_integer(peer["session_limit_bytes"], positive=True)
        bounded_integer(peer["rate_limit_bps"], positive=True)
        by_digest[digest] = {
            "id": alias,
            "session_limit_bytes": peer["session_limit_bytes"],
            "rate_limit_bps": peer["rate_limit_bps"],
        }
        ids.add(alias)
    return {"interface": data["interface"], "peers": by_digest}


def parse_transfer(text: str) -> dict[str, tuple[int, int]]:
    if len(text.encode("utf-8")) > MAX_INPUT:
        raise GuardError("WireGuard observation exceeds input bound")
    result = {}
    for line in text.splitlines():
        if not line:
            raise GuardError("blank WireGuard observation line")
        columns = line.split("\t")
        if len(columns) != 3:
            raise GuardError("unexpected WireGuard transfer format")
        digest = key_digest(columns[0])
        if digest in result:
            raise GuardError("repeated WireGuard peer in observation")
        if any(not value.isascii() or not value.isdecimal() for value in columns[1:]):
            raise GuardError("invalid WireGuard byte counter")
        result[digest] = tuple(bounded_integer(int(v)) for v in columns[1:])
        if len(result) > MAX_PEERS:
            raise GuardError("too many WireGuard peers")
    return result


def observe_via_ssh(host: str, interface: str) -> str:
    if not SSH_ALIAS.fullmatch(host) or host.startswith("-"):
        raise GuardError("SSH destination must be a configured host alias")
    if not IFACE.fullmatch(interface):
        raise GuardError("invalid WireGuard interface")
    # Never execute a caller-provided remote command. Configure a read-only,
    # narrowly privileged wg-show command on the VPS instead of general sudo.
    command = [
        "ssh", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=5", "-oConnectionAttempts=1",
        "--", host, "/usr/bin/wg", "show", interface, "transfer",
    ]
    try:
        process = subprocess.run(command, capture_output=True, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError("authenticated remote observation was unavailable") from exc
    if process.returncode:
        raise GuardError("remote WireGuard observation failed")
    if len(process.stdout) > MAX_INPUT:
        raise GuardError("remote observation exceeds input bound")
    try:
        return process.stdout.decode("utf-8")
    except UnicodeError as exc:
        raise GuardError("remote WireGuard observation is not UTF-8") from exc


def _safe_state_file(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_mode & 0o077 or st.st_size > MAX_INPUT):
            raise GuardError("state must be an owned private regular file")
        raw = handle.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise GuardError("state exceeds size bound")
        return raw


def load_state(path: Path) -> dict | None:
    raw = _safe_state_file(path)
    if raw is None:
        return None
    document = exactly(bounded_json(raw), {"version", "observed_at", "peers", "uncertain"})
    if document["version"] != 1 or type(document["version"]) is not int:
        raise GuardError("unsupported state version")
    bounded_integer(document["observed_at"])
    peers = document["peers"]
    uncertain = document["uncertain"]
    if not isinstance(peers, dict) or len(peers) > MAX_PEERS:
        raise GuardError("invalid state peer table")
    if not isinstance(uncertain, list) or len(uncertain) > MAX_PEERS:
        raise GuardError("invalid uncertain-peer table")
    if len(set(uncertain)) != len(uncertain):
        raise GuardError("duplicate uncertain-peer entry")
    for digest, sample in peers.items():
        if not DIGEST.fullmatch(digest):
            raise GuardError("invalid state peer identity")
        record = exactly(sample, {"rx", "tx"})
        bounded_integer(record["rx"])
        bounded_integer(record["tx"])
    for digest in uncertain:
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise GuardError("invalid uncertain-peer identity")
    return document


@contextlib.contextmanager
def exclusive_state(path: Path):
    parent = path.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise GuardError("state directory must be owned and not writable by others")
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise GuardError("state lock must be a private regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GuardError("another observer holds the state lock") from exc
        yield
    finally:
        os.close(fd)


def save_state(path: Path, data: dict) -> None:
    # The caller holds the state lock. Never follow or replace an existing
    # symlink; preserve a complete previous snapshot on write failure.
    _safe_state_file(path)
    fd, temporary = tempfile.mkstemp(prefix=".egress-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write((json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def evaluate(policy: dict, samples: dict[str, tuple[int, int]],
             previous: dict | None, observed_at: int) -> tuple[dict, dict]:
    # Nanosecond precision prevents repeated checks in the same wall-clock second
    # from overwriting each other or triggering a false clock rollback.
    bounded_integer(observed_at, positive=True)
    if previous is not None and observed_at <= previous["observed_at"]:
        raise GuardError("observation clock did not advance; retained the last trusted state")
    prior = previous["peers"] if previous else {}
    uncertain = set(previous["uncertain"]) if previous else set()
    elapsed_ns = observed_at - previous["observed_at"] if previous else None
    details = []
    alerts = []
    for digest, (rx, tx) in sorted(samples.items()):
        rule = policy["peers"].get(digest)
        alias = rule["id"] if rule else "unknown:" + digest[:12]
        total = rx + tx
        delta = None
        if rule is None:
            alerts.append({"code": "unregistered_peer", "peer": alias})
        elif total > rule["session_limit_bytes"]:
            alerts.append({"code": "session_budget_exceeded", "peer": alias})
        if digest in prior:
            old = prior[digest]
            if rx < old["rx"] or tx < old["tx"]:
                uncertain.add(digest)
            else:
                delta = rx - old["rx"] + tx - old["tx"]
                if rule and delta * 8 * 1_000_000_000 > rule["rate_limit_bps"] * elapsed_ns:
                    alerts.append({"code": "observed_rate_exceeded", "peer": alias})
        if digest in uncertain:
            alerts.append({"code": "counter_reset_or_mismatch", "peer": alias})
        details.append({
            "id": alias, "rx_bytes": rx, "tx_bytes": tx,
            "tunnel_session_bytes": total, "interval_bytes": delta,
        })
    # A reset remains suspicious across subsequent observations until an
    # operator intentionally establishes a new baseline.
    persisted = {
        "version": 1, "observed_at": observed_at,
        "peers": {digest: {"rx": rx, "tx": tx} for digest, (rx, tx) in samples.items()},
        "uncertain": sorted(uncertain),
    }
    report = {
        "version": 1,
        "observed_at": dt.datetime.fromtimestamp(observed_at / 1_000_000_000, dt.timezone.utc).isoformat(),
        "interface": policy["interface"],
        "status": "alert" if alerts else "ok",
        "peer_count": len(samples),
        "first_observation": previous is None,
        "peers": details,
        "alerts": alerts,
        "note": "Advisory WireGuard tunnel counters, not cellular billed bytes or VPS enforcement",
    }
    return report, persisted


def main(argv: list[str] | None = None) -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--policy", type=Path, required=True)
    args.add_argument("--state", type=Path, required=True)
    source = args.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample-file", type=Path)
    source.add_argument("--ssh-host")
    opt = args.parse_args(argv)
    try:
        policy = load_policy(opt.policy.expanduser())
        state_path = opt.state.expanduser()
        with exclusive_state(state_path):
            previous = load_state(state_path)
            if opt.sample_file is not None:
                raw = opt.sample_file.read_bytes()
                if len(raw) > MAX_INPUT:
                    raise GuardError("sample file exceeds input bound")
                observation = raw.decode("utf-8")
            else:
                observation = observe_via_ssh(opt.ssh_host, policy["interface"])
            samples = parse_transfer(observation)
            report, next_state = evaluate(policy, samples, previous, time.time_ns())
            save_state(state_path, next_state)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 2 if report["status"] == "alert" else 0
    except (GuardError, OSError, UnicodeError, ValueError) as exc:
        # No raw SSH stderr, WireGuard key, or network payload is exposed.
        print(f"egress observer: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
