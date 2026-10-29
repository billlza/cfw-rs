# Mobile egress guard: macOS observer prototype

Status: **read-only development prototype**. This does not create an Internet
relay, route traffic, enforce quotas, operate an M7 Pro, or approve public use.
It is intentionally separate from CFM's signed application and runtime.

## Intended topology

    CFM / CFW peers -> authenticated VPS ingress -> outbound reverse tunnel
                                                       |
                       M7 Pro cellular network <- M7 Agent (if possible)
                                                OR Mac temporary gateway

The Mac operator observes and administers the VPS, but is not on the required
packet-forwarding path. **Hard admission, per-user rate limits, byte quotas,
connection controls, a global carrier-data cutoff and emergency block must
be enforced on the VPS and/or the cellular egress node.** A Mac-based observer
cannot stop usage while the Mac is sleeping, offline or compromised.

Independently running software on NETGEAR MR7450-100EUS firmware is *unproven*.
Do not install third-party images, use unknown router APIs or assume root access.
Do not treat a same-version community report as an exact signed firmware hash.
A Mac temporary gateway is a separate fallback, not evidence of on-router support.

## Current scope

- A **read-only** macOS-compatible Python 3.11+ CLI collects the
  WireGuard show/transfer output of a *dedicated user-ingress* WireGuard
  interface. This requires a separately provisioned VPS and user peers.
- The operator configures a strict allowlist of peer public keys and aliases.
  Unknown peer keys, per-peer tunnel-session byte threshold breaches, counter
  rollback/recreation and sustained interval-average rates receive alerts.
- A private local state file uses an exclusive lock and atomic replacement.
  Peer key material is stored as hashes; program output uses only aliases or
  short key fingerprints. Neither keys, destination URLs nor packet payloads
  are logged.
- SSH observation uses BatchMode, strict host-key checking, a fixed WireGuard
  show command and a bounded deadline. Configure a separate *read-only* telemetry
  SSH key, pinned host key and narrowly scoped server permission. No shell
  execution is sourced from a policy file or peer name.
- The program returns 0 on an ordinary sample, 2 on alerts, and 1 on
  observation/policy/state errors. Exit 1 must itself trigger an operator alert:
  absence of telemetry is not evidence that the network is safe.

The policy fields session_alert_bytes and rate_alert_bps are **alert thresholds
only**: they neither disconnect a peer nor rate-limit traffic. An empty
observation, unknown peer or absent configured peer is reported as a problem,
not interpreted as safe idle.

**Counters are WireGuard transfer values since the peer/interface last
started, not the SIM's billed data and not accurate daily/monthly usage.**
After restarts these counters may reset. This observer explicitly reports
rollbacks, but a reset entirely between samples can evade it. Rate is the
average between samples, not an instantaneous burst limit. No code in this
prototype modifies the VPS, router, firewall or VPN peers.

## Offline smoke test

Use Python 3.11+ on macOS or Linux:

    cd tools/mobile-egress-guard
    python3 -m unittest discover -s tests -v
    python3 -m py_compile observer.py

Create a policy in a private local file with a dedicated **public** WireGuard
peer key (the example below is a synthetic test key, never deploy it):

    {
      "version": 1,
      "interface": "wg-users",
      "peers": [
        {
          "id": "test-user",
          "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
          "session_alert_bytes": 104857600,
          "rate_alert_bps": 8000000
        }
      ]
    }

For a **local test only**, a sample file contains one peer per line, exactly
three TAB-separated fields: public key, received bytes, transmitted bytes.

    python3 observer.py \
      --policy /path/to/policy.json \
      --state /path/to/private-state/state.json \
      --sample-file /path/to/transfer.tsv

For future VPS read-only observation (requires dedicated wg-users and
least-privilege SSH permissions to be configured and tested separately):

    python3 observer.py \
      --policy /path/to/policy.json \
      --state /path/to/private-state/state.json \
      --ssh-host cfw-egress-audit

The SSH host must be a configured alias whose host key is pinned in
known_hosts. The remote command is /usr/bin/wg show wg-users transfer.
Use a forced-command restricted key and only the minimum permission to retrieve
this fixed interface's counters. Do **not** provide arbitrary root shell or
broad passwordless sudo rights for telemetry. Do not put private SSH keys,
router admin passwords or tokens in policy JSON.

Apple launchd can run the one-shot monitor periodically after a real deployment
has been validated. No daemon is auto-installed by this prototype.

## Firmware source intake (offline only)

When NETGEAR supplies a source archive, the separate analyzer can inventory
it without extracting or executing any of its content:

    python3 firmware_intake.py /path/to/received-vendor-source.tgz

The output contains a SHA-256 digest, bounded member counts, declared content
size, suspicious duplicate paths, link counts and a small source-path sample.
Absolute paths and traversal are rejected. **An OSS tar archive is not a
flashable firmware image or evidence that arbitrary applications can run on
the hotspot.** Do not copy build scripts to the M7 Pro or try unknown images.

See MR7450.md for verified model evidence, device-specific documentation,
remaining execution-environment questions and safe fallback architecture.

## VPS enforcement requirements (not yet implemented)

1. **Default deny**: peer-specific admission with unique, revocable keys,
   restricted routes and no unauthenticated public forward proxy.
2. **Hard counters**: kernel-side (e.g. nftables) quotas/rate limits and
   connection admission, persistent across console outages. Validate IPv4
   and IPv6, UDP/TCP, tunnel restarts, rule replacement and outage behavior.
3. **Data budget**: dedicated global limit based on a measured 5G uplink,
   with a separate M7 / carrier usage reading when an authentic documented
   read-only API exists. WireGuard counters alone cannot establish billed usage.
4. **Abuse response**: revoke a specific account/peer, disable public
   admission, retain minimal security events, record operator audit events,
   and verify rule persistence after service restart. Test malicious peers,
   account theft, flood/scan attempts and accidental operator disconnects.
5. **Privacy and governance**: collect only necessary identity, timestamps,
   volumes and security events; avoid full traffic/payload or browsing-history
   collection. Define retention, disclosure, incident response and complaint
   handling before serving other users. Automated traffic rules cannot prove
   whether an encrypted user's conduct is legal.
6. **Operational/legal gate**: before public or paid sharing, obtain advice
   on the UK Student-visa business restrictions, the mobile operator's
   contractual permissions and whether UK communications-provider rules
   apply. A private lab proof-of-concept is not public service approval.

Do not treat passing observer tests as proof of quota enforcement,
router-side execution, safe service operation or network throughput.

## Technical references

- WireGuard show/dump counters:
  https://github.com/WireGuard/wireguard-tools/blob/master/src/man/wg.8
- Linux nftables named quotas and rate limits:
  https://wiki.nftables.org/wiki-nftables/index.php/Quotas
  https://wiki.nftables.org/wiki-nftables/index.php/Rate_limiting_matchings
- Apple launchd and ServiceManagement:
  https://developer.apple.com/documentation/servicemanagement
- UK ICO data minimisation:
  https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/data-minimisation/
