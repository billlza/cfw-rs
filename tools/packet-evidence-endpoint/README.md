# Packet evidence endpoint

This command is the bounded remote peer for the v0.4.0 physical packet matrix.
It has no runtime flags, configuration file, packet payload logging, or
shell-command surface. One fixed binary binds:

- TCP and UDP port `44333` on IPv4 and IPv6 for transport observations;
- UDP port `53` on IPv4 and IPv6 for independent DNS resolution capture.

Transport input is discarded. DNS replies are limited to exact
`<token>.evidence.test` A/AAAA questions with a 16–63 byte alphanumeric/hyphen
token. They are authoritative, non-recursive, use TTL `0`, and return only
`192.0.2.1` or `2001:db8::1`; every unrelated or malformed request is silent.
GCE firewall rules decide which listeners are reachable on each endpoint. The
three endpoint instances remain stopped outside a scheduled physical run.

Remote DNS capture uses the impersonated OS Login service account
`packet-capture-client@cfw-release-evidence-20260730.iam.gserviceaccount.com`.
Its OS Login and IAP grants exist only on the two DNS instances, and the IAP
condition permits only destination port 22. It has no administrator role: the
installed sudoers rule permits only the exact digest-bound `tcpdump` command
that streams UDP/53 pcap bytes to standard output and exits after the exact
six-packet, three-query/three-response DNS contract. The capture identity
cannot select an interface, filter, path, count, or post-capture command.

Build the Linux artifact with the repository-pinned Go toolchain:

```sh
GOTOOLCHAIN=local \
CGO_ENABLED=0 \
GOOS=linux \
GOARCH=amd64 \
GOCACHE="$PWD/target/toolchains/go-build-cache" \
target/toolchains/go-1.26.6/bin/go \
  -C tools/packet-evidence-endpoint \
  build \
  -trimpath \
  -ldflags='-s -w -buildid=' \
  -o ../../target/packet-evidence-endpoint-linux-amd64 \
  .
```

The reviewed Linux/amd64 artifact from those exact inputs has SHA-256
`c63c202b22823197ad12cb2d5f484c95be25904260ed266083dcca6fc766db6c`.

The reviewed endpoint policy must bind the resulting SHA-256, each GCE
instance identity, the exact external IPv4/IPv6 addresses, the SSH host-key
digest used by remote capture, and the systemd unit bytes. A fixture address,
mutable DNS name, unpinned host key, or operator-supplied endpoint remains a
release blocker.

`install-endpoint.sh` is the only supported Debian installation transaction.
It installs `tcpdump`, removes the unused MTA, installs the exact binary and
systemd unit from `/tmp`, validates and installs the fixed capture sudoers
rule, and rejects any source or installed-file digest drift. The Debian package
transaction requires `tcpdump` `4.99.3-1` and verifies the installed executable
digest before the sudoers rule can become usable. It disables
`systemd-resolved` so the bounded DNS peer can own public UDP port 53, installs
the fixed GCE metadata resolver file, disables mutable background package
upgrades and the unneeded telemetry manager, checks service health, and only
then deletes its staging files. Run it only after separately verifying the five
staged file digests.

The final installer, service unit, resolver configuration, capture sudoers and
strict known-hosts SHA-256 values are respectively
`14b45b1705f762057ac38d836f2ac5c7d3721e72ec0ec45b72505b354f0d05c8`,
`7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996`,
`b290cc794e7f0faac9ebbd63f83aad67d23086b48206295d5d6a2767721c1e62`,
`a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411`,
and `3741384531dbd24c65a2225386beae492bf92c61fdf2d5b90b57051d57be36ba`.
The source-pinned endpoint policy SHA-256 is
`a487fc3ebc0698b4b5ee0eb40dfd388fc0c5ee0994bbd7ffc698e9f817a272dd`.
All three endpoint installation transactions and both dedicated remote-capture
allow/deny preflights succeeded before the instances were stopped. That is
provisioning evidence only. The IAP grant is attached to each IAP TCP tunnel
instance resource, not to Compute instance IAM or project IAM: the fixed client
service account has `roles/iap.tunnelResourceAccessor` under condition
`destination.port == 22` (title `packet-capture-ssh-only`). Future audits must
read that IAP resource policy directly. The Host-owned DNS transaction and
remote stream capture now have closed source paths; the controlled Android LAN
peer remains the sole Packet source-readiness blocker.

## Controlled Android LAN peer (not yet admitted)

The GCE endpoint executable is not the LAN artifact. It also owns UDP/DNS
behavior and assumes a server installation model, so reusing it on an
unprivileged phone would widen the LAN proof surface. The pending LAN source
package must be a separate minimal `linux/arm64` build variant with this closed
contract:

- one compile-time TCP listener on port `44333`; no flags, environment
  configuration, config files, UDP socket, DNS role, subprocess, or shell;
- a fixed connection cap and deadline, a maximum 64-byte request, read/discard
  semantics, and explicit close on overflow, timeout, or I/O failure;
- standard-library-only source, `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`,
  reproducible build flags, unit tests for bounds/timeouts, and a reviewed
  source plus executable SHA-256 before admission;
- no root requirement: deploy and execute as the Android `shell` user from a
  private fixed path made available by an explicitly authorized ADB session.

Admission requires one live on-device capture transaction. It must retain the
exact hotspot peer IPv4 address and Mac route/interface, SHA-256 hashes of the
ADB serial, Android build fingerprint, and boot ID, plus the raw verified-boot
state, device-lock state, `arm64-v8a` ABI, pushed/executed binary SHA-256,
executable owner/mode, process identity, fixed ADB argv receipts, and an
independent packet window from the Mac. Until those fields are collected and
reviewed, `lan-bypass` stays absent from `packet_endpoints.json` and both LAN
source constants stay `None`.
