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

The endpoint has its own Go toolchain, independent of the product's
`GO_VERSION`. Three pins in `scripts/dependency_pins.env` identify it:
`PACKET_EVIDENCE_ENDPOINT_GO_VERSION` and
`PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256` name the official
darwin-arm64 Go archive that builds it, and
`PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256` is the reviewed Linux/amd64 output.
A product Go bump leaves the endpoint unchanged; bumping the endpoint's Go is a
separate, deliberate change. Build the artifact from the repository root in
bash. The recipe stops at the first failure: it checks the downloaded archive
before extracting it, builds with no inherited Go environment, compares the
output with the binary pin, and removes its temporary toolchain.

```sh
(
  set -euo pipefail
  source scripts/dependency_pins.env
  work="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/packet-evidence-endpoint.XXXXXX")"
  trap '/bin/rm -rf "$work"' EXIT
  archive="$work/go.darwin-arm64.tar.gz"
  /usr/bin/curl --fail --location --proto '=https' --tlsv1.2 \
    "https://go.dev/dl/go$PACKET_EVIDENCE_ENDPOINT_GO_VERSION.darwin-arm64.tar.gz" \
    --output "$archive"
  printf '%s  %s\n' "$PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256" "$archive" |
    /usr/bin/shasum -a 256 --check
  /bin/mkdir "$work/go" "$work/home"
  /usr/bin/tar -xzf "$archive" -C "$work/go" --strip-components 1
  /bin/mkdir -p target
  /usr/bin/env -i PATH=/usr/bin:/bin HOME="$work/home" GOTOOLCHAIN=local \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE="$work/go-build-cache" \
    "$work/go/bin/go" -C tools/packet-evidence-endpoint build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o ../../target/packet-evidence-endpoint-linux-amd64 .
  printf '%s  %s\n' "$PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256" \
    target/packet-evidence-endpoint-linux-amd64 | /usr/bin/shasum -a 256 --check
)
```

An endpoint Go bump first changes the two toolchain pins; the final comparison
then fails until `PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256` holds the new output
digest, after which the recipe must reproduce it.

`scripts/verify_pinned_build_inputs.py` requires this exact recipe, and requires
`install-endpoint.sh` and every endpoint identity in
`scripts/physical_capture/packet_endpoints.json` to carry exactly
`PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256`. Those files run on or describe the
instances and cannot read the pin file, so they keep a checked copy.

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

The installer, service unit, resolver configuration, capture sudoers, strict
known-hosts and endpoint policy SHA-256 values are the `packetEvidenceEndpoint`
source digests in `scripts/pinned_build_inputs.json`; this README repeats none
of them. An endpoint Go bump rebinds the binary pin and therefore the
installer, the endpoint identities and the policy, together with the installer,
identity and policy digests recorded for them; the instances then run the
earlier binary until the installation transaction is rerun, which physical
assurance collection requires.
All three endpoint installation transactions and both dedicated remote-capture
allow/deny preflights succeeded with an earlier binary before the instances
were stopped. That is
provisioning evidence only. The IAP grant is attached to each IAP TCP tunnel
instance resource, not to Compute instance IAM or project IAM: the fixed client
service account has `roles/iap.tunnelResourceAccessor` under condition
`destination.port == 22` (title `packet-capture-ssh-only`). Future audits must
read that IAP resource policy directly. The Host-owned DNS transaction and
remote stream capture now have closed source paths.

This GCE executable is not a LAN endpoint: it owns UDP/DNS behavior and assumes
a server installation model. The `lan-bypass` endpoint is the separately
pinned, test-only iPhone Packet-LAN peer in `tools/physical-transport-peer-ios`.
