# Controlled Android LAN peer

`packet-lan-peer` is the receive-only peer for the v0.4.0 physical
`lan-bypass` observation. It is intentionally a separate executable from the
GCE packet endpoint: this peer owns exactly one IPv4 TCP listener on `:44333` and
has no UDP, DNS, response, payload logging, flag, environment, configuration,
subprocess, or shell surface.

The protocol is one TCP byte stream terminated by client EOF. The peer reads
and discards at most 64 request bytes, waits at most five seconds, and then
closes the connection. A 65th byte, timeout, read failure, deadline failure,
or connection-cap refusal causes an explicit close. At most eight requests
are processed concurrently. `SIGINT` and `SIGTERM` close the listener and all
active connections before the process exits.

Build and verify with the repository-pinned Go toolchain:

```sh
scripts/build_packet_lan_peer.sh
scripts/verify_packet_lan_peer.sh
```

The build is fixed to `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` with `-trimpath`
and `-ldflags='-s -w -buildid='`. The build script performs two isolated builds
and refuses to publish the artifact unless their bytes are identical. The
verified output is:

```text
target/packet-lan-peer-linux-arm64
```

## Fixed Android deployment

The authorized physical-capture transaction must deploy the reviewed artifact
to this exact private shell-owned path:

```text
/data/local/tmp/cfw-release-evidence-v040/packet-lan-peer-linux-arm64
```

The directory must be owned by Android `shell:shell` with mode `0700`; the
binary must be owned by `shell:shell` with mode `0500`. Port `44333` is
unprivileged, so neither deployment nor execution requires root. The capture
transaction, rather than this package, owns the fixed ADB argv, artifact hash
comparison, Android identity receipts, process lifecycle, and independent Mac
packet window. Do not admit a mutable path, renamed binary, root-owned process,
operator-selected address/port, or artifact whose on-device SHA-256 differs
from the reviewed local artifact.
