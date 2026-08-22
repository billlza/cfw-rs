#!/bin/sh
# Fixed Debian installation transaction for the bounded packet endpoint.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "packet evidence endpoint installation requires root" >&2
  exit 77
fi

export DEBIAN_FRONTEND=noninteractive

verify_sha256() {
  expected="$1"
  path="$2"
  actual="$(/usr/bin/sha256sum "$path")"
  actual="${actual%% *}"
  if [ "$actual" != "$expected" ]; then
    echo "packet evidence endpoint digest mismatch: $path" >&2
    exit 78
  fi
}

verify_sha256 \
  c63c202b22823197ad12cb2d5f484c95be25904260ed266083dcca6fc766db6c \
  /tmp/packet-evidence-endpoint-linux-amd64
verify_sha256 \
  7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996 \
  /tmp/packet-evidence-endpoint.service
verify_sha256 \
  b290cc794e7f0faac9ebbd63f83aad67d23086b48206295d5d6a2767721c1e62 \
  /tmp/packet-evidence-resolv.conf
verify_sha256 \
  a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411 \
  /tmp/packet-evidence-capture.sudoers

/usr/bin/apt-get update
/usr/bin/apt-get install -y --no-install-recommends tcpdump=4.99.3-1
/usr/bin/apt-get purge -y exim4-base exim4-config exim4-daemon-light

if [ "$(/usr/bin/dpkg-query -W -f='${Version}' tcpdump)" != "4.99.3-1" ]; then
  echo "packet evidence endpoint tcpdump version mismatch" >&2
  exit 78
fi
verify_sha256 \
  c97881e39b54571829ec22b98cfa9c2348c7449a92fd761ebee7826b47ef4616 \
  /usr/bin/tcpdump

/usr/bin/install -d -o root -g root -m 0755 /usr/local/libexec
/usr/bin/install -o root -g root -m 0755 \
  /tmp/packet-evidence-endpoint-linux-amd64 \
  /usr/local/libexec/cfw-packet-evidence-endpoint
/usr/bin/install -o root -g root -m 0644 \
  /tmp/packet-evidence-endpoint.service \
  /etc/systemd/system/packet-evidence-endpoint.service
/usr/sbin/visudo -cf /tmp/packet-evidence-capture.sudoers
/usr/bin/install -o root -g root -m 0440 \
  /tmp/packet-evidence-capture.sudoers \
  /etc/sudoers.d/cfw-packet-evidence-capture
/usr/sbin/visudo -cf /etc/sudoers.d/cfw-packet-evidence-capture

/usr/bin/systemctl daemon-reload
/usr/bin/systemctl disable --now systemd-resolved.service
/usr/bin/rm /etc/resolv.conf
/usr/bin/install -o root -g root -m 0644 \
  /tmp/packet-evidence-resolv.conf \
  /etc/resolv.conf
/usr/bin/systemctl enable packet-evidence-endpoint.service
/usr/bin/systemctl restart packet-evidence-endpoint.service
/usr/bin/systemctl disable --now google-guest-agent-manager.service
/usr/bin/systemctl mask --now \
  apt-daily.service \
  apt-daily-upgrade.service \
  apt-daily.timer \
  apt-daily-upgrade.timer \
  unattended-upgrades.service

/usr/bin/systemctl is-active --quiet packet-evidence-endpoint.service

verify_sha256 \
  c63c202b22823197ad12cb2d5f484c95be25904260ed266083dcca6fc766db6c \
  /usr/local/libexec/cfw-packet-evidence-endpoint
verify_sha256 \
  7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996 \
  /etc/systemd/system/packet-evidence-endpoint.service
verify_sha256 \
  b290cc794e7f0faac9ebbd63f83aad67d23086b48206295d5d6a2767721c1e62 \
  /etc/resolv.conf
verify_sha256 \
  a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411 \
  /etc/sudoers.d/cfw-packet-evidence-capture

/usr/bin/rm \
  /tmp/packet-evidence-endpoint-linux-amd64 \
  /tmp/packet-evidence-endpoint.service \
  /tmp/packet-evidence-resolv.conf \
  /tmp/packet-evidence-capture.sudoers \
  /tmp/install-endpoint.sh
