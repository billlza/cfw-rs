# Data-only package closure consumed by libbox module preparation and source tests.

LIBBOX_MODULE_BUILD_PACKAGES=(
  "./experimental/libbox"
)

LIBBOX_GOMOBILE_BIND_PACKAGES=(
  "github.com/sagernet/gomobile/bind"
  "github.com/sagernet/gomobile/bind/objc"
)

LIBBOX_RACE_TEST_PACKAGES=(
  "./common/tls"
  "./common/urltest"
  "./adapter/outbound"
  "./protocol/group"
  "./protocol/socks"
  "./dns"
  "./dns/transport/hosts"
  "./option"
)

LIBBOX_TEST_PACKAGES=(
  "./protocol/socks"
  "."
  "./adapter"
  "./dns"
  "./option"
  "./common/dialer"
  "./daemon"
  "./protocol/mixed"
  "./experimental/clashapi"
  "./experimental/libbox"
)

LIBBOX_COMPILE_TEST_PACKAGES=(
  "./common/dialer"
  "./route"
)

LIBBOX_VET_PACKAGES=(
  "./common/tls"
  "./common/urltest"
  "./adapter/outbound"
  "./protocol/group"
  "./protocol/socks"
  "."
  "./adapter"
  "./dns"
  "./dns/transport/hosts"
  "./route"
  "./option"
  "./common/dialer"
  "./daemon"
  "./protocol/mixed"
  "./experimental/clashapi"
  "./experimental/libbox"
)
