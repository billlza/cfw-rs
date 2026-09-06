# Data-only package closure consumed by libbox module preparation and source tests.

LIBBOX_MODULE_BUILD_PACKAGES=(
  "./experimental/libbox"
)

LIBBOX_GOMOBILE_BIND_PACKAGES=(
  "github.com/sagernet/gomobile/bind"
  "github.com/sagernet/gomobile/bind/objc"
)

LIBBOX_RACE_TEST_PACKAGES=(
  "./dns"
  "./option"
)

LIBBOX_TEST_PACKAGES=(
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
