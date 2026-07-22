#!/usr/bin/env bash
# Hermetic Go environment shared by the explicit dependency-preparation and
# offline libbox build phases. Call exactly one configure_* function after
# setting GOPATH/GOBIN/GOMODCACHE/GOCACHE for the pinned toolchain.

sanitize_go_environment() {
  unset \
    AR CC CXX PKG_CONFIG SDKROOT \
    CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS \
    GO111MODULE GOARCH GOENV GOEXPERIMENT GOFLAGS GOHOSTARCH GOHOSTOS GOOS \
    GOPRIVATE GONOPROXY GONOSUMDB GOPROXY GOSUMDB GOWORK GOVCS

  export GOENV=off
  export GOFLAGS='-mod=readonly -trimpath'
  export GONOPROXY='none'
  export GONOSUMDB='none'
  export GOPRIVATE='none'
  export GOTOOLCHAIN=local
  export GOTELEMETRY=off
  export GOWORK=off
  export GOVCS='*:off'
}

configure_networked_go_environment() {
  sanitize_go_environment
  export GOPROXY='https://proxy.golang.org'
  export GOSUMDB='sum.golang.org'
}

configure_offline_go_environment() {
  sanitize_go_environment
  export GOPROXY=off
  export GOSUMDB=off
}
