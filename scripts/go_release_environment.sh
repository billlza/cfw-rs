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

# The source-bound generator copies the verified inputs into a private build
# workspace and corrects two dependency files. Original source and caches remain
# unchanged. A relative Go module replacement keeps build identities stable.
prepare_libbox_build_workspace() {
  [[ $# -eq 3 && "${GOFLAGS:-}" == '-mod=readonly -trimpath' ]] || {
    echo "error: build workspace requires the sanitized Go environment" >&2
    return 1
  }
  local source_root="$1" go_bin="$2" output="$3" workspace replacement
  workspace="$(
    cd "$source_root" && "$go_bin" run ./cmd/cfm-build-workspace \
      -module-source "$GOMODCACHE/github.com/sagernet/sing@v0.9.4" \
      -output "$output"
  )" || return 1
  [[ "$workspace" == "$output" && -d "$workspace" && ! -L "$workspace" ]] || {
    echo "error: build workspace did not produce its exact output" >&2
    return 1
  }
  replacement="$(cd "$workspace" && "$go_bin" list -m \
    -f '{{.Version}} {{if .Replace}}{{.Replace.Path}}{{end}}' github.com/sagernet/sing)" || return 1
  [[ "$replacement" == 'v0.9.4 ./cfw-dependencies/sing' ]] || {
    echo "error: build workspace resolved an unexpected sing replacement" >&2
    return 1
  }
  printf '%s\n' "$workspace"
}
