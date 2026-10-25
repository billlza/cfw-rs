module github.com/billlza/cfw-rs/tools/go-release-tools

go 1.27.3

tool (
	github.com/sagernet/gomobile/cmd/gobind
	github.com/sagernet/gomobile/cmd/gomobile
	golang.org/x/vuln/cmd/govulncheck
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/sagernet/gomobile v0.1.13 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
)
