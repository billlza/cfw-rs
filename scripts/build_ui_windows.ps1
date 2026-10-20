# Development UI build. Windows distribution admission remains a separate gate.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
$pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dependency_pins.env') -Raw
$versions = [regex]::Matches($pins, '(?m)^NODE_VERSION=([0-9]+\.[0-9]+\.[0-9]+)\r?$')
if ($versions.Count -ne 1) { throw 'Missing or ambiguous Node.js version pin' }
$expected = "v$($versions[0].Groups[1].Value)"
$node = (Get-Command node -CommandType Application -ErrorAction Stop |
    Select-Object -First 1).Source
$actual = & $node --version
if ($LASTEXITCODE -ne 0 -or $actual -cne $expected) {
    throw "The UI build requires Node.js $expected; selected executable reported $actual"
}
& $node (Join-Path $repository 'scripts/build_ui.mjs')
if ($LASTEXITCODE -ne 0) { throw 'Shared UI build failed' }
