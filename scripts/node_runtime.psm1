# Resolve one executable according to PATH, then verify the repository pin.
# Get-Command may return several applications even without -All.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CfwPinnedNode {
    $pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dependency_pins.env') -Raw
    $versions = [regex]::Matches($pins, '(?m)^NODE_VERSION=([0-9]+\.[0-9]+\.[0-9]+)\r?$')
    if ($versions.Count -ne 1) { throw 'Missing or ambiguous Node.js version pin' }
    $expected = "v$($versions[0].Groups[1].Value)"
    $node = (Get-Command node -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source
    $actual = & $node --version
    if ($LASTEXITCODE -ne 0 -or $actual -cne $expected) {
        throw "Node.js $expected is required; selected executable reported $actual"
    }
    return $node
}
Export-ModuleMember -Function Get-CfwPinnedNode
