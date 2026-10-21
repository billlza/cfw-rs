# Development UI build. Windows distribution admission remains a separate gate.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'node_runtime.psm1') -Force
$node = Get-CfwPinnedNode
& $node (Join-Path $repository 'scripts/build_ui.mjs')
if ($LASTEXITCODE -ne 0) { throw 'Shared UI build failed' }
