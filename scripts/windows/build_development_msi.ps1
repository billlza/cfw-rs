param(
    [Parameter(Mandatory)][string]$Runtime,
    [Parameter(Mandatory)][string]$DesktopDirectory,
    [Parameter(Mandatory)][string]$EngineDirectory,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Output
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Windows development packaging requires Windows' }
if (Test-Path -LiteralPath $Output) { throw 'Package output must be a new directory' }
$desktopReceipt = Get-Content -LiteralPath (Join-Path $DesktopDirectory 'build-receipt.json') -Raw | ConvertFrom-Json
$engineReceipt = Get-Content -LiteralPath (Join-Path $EngineDirectory 'build-receipt.json') -Raw | ConvertFrom-Json
if ($desktopReceipt.source -cne $Source -or $engineReceipt.product_source -cne $Source -or
    $desktopReceipt.target -cne 'x86_64-pc-windows-msvc' -or $desktopReceipt.profile -cne 'debug' -or
    $desktopReceipt.filename -cne 'Clash for Windows.exe' -or
    $engineReceipt.host_artifact.filename -cne 'cfw-engine-host.exe') {
    throw 'Development package inputs do not describe this source and target'
}
$desktop = Join-Path $DesktopDirectory $desktopReceipt.filename
$engine = Join-Path $EngineDirectory $engineReceipt.host_artifact.filename
$driver = $engineReceipt.wintun_artifact
if ($driver.filename -cne 'wintun.dll') { throw 'The Windows engine build omitted its fixed Wintun payload' }
$wintun = Join-Path $EngineDirectory $driver.filename
if ((Get-Item -LiteralPath $wintun).Length -ne $driver.size -or
    (Get-FileHash -LiteralPath $wintun -Algorithm SHA256).Hash.ToLowerInvariant() -cne $driver.sha256) {
    throw 'Wintun payload differs from its engine build receipt'
}
$notices = $engineReceipt.source_notices.archive
if ($notices.filename -cne 'engine-third-party-notices.zip' -or $engineReceipt.source_notices.embedded_binaries -ne 1) {
    throw 'The Windows engine build omitted its embedded-binary notices'
}
$noticeArchive = Join-Path $EngineDirectory $notices.filename
if ((Get-Item -LiteralPath $noticeArchive).Length -ne $notices.bytes -or
    (Get-FileHash -LiteralPath $noticeArchive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $notices.sha256) {
    throw 'Engine notices differ from their build receipt'
}
if ((Get-FileHash -LiteralPath $desktop -Algorithm SHA256).Hash.ToLowerInvariant() -cne $desktopReceipt.sha256 -or
    (Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant() -cne $engineReceipt.host_artifact.sha256) {
    throw 'Development package executable differs from its build receipt'
}
$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($desktop)
$config = Get-Content -LiteralPath 'apps/cfw-tauri-shell/tauri.conf.json' -Raw | ConvertFrom-Json
if ($version.ProductName -cne 'Clash for Windows' -or $version.ProductVersion -cne $config.version) {
    throw 'Desktop native version resource differs from the product source'
}
New-Item -ItemType Directory -Path $Output -ErrorAction Stop | Out-Null
$manifest = [ordered]@{
    schema_version = 2; product_version = $config.version; build_number = 1
    msi_product_code = [guid]::NewGuid().ToString('B').ToUpperInvariant()
    msi_package_code = '{00000000-0000-0000-0000-000000000000}'
    architecture = 'x86_64'; engine_version = $engineReceipt.engine_version.TrimStart('v')
    runtime_sha256 = (Get-FileHash -LiteralPath $Runtime -Algorithm SHA256).Hash.ToLowerInvariant()
    desktop_sha256 = $desktopReceipt.sha256; engine_sha256 = $engineReceipt.host_artifact.sha256
}
$manifestPath = Join-Path $Output 'manifest.json'
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
Import-Module (Join-Path $PSScriptRoot 'runtime_msi.psm1') -Force
$package = New-WindowsRuntimeMsi -Runtime $Runtime -Desktop $desktop -Engine $engine -Wintun $wintun -Manifest $manifestPath `
    -ProductCode $manifest.msi_product_code -Source $Source -Evidence $Output `
    -EngineNotices $noticeArchive -EngineNoticesSha256 $notices.sha256
[ordered]@{
    source=$Source; profile='debug'; desktop_sha256=$manifest.desktop_sha256
    runtime_sha256=$manifest.runtime_sha256; engine_sha256=$manifest.engine_sha256
    engine_notices_sha256=$package.engine_notices_sha256
    wintun_sha256=$package.wintun_sha256
    package_sha256=$package.package_sha256; manifest_sha256=$package.manifest_sha256
    development_build_number=1; production_build_allocated=$false
    installed=$false; gui_exercised=$false; signed=$false; release_accepted=$false
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Output 'development-receipt.json') -Encoding utf8NoBOM
