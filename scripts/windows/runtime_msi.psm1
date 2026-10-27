# Shared WiX authoring; building a package does not install it or accept release.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-WindowsRuntimeMsi {
    param([string]$Runtime, [string]$Desktop, [string]$Engine, [string]$Wintun, [string]$Manifest,
          [string]$ProductCode, [string]$Source, [string]$Evidence,
          [string]$EngineNotices, [string]$EngineNoticesSha256,
          [switch]$QualificationFixture)
    if (-not $IsWindows) { throw 'Windows MSI authoring requires Windows' }
    if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
        throw 'Runtime MSI source identity mismatch'
    }
    $inputManifest = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
    $build = $inputManifest.build_number
    if ($inputManifest.schema_version -ne 2 -or $inputManifest.architecture -cne 'x86_64' -or
        $inputManifest.msi_product_code -cne $ProductCode -or
        $inputManifest.msi_package_code -cne '{00000000-0000-0000-0000-000000000000}' -or
        $build -lt 1 -or $inputManifest.product_version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw 'Invalid Windows MSI manifest input'
    }
    $msiVersion = $inputManifest.product_version
    $driverPin = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot '../dependency_pins.env') |
        Select-String -Pattern '^WINTUN_WINDOWS_AMD64_SHA256=([a-f0-9]{64})$')
    if ($driverPin.Count -ne 1 -or -not (Test-Path -LiteralPath $Wintun -PathType Leaf)) {
        throw 'The runtime MSI requires the pinned official Wintun image'
    }
    $driverDigest = (Get-FileHash -LiteralPath $Wintun -Algorithm SHA256).Hash.ToLowerInvariant()
    $driverBytes = (Get-Item -LiteralPath $Wintun).Length
    if ($driverDigest -cne $driverPin[0].Matches[0].Groups[1].Value -or $driverBytes -lt 1 -or $driverBytes -gt 2MB) {
        throw 'MSI Wintun input differs from the compiled official image pin'
    }
    $driverSignature = Get-AuthenticodeSignature -LiteralPath $Wintun
    if ($driverSignature.Status -ne 'Valid' -or $null -eq $driverSignature.SignerCertificate) {
        throw 'The official Wintun image did not pass native Authenticode verification'
    }
    $basename = 'CFW-development-windows-x64'
    if ($QualificationFixture) {
        if ($EngineNotices -or $EngineNoticesSha256) { throw 'The executable fixture does not claim engine notice delivery' }
        if ($build -notin @(1, 2)) { throw 'Unexpected native MSI qualification build' }
        $msiVersion = "0.5.$build"
        $basename = 'runtime-fixture'
    }
    $noticeBytes = $null
    $noticeDigest = $null
    if (-not $QualificationFixture) {
        if (-not (Test-Path -LiteralPath $EngineNotices -PathType Leaf) -or $EngineNoticesSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'The desktop MSI requires verified engine notices'
        }
        $noticeBytes = (Get-Item -LiteralPath $EngineNotices).Length
        $noticeDigest = (Get-FileHash -LiteralPath $EngineNotices -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($noticeBytes -lt 1 -or $noticeBytes -gt 64MB -or $noticeDigest -cne $EngineNoticesSha256) {
            throw 'MSI engine notice input differs from its expected bytes'
        }
    }
    foreach ($entry in @(@($Runtime, $inputManifest.runtime_sha256), @($Desktop, $inputManifest.desktop_sha256), @($Engine, $inputManifest.engine_sha256))) {
        if ((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[1]) {
            throw 'MSI manifest does not describe the input image bytes'
        }
    }
    $tools = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'WiX Toolset v3.14/bin'
    $candle = Join-Path $tools 'candle.exe'
    $light = Join-Path $tools 'light.exe'
    $csc = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    $wixAssembly = Join-Path $tools 'wix.dll'
    $wixUtil = Join-Path $tools 'WixUtilExtension.dll'
    foreach ($path in @($candle, $light, $csc, $wixAssembly, $wixUtil, $Runtime, $Desktop, $Engine, $Manifest)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required MSI qualification input missing: $path" }
    }
    $definition = Join-Path $PSScriptRoot 'runtime.wxs'
    $object = Join-Path $Evidence "$basename.wixobj"
    $package = Join-Path $Evidence "$basename.msi"
    $binder = Join-Path $Evidence 'RuntimeMsiManifestBinder.dll'
    & $csc /nologo /target:library /warnaserror+ "/reference:$wixAssembly" "/out:$binder" (Join-Path $PSScriptRoot 'RuntimeMsiManifestBinder.cs') 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'binder-compile.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Runtime MSI manifest binder compilation failed' }
    $transaction = [guid]::NewGuid().ToString('D')
    $arguments = @('-nologo', '-wx', '-arch', 'x64', '-out', $object,
        "-dRuntime=$Runtime", "-dDesktop=$Desktop", "-dEngine=$Engine", "-dWintun=$Wintun", "-dManifest=$Manifest",
        "-dQualificationFixture=$([int]$QualificationFixture.IsPresent)", "-dBuildNumber=$build",
        "-dProductCode=$ProductCode", "-dMsiVersion=$msiVersion", "-dMaintenanceTransaction=$transaction", $definition)
    if (-not $QualificationFixture) { $arguments = @("-dEngineNotices=$EngineNotices") + $arguments }
    & $candle @arguments 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'compile.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Windows MSI compilation failed' }
    & $light -nologo -wx -ext $binder -ext $wixUtil -out $package $object 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'link.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Windows MSI link or validation failed' }
    $boundManifest = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
    if ($boundManifest.msi_product_code -cne $ProductCode -or $boundManifest.msi_package_code -ceq '{00000000-0000-0000-0000-000000000000}') { throw 'Runtime manifest was not bound to its generated MSI identity' }
    $result = [ordered]@{
        source=$Source; path=$package; product_code=$ProductCode; package_code=$boundManifest.msi_package_code; msi_version=$msiVersion
        package_sha256=(Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
        maintenance_transaction=$transaction; manifest_sha256=(Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
        build_number=$boundManifest.build_number
        desktop_is_fixture=$QualificationFixture.IsPresent; signed=$false; release_accepted=$false
        wintun_filename='wintun.dll'; wintun_sha256=$driverDigest; wintun_bytes=$driverBytes
        wintun_authenticode_status=$driverSignature.Status.ToString()
        wintun_signer_thumbprint=$driverSignature.SignerCertificate.Thumbprint
    }
    if (-not $QualificationFixture) {
        $result['engine_notices_packaged'] = $true
        $result['engine_notices_sha256'] = $noticeDigest
        $result['engine_notices_bytes'] = $noticeBytes
    }
    $result = [pscustomobject]$result
    $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'package.json') -Encoding utf8NoBOM
    return $result
}
Export-ModuleMember -Function New-WindowsRuntimeMsi
