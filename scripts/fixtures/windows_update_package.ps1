param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Evidence
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:CFW_NATIVE_PACKAGE_TESTS -cne '1' -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'Temporary certificate trust is permitted only in explicitly opted-in disposable hosted CI'
}
if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
    throw 'Package fixture source identity mismatch'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Disposable machine certificate preparation requires an administrator runner'
    }
} finally { $identity.Dispose() }
$root = Join-Path $env:RUNNER_TEMP ('cfw-package-fixtures-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $Evidence -ErrorAction Stop | Out-Null
$certificates = [System.Collections.Generic.List[object]]::new()
$trusted = [System.Collections.Generic.List[string]]::new()
$failure = $null
$cleanupErrors = [System.Collections.Generic.List[string]]::new()
$cases = [System.Collections.Generic.List[string]]::new()
$priorFixtures = $env:CFW_NATIVE_PACKAGE_FIXTURES
$inspectionPassed = $false
$signTool = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'

function Write-Stage([string]$Phase, [string]$Case) {
    [ordered]@{ source=$Source; phase=$Phase; case=$Case; recorded_utc=[DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'progress.json') -Encoding utf8NoBOM
    Write-Host "Native package fixture: $Phase $Case"
}
function Invoke-Msi([object]$Object, [string]$Name, [object[]]$Arguments) {
    $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::InvokeMethod, $null, $Object, $Arguments)
}
function Get-MsiProperty([object]$Object, [string]$Name, [object[]]$Arguments) {
    $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::GetProperty, $null, $Object, $Arguments)
}
function Set-MsiProperty([object]$Object, [string]$Name, [object[]]$Arguments) {
    $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]::SetProperty, $null, $Object, $Arguments)
}
function Release-Msi([object]$Object) {
    if ($null -ne $Object) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Object) }
}
function New-MinimalDatabase([string]$Path, [hashtable]$Overrides, [string]$Template = 'x64;1033', [string]$PackageCode = '{E58D1FC6-A003-4849-900C-45D6861E75D9}') {
    $properties = [ordered]@{
        CFW_PRODUCT_ID = 'com.bill.clashforwindows'
        ProductName = 'Clash for Windows'
        UpgradeCode = '{7ECD99B2-CFE4-51EA-868B-544E2A12E25D}'
        ProductCode = '{E66ACF84-7639-4707-BC01-0A370C9B2E3E}'
        ALLUSERS = '1'
        MSIRESTARTMANAGERCONTROL = 'DisableShutdown'
        ProductVersion = '0.5.0'
        CFW_RELEASE_VERSION = '0.5.0'
        CFW_BUILD_NUMBER = '2'
        CFW_MINIMUM_WINDOWS_VERSION = '10.0.19041'
    }
    foreach ($key in $Overrides.Keys) {
        if ($null -eq $Overrides[$key]) { $properties.Remove($key) } else { $properties[$key] = $Overrides[$key] }
    }
    $installer = $null
    $database = $null
    $summary = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = Invoke-Msi $installer 'OpenDatabase' @($Path, 3)
        $view = Invoke-Msi $database 'OpenView' @('CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)')
        try { Invoke-Msi $view 'Execute' @(); Invoke-Msi $view 'Close' @() } finally { Release-Msi $view }
        foreach ($entry in $properties.GetEnumerator()) {
            $view = Invoke-Msi $database 'OpenView' @('INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)')
            $record = $null
            try {
                $record = Invoke-Msi $installer 'CreateRecord' @(2)
                Set-MsiProperty $record 'StringData' @(1, [string]$entry.Key)
                Set-MsiProperty $record 'StringData' @(2, [string]$entry.Value)
                Invoke-Msi $view 'Execute' @($record)
                Invoke-Msi $view 'Close' @()
            } finally { Release-Msi $record; Release-Msi $view }
        }
        $summary = Get-MsiProperty $database 'SummaryInformation' @(20)
        Set-MsiProperty $summary 'Property' @(1, 1252)
        Set-MsiProperty $summary 'Property' @(2, 'CFW package inspection fixture')
        Set-MsiProperty $summary 'Property' @(7, $Template)
        Set-MsiProperty $summary 'Property' @(9, $PackageCode)
        Set-MsiProperty $summary 'Property' @(14, 200)
        Set-MsiProperty $summary 'Property' @(15, 0)
        Invoke-Msi $summary 'Persist' @()
        Invoke-Msi $database 'Commit' @()
    } finally { Release-Msi $summary; Release-Msi $database; Release-Msi $installer }
}
function New-Database([string]$Path, [hashtable]$Overrides, [string]$Template = 'x64;1033', [string]$PackageCode = ([guid]::NewGuid().ToString('B').ToUpperInvariant())) {
    Copy-Item -LiteralPath (Join-Path $root 'package-template.msi') -Destination $Path
    $installer = $null
    $database = $null
    $summary = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = Invoke-Msi $installer 'OpenDatabase' @($Path, 1)
        foreach ($entry in $Overrides.GetEnumerator()) {
            $record = $null
            $view = $null
            try {
                $record = Invoke-Msi $installer 'CreateRecord' @(1)
                Set-MsiProperty $record 'StringData' @(1, [string]$entry.Key)
                $view = Invoke-Msi $database 'OpenView' @('DELETE FROM `Property` WHERE `Property` = ?')
                Invoke-Msi $view 'Execute' @($record)
                Invoke-Msi $view 'Close' @()
            } finally { Release-Msi $view; Release-Msi $record }
            if ($null -ne $entry.Value) {
                $record = $null
                $view = $null
                try {
                    $record = Invoke-Msi $installer 'CreateRecord' @(2)
                    Set-MsiProperty $record 'StringData' @(1, [string]$entry.Key)
                    Set-MsiProperty $record 'StringData' @(2, [string]$entry.Value)
                    $view = Invoke-Msi $database 'OpenView' @('INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)')
                    Invoke-Msi $view 'Execute' @($record)
                    Invoke-Msi $view 'Close' @()
                } finally { Release-Msi $view; Release-Msi $record }
            }
        }
        $summary = Get-MsiProperty $database 'SummaryInformation' @(2)
        Set-MsiProperty $summary 'Property' @(7, $Template)
        Set-MsiProperty $summary 'Property' @(9, $PackageCode)
        Invoke-Msi $summary 'Persist' @()
        Invoke-Msi $database 'Commit' @()
    } finally { Release-Msi $summary; Release-Msi $database; Release-Msi $installer }
}
function Sign-File([string]$Path, [object]$Certificate, [bool]$RequireTrusted = $true) {
    & $signTool sign /fd SHA256 /s My /sha1 $Certificate.Thumbprint $Path
    if ($LASTEXITCODE -ne 0) { throw "SDK package signing failed: $Path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -cne $Certificate.Thumbprint) {
        throw "Fixture signing did not use the requested certificate: $Path"
    }
    if ($RequireTrusted -and $signature.Status -ne 'Valid') { throw "Fixture signature failed: $($signature.StatusMessage)" }
    if ($RequireTrusted) {
        & $signTool verify /pa /all $Path
        if ($LASTEXITCODE -ne 0) { throw "SDK signature verification failed: $Path" }
    }
}
function New-SignedDatabase([string]$Name, [hashtable]$Overrides = @{}, [string]$Template = 'x64;1033', [string]$PackageCode = ([guid]::NewGuid().ToString('B').ToUpperInvariant())) {
    $path = Join-Path $root $Name
    Write-Stage 'create-database' $Name
    New-Database $path $Overrides $Template $PackageCode
    Write-Stage 'sign-database' $Name
    Sign-File $path $certificates[0]
    $cases.Add($Name)
}
function New-WixControl {
    # A fully authored package distinguishes an incomplete native-database
    # fixture from signing-provider behavior. It is never installed.
    $tools = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'WiX Toolset v3.14\bin'
    $candle = Join-Path $tools 'candle.exe'
    $light = Join-Path $tools 'light.exe'
    if (-not (Test-Path -LiteralPath $candle) -or -not (Test-Path -LiteralPath $light)) {
        throw 'The hosted image WiX 3.14 control-package tools are missing'
    }
    $payload = Join-Path $root 'control-payload.txt'
    'Native MSI inspection control; not the CFW product.' | Set-Content -LiteralPath $payload -Encoding utf8NoBOM
    $escapedPayload = [Security.SecurityElement]::Escape($payload)
    $definition = Join-Path $Evidence 'wix-control.wxs'
    @"
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="{E66ACF84-7639-4707-BC01-0A370C9B2E3E}" Name="Clash for Windows" Language="1033" Version="0.5.0" Manufacturer="CFW validation fixture" UpgradeCode="{7ECD99B2-CFE4-51EA-868B-544E2A12E25D}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" Platform="x64" />
    <MediaTemplate EmbedCab="yes" />
    <Property Id="CFW_PRODUCT_ID" Value="com.bill.clashforwindows" />
    <Property Id="CFW_RELEASE_VERSION" Value="0.5.0" />
    <Property Id="CFW_BUILD_NUMBER" Value="2" />
    <Property Id="CFW_MINIMUM_WINDOWS_VERSION" Value="10.0.19041" />
    <Property Id="MSIRESTARTMANAGERCONTROL" Value="DisableShutdown" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLFOLDER" Name="CFW Package Inspection Fixture">
          <Component Id="Fixture" Guid="{F5818D2D-EBF9-4B5E-9326-41BCD6B3C476}" Win64="yes">
            <File Id="FixtureFile" Source="$escapedPayload" KeyPath="yes" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Main" Level="1"><ComponentRef Id="Fixture" /></Feature>
  </Product>
</Wix>
"@ | Set-Content -LiteralPath $definition -Encoding utf8NoBOM
    $object = Join-Path $root 'wix-control.wixobj'
    $package = Join-Path $Evidence 'wix-control.msi'
    Write-Stage 'build-wix-control' 'compile'
    & $candle -nologo -wx -arch x64 -out $object $definition
    if ($LASTEXITCODE -ne 0) { throw 'WiX control compilation failed' }
    Write-Stage 'build-wix-control' 'link-and-validate'
    & $light -nologo -wx -out $package $object
    if ($LASTEXITCODE -ne 0) { throw 'WiX control link/validation failed' }
    Copy-Item -LiteralPath $package -Destination (Join-Path $root 'package-template.msi')
    Copy-Item -LiteralPath $package -Destination (Join-Path $Evidence 'wix-control-unsigned.msi')
    Write-Stage 'sign-wix-control' 'signtool'
    Sign-File $package $certificates[0]
    [ordered]@{
        source=$Source
        package_sha256=(Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
        authenticode_status=[string](Get-AuthenticodeSignature -LiteralPath $package).Status
        installed=$false
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'wix-control.json') -Encoding utf8NoBOM
}
try {
    Write-Stage 'verify-sdk-signer' '10.0.26100.0'
    if (-not (Test-Path -LiteralPath $signTool) -or (Get-AuthenticodeSignature -LiteralPath $signTool).Status -ne 'Valid') {
        throw 'The pinned Windows SDK signer is missing or untrusted'
    }
    [ordered]@{
        sdk_directory='10.0.26100.0'
        file_version=(Get-Item -LiteralPath $signTool).VersionInfo.FileVersion
        sha256=(Get-FileHash -LiteralPath $signTool -Algorithm SHA256).Hash.ToLowerInvariant()
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'signer-tool.json') -Encoding utf8NoBOM
    # Three independent keys, with identical subject names. Only two are trusted
    # in this disposable runner's machine root store. The CurrentUser Root
    # provider can display a native confirmation dialog and is unsuitable for
    # unattended CI. No trust policy is relaxed and no private key is exported.
    $subject = 'CN=CFW disposable package fixture ' + [guid]::NewGuid().ToString('N')
    for ($i = 0; $i -lt 3; $i++) {
        Write-Stage 'create-certificate' ([string]$i)
        $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter ([DateTime]::Now.AddDays(1))
        $certificates.Add($certificate)
        if ($i -lt 2) {
            $publicPath = Join-Path $root "publisher-$i.cer"
            Export-Certificate -Cert $certificate -FilePath $publicPath | Out-Null
            Write-Stage 'import-disposable-machine-root' ([string]$i)
            $trusted.Add($certificate.Thumbprint)
            Import-Certificate -FilePath $publicPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
            if (-not (Test-Path -LiteralPath "Cert:\LocalMachine\Root\$($certificate.Thumbprint)")) {
                throw 'The temporary root was not imported into the requested store'
            }
        }
    }
    Export-Certificate -Cert $certificates[0] -FilePath (Join-Path $Evidence 'fixture-publisher.cer') | Out-Null
    New-WixControl
    # Isolate the original CryptUI/MSI digest failure from package parsing.
    # Each signer sees the same unsigned bytes in ASCII and Unicode paths.
    # These are diagnostic inputs, never a fallback installation path.
    $unsigned = Join-Path $root 'comparison-unsigned.msi'
    New-MinimalDatabase $unsigned @{}
    Copy-Item -LiteralPath $unsigned -Destination (Join-Path $Evidence 'comparison-unsigned.msi')
    $unsignedDigest = (Get-FileHash -LiteralPath $unsigned -Algorithm SHA256).Hash.ToLowerInvariant()
    $comparison = [System.Collections.Generic.List[object]]::new()
    foreach ($signer in @('cryptui', 'signtool')) {
        foreach ($label in @('ascii', '中文')) {
            $name = "comparison-$signer-$label.msi"
            $path = Join-Path $Evidence $name
            Copy-Item -LiteralPath $unsigned -Destination $path
            Write-Stage 'compare-signer' $name
            $returnedStatus = $null
            if ($signer -ceq 'cryptui') {
                $returnedStatus = [string](Set-AuthenticodeSignature -LiteralPath $path -Certificate $certificates[0] -HashAlgorithm SHA256).Status
            } else {
                & $signTool sign /fd SHA256 /s My /sha1 $certificates[0].Thumbprint $path
                if ($LASTEXITCODE -ne 0) { throw 'SDK comparison signing failed' }
            }
            $observed = Get-AuthenticodeSignature -LiteralPath $path
            & $signTool verify /pa /all $path
            $verifyCode = $LASTEXITCODE
            $comparison.Add([ordered]@{
                signer=$signer; path_kind=$label; returned_status=$returnedStatus
                unsigned_sha256=$unsignedDigest
                observed_status=[string]$observed.Status; sdk_verification_exit=$verifyCode
                sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            })
        }
    }
    $comparison.ToArray() | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'signer-comparison.json') -Encoding utf8NoBOM
    # The former positive fixture was an incomplete, non-installable database.
    # Preserve it as a diagnosed negative control; never use its bytes as a
    # valid package or weaken the native verifier to admit it.
    if (@($comparison | Where-Object { $_.observed_status -cne 'HashMismatch' -or $_.sdk_verification_exit -ne 1 }).Count -ne 0) {
        throw 'The minimal-database counterexample changed; inspect it before altering the fixture contract'
    }
    $fixtureSource = Join-Path $root 'publisher.rs'
    'fn main() { println!("package inspection fixture"); }' | Set-Content -LiteralPath $fixtureSource -Encoding utf8NoBOM
    $publisher = Join-Path $root 'publisher.exe'
    Write-Stage 'build-publisher' 'publisher.exe'
    rustc --edition=2024 -D warnings $fixtureSource -o $publisher
    if ($LASTEXITCODE -ne 0) { throw 'Publisher fixture build failed' }
    Copy-Item -LiteralPath $publisher -Destination (Join-Path $root 'unsigned.exe')
    Copy-Item -LiteralPath $publisher -Destination (Join-Path $root 'other-publisher.exe')
    Sign-File $publisher $certificates[0]
    Sign-File (Join-Path $root 'other-publisher.exe') $certificates[1]
    New-SignedDatabase '有效 安装包.msi'
    New-Database (Join-Path $root 'unsigned.msi') @{}
    New-Database (Join-Path $root 'other-publisher.msi') @{}
    Sign-File (Join-Path $root 'other-publisher.msi') $certificates[1]
    New-Database (Join-Path $root 'untrusted.msi') @{}
    Sign-File (Join-Path $root 'untrusted.msi') $certificates[2] $false
    New-SignedDatabase 'tampered.msi'
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    try {
        # Reflection marshals inline cmdlet output as PSObject, not BSTR.
        [string]$tamperedPath = Join-Path $root 'tampered.msi'
        $database = Invoke-Msi $installer 'OpenDatabase' @($tamperedPath, 1)
        $view = Invoke-Msi $database 'OpenView' @("UPDATE ``Property`` SET ``Value`` = 'changed' WHERE ``Property`` = 'ProductName'")
        Invoke-Msi $view 'Execute' @()
        Invoke-Msi $view 'Close' @()
        Invoke-Msi $database 'Commit' @()
    } finally { Release-Msi $view; Release-Msi $database; Release-Msi $installer }
    foreach ($case in @(
        @('wrong-product.msi', @{CFW_PRODUCT_ID='com.bill.clashformac'}),
        @('wrong-name.msi', @{ProductName='Clash for Mac'}),
        @('wrong-upgrade.msi', @{UpgradeCode='{0A0B0C0D-0000-4000-8000-000000000001}'}),
        @('per-user.msi', @{ALLUSERS='2'}),
        @('automatic-shutdown.msi', @{MSIRESTARTMANAGERCONTROL='0'}),
        @('wrong-release.msi', @{CFW_RELEASE_VERSION='0.5.1';ProductVersion='0.5.1'}),
        @('wrong-msi-version.msi', @{ProductVersion='0.5.1'}),
        @('wrong-product-code.msi', @{ProductCode='invalid'}),
        @('replayed-build.msi', @{CFW_BUILD_NUMBER='1'}),
        @('noncanonical-build.msi', @{CFW_BUILD_NUMBER='02'}),
        @('zero-build.msi', @{CFW_BUILD_NUMBER='0'}),
        @('overflow-build.msi', @{CFW_BUILD_NUMBER='18446744073709551616'}),
        @('future-windows.msi', @{CFW_MINIMUM_WINDOWS_VERSION='11.0.1'}),
        @('invalid-minimum-os.msi', @{CFW_MINIMUM_WINDOWS_VERSION='10.0.019041'}),
        @('oversized-product.msi', @{CFW_PRODUCT_ID=('x' * 257)}),
        @('missing-product.msi', @{CFW_PRODUCT_ID=$null})
    )) { New-SignedDatabase $case[0] $case[1] }
    New-SignedDatabase 'wrong-architecture.msi' @{} 'Intel;1033'
    New-SignedDatabase 'multiple-architectures.msi' @{} 'Intel,x64;1033'
    New-SignedDatabase 'bad-language.msi' @{} 'x64;01033'
    New-SignedDatabase 'wrong-package-code.msi' @{} 'x64;1033' 'invalid'
    New-SignedDatabase 'reused-code.msi' @{} 'x64;1033' '{E66ACF84-7639-4707-BC01-0A370C9B2E3E}'
    $env:CFW_NATIVE_PACKAGE_FIXTURES = $root
    Write-Stage 'clippy' 'native_update_package'
    cargo clippy --locked -p cfw-windows-engine --all-targets --features native-package-validation,native-service-validation -- -D warnings 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'clippy.log')
    if ($LASTEXITCODE -ne 0) { throw 'Native package inspection Clippy failed' }
    Write-Stage 'test' 'native_update_package'
    cargo test --locked -p cfw-windows-engine --test native_update_package --features native-package-validation -- --test-threads=1 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'Native signed package inspection failed' }
    $inspectionPassed = $true
    Write-Stage 'test' 'installed_update_worker'
    ./scripts/fixtures/windows_update_worker.ps1 -Source $Source -Fixtures $root -Evidence $Evidence -SignTool $signTool -PublisherThumbprint $certificates[0].Thumbprint
} catch { $failure = "$($_.Exception.ToString())`n$($_.ScriptStackTrace)" }
finally {
    try { Write-Stage 'cleanup-certificates' '' } catch { $cleanupErrors.Add($_.ToString()) }
    $env:CFW_NATIVE_PACKAGE_FIXTURES = $priorFixtures
    foreach ($thumbprint in $trusted) {
        try {
            if (Test-Path -LiteralPath "Cert:\LocalMachine\Root\$thumbprint") {
                Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$thumbprint" -ErrorAction Stop
            }
            if (Test-Path -LiteralPath "Cert:\LocalMachine\Root\$thumbprint") { throw 'Temporary machine root remains' }
        }
        catch { $cleanupErrors.Add($_.ToString()) }
    }
    foreach ($certificate in $certificates) {
        try {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -DeleteKey -ErrorAction Stop
            if (Test-Path -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)") { throw 'Temporary signing certificate remains' }
        }
        catch { $cleanupErrors.Add($_.ToString()) }
    }
    [ordered]@{
        source=$Source; signed_database_cases=$cases.ToArray()
        failure=$failure; cleanup_errors=$cleanupErrors.ToArray()
        native_inspection_passed=$inspectionPassed; temporary_trust_only=$true
        temporary_root_scope='local_machine_disposable_runner'
        installed_package=$false; production_publisher=$false; release_accepted=$false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Evidence 'receipt.json') -Encoding utf8NoBOM
}
if ($null -ne $failure -or $cleanupErrors.Count -ne 0) {
    throw "Native package validation failed: $failure; certificate cleanup: $($cleanupErrors -join '; ')"
}
Write-Stage 'complete' 'native_update_package'
