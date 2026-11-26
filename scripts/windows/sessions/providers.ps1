# The providers session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# A profile of two proxy providers and a rule provider beside the LocalProxy
# profile. The one node of its inline provider is the session's stand-in, run
# with the pinned Node: it answers only the health check the profile declares
# and dials nothing. The stand-in listens on this runner's own IPv4 address,
# because a node on a loopback address is refused. A health check and a rule
# provider update run with the core off, Health Check All and Update All with
# the core on; once the session stops the stand-in, the check fails. The core
# is stopped and the profile deleted, so the next session begins as this one
# did.

# The URL the profile's health check asks for; the stand-in answers it and
# nothing else, so the address is never dialled.
$checkedUrl = 'http://192.0.2.1/generate_204'

# The IPv4 address of the interface with the default route: the engine accepts
# it for a remote node and reaches it on this machine.
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop)
$interfaces = @($routes | ForEach-Object InterfaceIndex | Sort-Object -Unique)
if ($interfaces.Count -ne 1) { throw "The runner has $($interfaces.Count) interfaces with a default IPv4 route, not one" }
$addresses = @(Get-NetIPAddress -InterfaceIndex $interfaces[0] -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object AddressState -EQ 'Preferred' | ForEach-Object IPAddress)
if ($addresses.Count -ne 1) { throw "The default-route interface holds $($addresses.Count) preferred IPv4 addresses, not one" }
$standInAddress = $addresses[0]
# The ranges the engine refuses for a remote node, widened to all of 0/8 and
# 240/4, which are reserved.
$octets = [Net.IPAddress]::Parse($standInAddress).GetAddressBytes()
if ($octets[0] -in 0, 127 -or $octets[0] -ge 224 -or ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
    ($octets[0] -eq 198 -and $octets[1] -in 18, 19) -or ($octets[0] -eq 192 -and $octets[1] -eq 0 -and $octets[2] -eq 2) -or
    ($octets[0] -eq 198 -and $octets[1] -eq 51 -and $octets[2] -eq 100) -or ($octets[0] -eq 203 -and $octets[1] -eq 0 -and $octets[2] -eq 113)) {
    throw 'The default-route address of this runner is one the engine refuses for a remote node'
}

$standInRoot = Join-Path $outputRoot 'provider-stand-in'
New-Item -ItemType Directory -Path $standInRoot -ErrorAction Stop | Out-Null
$standInReceipt = Join-Path $standInRoot 'receipt.jsonl'
# The stand-in appends while the session reads, so the file is opened shared.
function Read-StandInEvents {
    if (-not (Test-Path -LiteralPath $standInReceipt -PathType Leaf)) { return @() }
    $stream = [IO.FileStream]::new($standInReceipt, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try { $text = [IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
    # A line still being written has no newline yet.
    $complete = $text.Substring(0, $text.LastIndexOf("`n") + 1)
    return @($complete -split "`n" | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Get-StandInAnswered { @(Read-StandInEvents | Where-Object event -CEQ 'answered').Count }

$standIn = $null
$standInOutput = $null
$standInErrors = $null
try {
    $start = [Diagnostics.ProcessStartInfo]::new($node)
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $standInScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'provider_stand_in.mjs'
    foreach ($argument in @($standInScript, $standInAddress, $checkedUrl, $standInReceipt, '900')) { $start.ArgumentList.Add($argument) }
    $standIn = [Diagnostics.Process]::Start($start)
    $standInOutput = $standIn.StandardOutput.ReadToEndAsync()
    $standInErrors = $standIn.StandardError.ReadToEndAsync()
    $waited = [Diagnostics.Stopwatch]::StartNew()
    while (@(Read-StandInEvents | Where-Object event -CEQ 'listening').Count -eq 0) {
        if ($standIn.HasExited) { throw "The provider stand-in exited with $($standIn.ExitCode) before it listened" }
        if ($waited.ElapsedMilliseconds -gt 15000) { throw 'The provider stand-in did not listen within 15 seconds' }
        Start-Sleep -Milliseconds 50
    }
    $listening = @(Read-StandInEvents)[0]
    if ($listening.event -cne 'listening' -or $listening.address -cne $standInAddress -or $listening.port -lt 1 -or $listening.port -gt 65535) {
        throw 'The provider stand-in did not begin its receipt with the address it was given'
    }
    # The runner told the steps where GitHub serves the documents.
    $sessionInput = [ordered]@{ origin=$sessionInput; host=$standInAddress; port=[int]$listening.port; url=$checkedUrl }

    $imported = (Invoke-GuiScenario 'providers-import') | ConvertFrom-Json
    $imported | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'providers-import.json') -Encoding utf8NoBOM
    if ($imported.release_accepted -or $imported.profile -ceq $imported.kept -or (Get-StandInAnswered) -ne 0) {
        throw 'The providers import receipt is invalid, or the stand-in answered before a health check'
    }
    $receipt.native_gui_exercised = $true
    $receipt.imported_profile_id = $imported.profile
    $receipt.kept_profile_id = $imported.kept

    $offline = (Invoke-GuiScenario 'providers-offline') | ConvertFrom-Json
    $offline | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'providers-offline.json') -Encoding utf8NoBOM
    $offlineAnswered = Get-StandInAnswered
    if ($offline.release_accepted -or $offlineAnswered -lt 1) { throw 'The health check with the core off did not reach the stand-in' }

    $online = (Invoke-GuiScenario 'providers-online') | ConvertFrom-Json
    $online | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'providers-online.json') -Encoding utf8NoBOM
    $onlineAnswered = Get-StandInAnswered
    if ($online.release_accepted -or $onlineAnswered -le $offlineAnswered) { throw 'Health Check All did not reach the stand-in through the core' }
    $receipt.active_runtime = $online.active.snapshot.state.runtime

    # Every connection the stand-in saw was a health check it answered.
    $standIn.StandardInput.Close()
    if (-not $standIn.WaitForExit(15000) -or $standIn.ExitCode -ne 0) { throw 'The provider stand-in did not stop when its input closed' }
    $events = @(Read-StandInEvents)
    $closed = $events[-1]
    if ($closed.event -cne 'closed' -or $closed.refused -ne 0 -or $closed.answered -lt $onlineAnswered -or
        @($events | Where-Object event -CEQ 'refused').Count -ne 0) {
        throw 'The provider stand-in saw a request that was not the declared health check'
    }

    $unreachable = (Invoke-GuiScenario 'providers-unreachable') | ConvertFrom-Json
    $unreachable | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'providers-unreachable.json') -Encoding utf8NoBOM
    $onlineIdentity = $online.after.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    $unreachableIdentity = $unreachable.after.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    if ($unreachable.release_accepted -or $onlineIdentity -cne $unreachableIdentity) {
        throw 'The failed health check did not run beside the core that ran the providers'
    }

    $stopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
    $stopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
    $stoppedIdentity = $stopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    if ($unreachableIdentity -cne $stoppedIdentity -or $stopped.stopped.snapshot.state.state -cne 'off' -or
        $stopped.stopped.snapshot.desired_mode -cne 'off') {
        throw 'GUI stop did not retire the core that ran the providers'
    }
    $receipt.engine_stopped = $true

    $deleted = (Invoke-GuiScenario 'providers-delete') | ConvertFrom-Json
    $deleted | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'providers-delete.json') -Encoding utf8NoBOM
    $remaining = @($deleted.deleted.profiles)
    if ($deleted.profile -cne $receipt.imported_profile_id -or $deleted.kept -cne $receipt.kept_profile_id -or
        $remaining.Count -ne 1 -or $remaining[0].id -cne $receipt.kept_profile_id -or -not $remaining[0].active -or $deleted.release_accepted) {
        throw 'The providers profile was not removed through the GUI'
    }
    $receipt.profile_deleted = $true
    $receipt.providers_exercised = $true
    $receipt.network_mode_exercised = $true
} finally {
    if ($null -ne $standIn) {
        if (-not $standIn.HasExited) {
            $standIn.Kill($true)
            $null = $standIn.WaitForExit(15000)
        }
        $standInOutput.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $standInRoot 'stdout.log') -Encoding utf8NoBOM
        $standInErrors.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $standInRoot 'stderr.log') -Encoding utf8NoBOM
        $standIn.Dispose()
    }
}
