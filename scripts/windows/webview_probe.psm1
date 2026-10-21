# Read-only CI readiness observation. This module never launches or changes
# the application, and does not accept protocol/authentication failures.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Wait-CfwWebView2 {
    param(
        [Parameter(Mandatory)][Diagnostics.Process]$Controller,
        [Parameter(Mandatory)][uri]$Endpoint,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$ProbeAttempts,
        [ValidateRange(1,45)][int]$TimeoutSeconds = 45
    )
    if ($Endpoint.Scheme -cne 'http' -or $Endpoint.Host -cne '127.0.0.1' -or
        $Endpoint.Port -lt 1 -or $Endpoint.AbsolutePath -cne '/' -or
        $Endpoint.Query -ne '' -or $Endpoint.Fragment -ne '' -or $Endpoint.UserInfo -ne '') {
        throw 'WebView2 readiness requires a local HTTP endpoint without credentials or path'
    }
    $address = $Endpoint.GetLeftPart([UriPartial]::Authority)
    $startupClock = [Diagnostics.Stopwatch]::StartNew()
    $lastConnectionError = $null
    while ($true) {
        if ($controller.HasExited) { throw "GUI controller exited before WebView2 was ready: $($controller.ExitCode)" }
        try {
            $version = Invoke-RestMethod "$address/json/version" -TimeoutSec ([Math]::Min(2, $TimeoutSeconds)) -NoProxy
            if ([string]::IsNullOrEmpty($version.webSocketDebuggerUrl)) { throw 'WebView2 endpoint has no debugger identity' }
            return $version
        } catch {
            $chain = [Collections.Generic.List[Exception]]::new()
            for ($exception = $_.Exception; $null -ne $exception; $exception = $exception.InnerException) {
                if ($chain.Count -ge 16) { throw 'Unexpectedly deep startup HTTP exception chain' }
                $chain.Add($exception)
            }
            $refused = @($chain | Where-Object {
                $_ -is [Net.Sockets.SocketException] -and $_.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionRefused
            }).Count -gt 0
            $requestTimedOut = @($chain | Where-Object { $_ -is [TimeoutException] }).Count -gt 0 -and
                @($chain | Where-Object { $_ -is [OperationCanceledException] }).Count -gt 0
            $probeAttempts.Add([ordered]@{
                elapsed_ms=$startupClock.ElapsedMilliseconds
                exception_types=@($chain | ForEach-Object { $_.GetType().FullName })
                connection_refused=$refused; request_timed_out=$requestTimedOut
                message=$_.Exception.Message
            })
            # WebView2 initialization can exceed one HTTP observation. Retry
            # only refusal or HttpClient's own timeout while this exact GUI is
            # alive, within the caller's bounded startup budget (at most 45 seconds). A protocol,
            # HTTP status, authentication or JSON error is never retried.
            if (-not ($refused -or $requestTimedOut)) { throw }
            $lastConnectionError = $_.Exception.Message
            if ($startupClock.Elapsed.TotalSeconds -ge $TimeoutSeconds -or $probeAttempts.Count -ge 256) {
                throw "WebView2 startup deadline: $lastConnectionError"
            }
            Start-Sleep -Milliseconds 200
        }
    }
}
Export-ModuleMember -Function Wait-CfwWebView2
