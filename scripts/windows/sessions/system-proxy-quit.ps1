# The system-proxy-quit session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# System Proxy on the LocalProxy profile, left active for Quit. The runner
# checks after the GUI's exit that this user's proxy options are restored and
# the listener is gone, with the $started and $proxyPort this file leaves.
$started = (Invoke-GuiScenario 'system-proxy-start') | ConvertFrom-Json
$started | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'system-proxy-start.json') -Encoding utf8NoBOM
if (-not $started.controller_verified) { throw 'SystemProxy GUI did not verify its actual controller' }
$receipt.controller_verified = $true
$proxyPort = [int]$started.settings.effective.mixed_port
if ($proxyPort -lt 1 -or $proxyPort -gt 65535) { throw 'GUI system proxy port is invalid' }
$receipt.native_gui_exercised = $true
$receipt.imported_profile_id = $started.before.profiles.profiles[0].id
$receipt.proxy_port = $proxyPort
$receipt.active_runtime = $started.active.snapshot.state.runtime
$systemHttp = Invoke-NativeNetworkProbe 'system-http' $proxyPort $launch
$receipt.http_forwarding_verified = $systemHttp.http_forwarding_verified
$receipt.wininet_proxy_verified = $systemHttp.wininet_via_proxy_verified
$receipt.network_mode_exercised = $true
[ordered]@{ source=$Source; gui_process_id=$launch.process_id; gui_process_creation_time=$launch.process_creation_time;
    proxy_port=$proxyPort; mode='system_proxy' } | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $outputRoot 'exit-network-expectation.json') -Encoding utf8NoBOM
