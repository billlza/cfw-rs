"""Exercise the installed GUI probe receipt checks through a stand-in launcher, without a GUI."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
MODULE = SCRIPTS / "installed_gui_probes.psm1"
RUNNER = SCRIPTS / "run_installed_gui_session.ps1"
SOURCE = "0123456789abcdef0123456789abcdef01234567"
INSTALLATION = "6a1f0c2e9b7d4835a0c4e1f29b3d7a56"
ORIGINAL_PROXY = "a" * 64
APPLIED_PROXY = "b" * 64
PORT = 7890
LAUNCH = {"process_id": 4242, "process_creation_time": 134079552000000000,
          "user_proxy_before_sha256": ORIGINAL_PROXY}
# What the fixture launcher is to the module: it is started with the probe's
# arguments and leaves the receipt the test planned, or fails as planned.
STAND_IN = r"""
import json, os, pathlib, sys
receipts = pathlib.Path(os.environ["CFW_NATIVE_SERVICE_RECEIPTS"])
plan = json.loads((receipts / "plan.json").read_text(encoding="utf-8"))
(receipts / "call.json").write_text(json.dumps(
    {"arguments": sys.argv[1:], "source": os.environ["CFW_NATIVE_SERVICE_SOURCE"]}), encoding="utf-8")
if plan["exit"] != 0:
    sys.stderr.write("stand-in probe failure\n")
    sys.exit(plan["exit"])
(receipts / plan["file"]).write_text(json.dumps(plan["receipt"]), encoding="utf-8")
"""
POWERSHELL = r"""
param([string]$ProbeModule, [string]$Launcher, [string]$Source, [string]$Receipts, [string]$Cases)
$ErrorActionPreference = 'Stop'
Import-Module $ProbeModule -Force -ArgumentList $Launcher, $Source, $Receipts
$plan = Get-Content -LiteralPath $Cases -Raw | ConvertFrom-Json
$results = foreach ($case in $plan.cases) {
    $case.launcher | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Receipts 'plan.json') -Encoding utf8NoBOM
    $record = $null
    $failure = $null
    $arguments = @($case.arguments)
    try { $record = & $case.probe @arguments $plan.launch } catch { $failure = $_.Exception.Message }
    [ordered]@{ record=$record; failure=$failure
        call=(Get-Content -LiteralPath (Join-Path $Receipts 'call.json') -Raw | ConvertFrom-Json) }
}
ConvertTo-Json -InputObject @($results) -Depth 8 -Compress
"""
CONTRACT = r"""
param([string]$ProbeModule, [string]$Runner)
$ErrorActionPreference = 'Stop'
$module = Import-Module $ProbeModule -Force -PassThru -ArgumentList 'launcher', 'source', 'receipts'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Runner, [ref]$tokens, [ref]$errors)
$commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
[ordered]@{
    parse_errors=@($errors).Count
    exported=@($module.ExportedFunctions.Keys | Sort-Object)
    called=@($commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -like 'Invoke-Native*' } | Sort-Object -Unique)
    imports=@($commands | Where-Object { $_.GetCommandName() -ceq 'Import-Module' } | ForEach-Object { $_.Extent.Text })
} | ConvertTo-Json -Compress
"""


def observed(document, **fields):
    """A receipt of the launched GUI's own session, as every probe writes it."""
    return {"document": document, "source": SOURCE, "gui_process_id": LAUNCH["process_id"],
            "gui_process_creation_time": LAUNCH["process_creation_time"], "gui_same_user_session": True,
            "release_accepted": False, **fields}


def shortcut(operation):
    return observed(
        "cfw-installed-gui-shortcut-probe-v1", operation=operation, shortcut="Control+Alt+Shift+F9",
        keyboard_events_sent=8, keyboard_events_accepted=8, product_addressed=False,
        desktop_observation={"window_station": "WinSta0", "desktop": "Default", "interactive_window_station": True,
                             "input_desktop_observed": True, "existing_user_object_permissions_changed": False})


def network(operation):
    receipt = observed(
        "cfw-installed-gui-network-probe-v1", operation=operation, proxy_address=f"127.0.0.1:{PORT}",
        original_user_proxy_sha256=ORIGINAL_PROXY, http_forwarding_verified=operation != "closed",
        listener_refused=operation == "closed", user_proxy_sha256=ORIGINAL_PROXY, user_proxy_unchanged=True)
    if operation == "system-http":
        receipt.update(system_proxy_applied=True, applied_user_proxy_unchanged=True, wininet_via_proxy_verified=True,
                       wininet_request_flags=4, user_proxy_sha256=APPLIED_PROXY, user_proxy_unchanged=False)
    return receipt


def tunnel(operation):
    entered = operation == "tunnel-http"
    return observed(
        "cfw-installed-gui-tunnel-probe-v1", operation=operation, installation_id=INSTALLATION,
        adapter_absent=not entered, route_entered_tunnel=entered, http_through_tunnel_verified=entered,
        route_luid=1234 if entered else 99, adapter_luid=1234, local_address="198.18.64.1:50000" if entered else None,
        user_proxy_sha256=ORIGINAL_PROXY, user_proxy_unchanged=True)


def combined():
    return observed(
        "cfw-installed-gui-combined-probe-v1", installation_id=INSTALLATION, route_entered_tunnel=True,
        route_luid=1234, adapter_luid=1234, local_address="198.18.64.1:50001", http_through_tunnel_verified=True,
        proxy_address=f"127.0.0.1:{PORT}", http_forwarding_verified=True, system_proxy_applied=True,
        native_user_proxy={"manual_proxy_enabled": True, "auto_config_enabled": False, "auto_detect_enabled": False,
                           "ports": [PORT]},
        original_user_proxy_sha256=ORIGINAL_PROXY, user_proxy_sha256=APPLIED_PROXY)


def leak(operation):
    refused = operation == "leak-refused"
    flow = "refused" if refused else "connected"
    return observed(
        "cfw-installed-gui-leak-protection-probe-v1", operation=operation, installation_id=INSTALLATION,
        route_entered_tunnel=True, resolver="192.0.2.53", encrypted_dns_tcp=flow,
        encrypted_dns_attempts=[{"target": "192.0.2.53:853", "outcome": flow}],
        stun={"target": "stun.example.net:3478", "outcome": "unanswered" if refused else "answered"},
        http_through_tunnel_verified=refused, http_local_address="198.18.64.1:50002" if refused else None,
        user_proxy_sha256=ORIGINAL_PROXY, user_proxy_unchanged=True)


def case(probe, arguments, name, receipt, exit_code=0):
    return {"probe": probe, "arguments": arguments,
            "launcher": {"file": f"{name}-probe.json", "receipt": receipt, "exit": exit_code}}


# One accepted receipt of every probe and operation, with the arguments the
# session gives the probe and those the launcher must be started with.
ACCEPTED = [
    *(case("Invoke-NativeShortcutProbe", [operation], operation, shortcut(operation))
      | {"started_with": ["--installed-gui-shortcut-probe", operation]}
      for operation in ("shortcut-stop", "shortcut-start", "shortcut-removed")),
    *(case("Invoke-NativeNetworkProbe", [operation, PORT], operation, network(operation))
      | {"started_with": ["--installed-gui-network-probe", operation, str(PORT)]}
      for operation in ("http", "closed", "system-http")),
    *(case("Invoke-NativeTunnelProbe", [operation, INSTALLATION], operation, tunnel(operation))
      | {"started_with": ["--installed-gui-tunnel-probe", operation, INSTALLATION]}
      for operation in ("tunnel-http", "tunnel-closed")),
    case("Invoke-NativeCombinedProbe", [INSTALLATION, PORT], "combined-http", combined())
    | {"started_with": ["--installed-gui-combined-probe", INSTALLATION, str(PORT)]},
    *(case("Invoke-NativeLeakProtectionProbe", [operation, INSTALLATION, "192.0.2.53", "stun.example.net:3478"],
           operation, leak(operation))
      | {"started_with": ["--installed-gui-leak-protection-probe", operation, INSTALLATION, "192.0.2.53",
                          "stun.example.net:3478"]}
      for operation in ("leak-open", "leak-refused", "leak-reopened")),
]
SHORTCUT_REFUSAL = "The native shortcut press differs from the launched GUI and its input desktop"
# Every way a shortcut receipt can differ from the launched GUI, the entered
# shortcut and one whole press on the input desktop.
SHORTCUT_DIFFERENCES = {
    "another document": {"document": "cfw-installed-gui-network-probe-v1"},
    "another source": {"source": "f" * 40},
    "another step": {"operation": "shortcut-start"},
    "another process": {"gui_process_id": LAUNCH["process_id"] + 1},
    "a reused process id": {"gui_process_creation_time": LAUNCH["process_creation_time"] + 1},
    "another session": {"gui_same_user_session": False},
    "another shortcut": {"shortcut": "Control+Alt+F9"},
    "a key left out": {"keyboard_events_sent": 7},
    "a key Windows did not take": {"keyboard_events_accepted": 7},
    "no input desktop": {"desktop_observation": {"input_desktop_observed": False}},
    "the product addressed": {"product_addressed": True},
    "a release claim": {"release_accepted": True},
}
MOVED_REFUSALS = {
    "Invoke-NativeNetworkProbe": "Native network proof differs from the UI-owned runtime and original user proxy",
    "Invoke-NativeTunnelProbe": "Native tunnel proof differs from the UI-owned TUN runtime and the original user proxy",
    "Invoke-NativeCombinedProbe": "Native combined proof differs from the UI-owned runtime, its tunnel and its proxy listener",
    "Invoke-NativeLeakProtectionProbe":
        "Native leak protection proof differs from the UI-owned TUN runtime with both switches off",
}


class ProbeReceiptTests(unittest.TestCase):
    def powershell(self, script, *arguments):
        executable = shutil.which("pwsh")
        self.assertIsNotNone(executable, "PowerShell is required; this boundary test cannot be skipped")
        result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-File", str(script), *arguments],
                                capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", result.stderr)
        return json.loads(result.stdout)

    def probe(self, cases):
        """Run the cases in one PowerShell; return each outcome and the retained probe logs."""
        with tempfile.TemporaryDirectory(prefix="cfw-gui-probes-") as directory:
            root = Path(directory)
            receipts = root / "receipts"
            receipts.mkdir()
            stand_in = root / "stand_in.py"
            stand_in.write_text(STAND_IN, encoding="utf-8")
            # Isolated and without bytecode: the stand-in leaves nothing but its receipt.
            if os.name == "nt":
                launcher = root / "launcher.cmd"
                launcher.write_text(f'@"{sys.executable}" -I -B "{stand_in}" %*\r\n@exit /b %ERRORLEVEL%\r\n',
                                    encoding="utf-8")
            else:
                launcher = root / "launcher"
                launcher.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -I -B {shlex.quote(str(stand_in))} "$@"\n',
                                    encoding="utf-8")
                launcher.chmod(0o755)
            plan = root / "cases.json"
            plan.write_text(json.dumps({"launch": LAUNCH, "cases": cases}), encoding="utf-8")
            script = root / "probe.ps1"
            script.write_text(POWERSHELL, encoding="utf-8")
            results = self.powershell(script, "-ProbeModule", str(MODULE), "-Launcher", str(launcher),
                                      "-Source", SOURCE, "-Receipts", str(receipts), "-Cases", str(plan))
            logs = {path.name: path.read_text(encoding="utf-8") for path in receipts.glob("*-probe-std*.log")}
        self.assertEqual(len(results), len(cases))
        return results, logs

    def test_every_probe_accepts_its_receipt_and_starts_the_launcher_with_its_arguments(self):
        results, logs = self.probe(ACCEPTED)
        for planned, result in zip(ACCEPTED, results, strict=True):
            with self.subTest(probe=planned["probe"], receipt=planned["launcher"]["file"]):
                self.assertIsNone(result["failure"], result["failure"])
                self.assertEqual(result["record"], planned["launcher"]["receipt"])
                self.assertEqual(result["call"], {"arguments": planned["started_with"], "source": SOURCE})
        # Both streams of every probe are retained beside its receipt.
        self.assertEqual(sorted(logs), sorted(
            f"{planned['launcher']['file'].removesuffix('.json')}-{stream}.log"
            for planned in ACCEPTED for stream in ("stdout", "stderr")))

    def test_a_shortcut_receipt_that_differs_is_refused(self):
        cases = [case("Invoke-NativeShortcutProbe", ["shortcut-stop"], "shortcut-stop", shortcut("shortcut-stop") | difference)
                 for difference in SHORTCUT_DIFFERENCES.values()]
        results, _logs = self.probe(cases)
        for name, result in zip(SHORTCUT_DIFFERENCES, results, strict=True):
            with self.subTest(difference=name):
                self.assertIsNone(result["record"])
                self.assertEqual(result["failure"], SHORTCUT_REFUSAL)

    def test_the_other_probes_refuse_another_source_and_another_gui(self):
        one_of_each = [planned for planned in ACCEPTED
                       if planned["launcher"]["file"] in ("http-probe.json", "tunnel-http-probe.json",
                                                          "combined-http-probe.json", "leak-open-probe.json")]
        self.assertEqual([planned["probe"] for planned in one_of_each], list(MOVED_REFUSALS))
        differences = ({"source": "f" * 40}, {"gui_process_id": LAUNCH["process_id"] + 1},
                       {"gui_process_creation_time": LAUNCH["process_creation_time"] + 1})
        cases = [planned | {"launcher": planned["launcher"] | {"receipt": planned["launcher"]["receipt"] | difference}}
                 for planned in one_of_each for difference in differences]
        results, _logs = self.probe(cases)
        for planned, result in zip(cases, results, strict=True):
            with self.subTest(probe=planned["probe"]):
                self.assertIsNone(result["record"])
                self.assertEqual(result["failure"], MOVED_REFUSALS[planned["probe"]])

    def test_a_probe_that_fails_reports_its_retained_stderr_and_reads_no_receipt(self):
        accepted = case("Invoke-NativeShortcutProbe", ["shortcut-stop"], "shortcut-stop", shortcut("shortcut-stop"))
        failed = case("Invoke-NativeShortcutProbe", ["shortcut-stop"], "shortcut-stop", shortcut("shortcut-stop"), exit_code=3)
        # The accepted receipt of the first run is still on disk during the second.
        results, logs = self.probe([accepted, failed])
        self.assertIsNone(results[0]["failure"], results[0]["failure"])
        self.assertIsNone(results[1]["record"])
        self.assertEqual(results[1]["failure"], "Native GUI shortcut-stop probe failed; see its retained stderr")
        self.assertEqual(logs["shortcut-stop-probe-stderr.log"].strip(), "stand-in probe failure")

    def test_the_session_calls_the_probes_the_module_exports_and_imports_it_in_parameter_order(self):
        with tempfile.TemporaryDirectory(prefix="cfw-gui-probes-") as directory:
            script = Path(directory) / "contract.ps1"
            script.write_text(CONTRACT, encoding="utf-8")
            contract = self.powershell(script, "-ProbeModule", str(MODULE), "-Runner", str(RUNNER))
        self.assertEqual(contract["parse_errors"], 0)
        self.assertEqual(contract["exported"], sorted({planned["probe"] for planned in ACCEPTED}))
        self.assertEqual(contract["called"], contract["exported"])
        # The module takes its launcher, source and receipt directory by position.
        self.assertIn("Import-Module (Join-Path $PSScriptRoot 'installed_gui_probes.psm1') -Force "
                      "-ArgumentList $Launcher, $Source, $outputRoot", contract["imports"])


if __name__ == "__main__":
    unittest.main()
