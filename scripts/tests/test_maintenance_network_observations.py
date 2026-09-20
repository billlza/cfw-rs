from __future__ import annotations

from pathlib import Path
import stat
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import dormant_app_install as install
from scripts.maintenance_network_observations import (
    NetworkObservationError, VPN_HEADER, cfm_vpn_services, network_routes, tunnel_interfaces,
    require_managed_tunnel_location,
)
from test_dormant_app_install import system_extensions_fixture


IDENTIFIER = "97543966-32A2-4199-B43A-2F18E9C69F84"
MANAGED_BUNDLE = Path("/Library/SystemExtensions/36605F93-16AC-4DEF-B399-A855B700D58A/com.bill.clashformac.packet-tunnel.systemextension")
MANAGED_PROCESS = {"pid": 7002, "uid": 0, "path": str(MANAGED_BUNDLE / "Contents/MacOS/CFWPacketTunnel")}


def vpn_list(state: str = "Disconnected") -> str:
    return f'{VPN_HEADER}\n* ({state}) {IDENTIFIER} VPN (com.bill.clashformac) "Clash for Mac Tunnel" [VPN:com.bill.clashformac]\n'


class NetworkProjectionTests(TestCase):
    ROUTES = "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 192.168.1.1 UGScg en0\n"

    def test_neighbor_and_cloned_cache_churn_is_not_a_route_policy_change(self) -> None:
        extra = "192.168.1.3 aa:bb:cc:dd:ee:ff UHLWI en0 700\n1.1.1.1 192.168.1.1 UGHW en0 10\n"
        self.assertEqual(network_routes(self.ROUTES), network_routes(self.ROUTES + extra))

    def test_gateway_flags_interface_and_permanent_reject_marker_are_preserved(self) -> None:
        baseline = network_routes(self.ROUTES)
        for changed in (
            self.ROUTES.replace("192.168.1.1", "192.168.1.2"),
            self.ROUTES.replace("UGScg", "UGRScg"),
            self.ROUTES.replace("en0", "utun7"),
            self.ROUTES.replace("UGScg en0", "UGScg en0 !"),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(baseline, network_routes(changed))

    def test_empty_table_is_allowed_only_after_a_real_table_header(self) -> None:
        self.assertEqual(network_routes("Routing tables\nInternet6:\nDestination Gateway Flags Netif Expire\n"), "[]\n")
        for text in ("", "unavailable", "Destination Gateway Flags\n", "Destination Gateway Flags Netif\npartial\n"):
            with self.subTest(text=text), self.assertRaises(NetworkObservationError):
                network_routes(text)

    def test_all_tunnels_are_preserved_and_observed_absence_is_explicit(self) -> None:
        base = "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n"
        self.assertEqual(tunnel_interfaces(base), "{}\n")
        tunnel = "utun7: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n\tinet 10.0.0.1 --> 10.0.0.1\n"
        self.assertNotEqual(tunnel_interfaces(base), tunnel_interfaces(base + tunnel))
        self.assertNotEqual(tunnel_interfaces(base + tunnel), tunnel_interfaces(base + tunnel.replace("1500", "1280")))
        for text in ("", "unavailable", "\tinet 10.0.0.1\n", base + base):
            with self.subTest(text=text), self.assertRaises(NetworkObservationError):
                tunnel_interfaces(text)

    def test_vpn_absence_requires_a_complete_supported_list(self) -> None:
        self.assertEqual(cfm_vpn_services(VPN_HEADER + "\n"), ())
        self.assertEqual(cfm_vpn_services(vpn_list()), ((IDENTIFIER, "Disconnected"),))
        for text in ("", "permission denied\n", VPN_HEADER + "\ntruncated", vpn_list() + vpn_list().splitlines()[1] + "\n"):
            with self.subTest(text=text), self.assertRaises(NetworkObservationError):
                cfm_vpn_services(text)

    def test_managed_copy_requires_root_owned_nonwritable_nonsymlink_ancestors(self) -> None:
        def metadata(path):
            kind = stat.S_IFREG if path.name == "CFWPacketTunnel" else stat.S_IFDIR
            return SimpleNamespace(st_mode=kind | 0o755, st_uid=0)

        with patch.object(Path, "lstat", autospec=True, side_effect=metadata):
            require_managed_tunnel_location(MANAGED_BUNDLE)
        for mode, uid in ((stat.S_IFLNK | 0o755, 0), (stat.S_IFDIR | 0o775, 0), (stat.S_IFDIR | 0o755, 501)):
            def changed(path):
                return SimpleNamespace(st_mode=mode, st_uid=uid) if path == MANAGED_BUNDLE else metadata(path)
            with self.subTest(mode=mode, uid=uid), patch.object(Path, "lstat", autospec=True, side_effect=changed):
                with self.assertRaises(NetworkObservationError):
                    require_managed_tunnel_location(MANAGED_BUNDLE)
        with self.assertRaises(NetworkObservationError):
            require_managed_tunnel_location(Path("/tmp") / MANAGED_BUNDLE.name)


class RegisteredExtensionMaintenanceTests(TestCase):
    def test_only_read_only_vpn_commands_are_admitted(self) -> None:
        install._require_fixed_command(("/usr/sbin/scutil", "--nc", "list"))
        install._require_fixed_command(("/usr/sbin/scutil", "--nc", "status", IDENTIFIER))
        for action in ("start", "stop", "select", "suspend", "resume"):
            with self.subTest(action=action), self.assertRaises(install.InstallError):
                install._require_fixed_command(("/usr/sbin/scutil", "--nc", action, IDENTIFIER))
        with self.assertRaises(install.InstallError):
            install._require_fixed_command(("/usr/sbin/scutil", "--nc", "status", "unbound-name"))

    def runner(self, *, state="Disconnected", status="Disconnected\n", after=None,
               registered=True, list_error=False, signature_error=False):
        calls = []
        listings = [vpn_list(state), vpn_list(state) if after is None else after]

        def run(command):
            calls.append(command)
            if command == ("/usr/bin/codesign", "--verify", "--deep", "--strict", "-R", install.TUNNEL_SIGNING_REQUIREMENT, str(MANAGED_BUNDLE)):
                return install.CommandResult(1 if signature_error else 0, "", "")
            if command == ("/usr/bin/systemextensionsctl", "list"):
                body = system_extensions_fixture(install.CFM_SYSTEM_EXTENSION_IDENTITY) if registered else "0 extension(s)\n"
                return install.CommandResult(0, body, "")
            if command == ("/usr/sbin/scutil", "--nc", "list"):
                if list_error:
                    return install.CommandResult(1, "", "permission denied\n")
                return install.CommandResult(0, listings.pop(0), "")
            if command == ("/usr/sbin/scutil", "--nc", "status", IDENTIFIER):
                return install.CommandResult(0, status, "")
            raise AssertionError(command)
        return run, calls

    def test_idle_os_managed_process_does_not_block_app_swap(self) -> None:
        runner, calls = self.runner()
        with patch.object(install, "require_managed_tunnel_location") as location:
            install._require_no_cfm_processes([MANAGED_PROCESS], runner)
        location.assert_called_once_with(MANAGED_BUNDLE)
        self.assertEqual(calls[0][:6], ("/usr/bin/codesign", "--verify", "--deep", "--strict", "-R", install.TUNNEL_SIGNING_REQUIREMENT))
        for command in calls:
            install._require_fixed_command(command)

    def test_active_or_unsigned_managed_process_is_rejected(self) -> None:
        for kwargs in ({"state": "Connected"}, {"signature_error": True}):
            runner, _ = self.runner(**kwargs)
            with self.subTest(kwargs=kwargs), patch.object(install, "require_managed_tunnel_location"):
                with self.assertRaises(install.InstallError):
                    install._require_no_cfm_processes([MANAGED_PROCESS], runner)

    def test_foreign_duplicate_and_host_processes_are_rejected(self) -> None:
        for processes in (
            [{**MANAGED_PROCESS, "uid": 501}], [MANAGED_PROCESS, {**MANAGED_PROCESS, "pid": 7003}],
            [{**MANAGED_PROCESS, "path": "/tmp/Contents/MacOS/CFWPacketTunnel"}],
            [{"pid": 7004, "uid": 501, "path": "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"}],
        ):
            runner, _ = self.runner()
            with self.subTest(processes=processes), self.assertRaises(install.InstallError):
                install._require_no_cfm_processes(processes, runner)

    def test_registered_disconnected_extension_is_not_uninstalled(self) -> None:
        runner, calls = self.runner()
        install.require_cfm_system_extension_inactive(runner)
        self.assertEqual(calls.count(("/usr/sbin/scutil", "--nc", "list")), 2)
        self.assertTrue(all(command[0] in ("/usr/bin/systemextensionsctl", "/usr/sbin/scutil") for command in calls))
        self.assertNotIn("uninstall", " ".join(" ".join(command) for command in calls))

    def test_active_transitioning_or_invalid_vpn_is_rejected_even_without_registration(self) -> None:
        for state in ("Connected", "Connecting", "Disconnecting", "Invalid"):
            for registered in (True, False):
                with self.subTest(state=state, registered=registered):
                    runner, _ = self.runner(state=state, registered=registered)
                    with self.assertRaises(install.InstallError) as raised:
                        install.require_cfm_system_extension_inactive(runner)
                    self.assertEqual(raised.exception.code, "cfm_tunnel_not_disconnected")

    def test_failed_read_status_drift_and_list_drift_are_rejected(self) -> None:
        for kwargs in ({"list_error": True}, {"status": "Connecting\n"}, {"after": vpn_list("Connected")}, {"after": VPN_HEADER + "\n"}):
            with self.subTest(kwargs=kwargs):
                runner, _ = self.runner(**kwargs)
                with self.assertRaises(install.InstallError):
                    install.require_cfm_system_extension_inactive(runner)

    def test_malformed_listing_is_not_an_absent_service(self) -> None:
        runner, _ = self.runner(after="unavailable")
        with self.assertRaises(install.InstallError) as raised:
            install.require_cfm_system_extension_inactive(runner)
        self.assertEqual(raised.exception.code, "cfm_tunnel_observation_invalid")
