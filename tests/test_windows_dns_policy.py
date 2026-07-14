from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Final
from unittest import mock

ROOT: Final = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
import net_stability  # noqa: E402
import net_stability_gui_commands  # noqa: E402
import windows_dns_policy  # noqa: E402


class WindowsDnsPolicyTests(unittest.TestCase):
    def test_health_when_nrpt_is_corrupted_recommends_repair(self) -> None:
        # Given: Windows reports the NRPT corruption and DNS server shape seen during the failing build.
        def fake_runner(script: str, timeout: float) -> net_stability.CommandResult:
            del timeout
            if "Get-DnsClientNrptPolicy -Effective" in script:
                return net_stability.CommandResult(
                    ["powershell"],
                    0,
                    '{"Ok":false,"Error":"Failed to retrieve NRPT policy. WIN32 9572"}',
                    "",
                    1.0,
                )
            if "Get-DnsClientNrptRule" in script:
                return net_stability.CommandResult(
                    ["powershell"],
                    0,
                    '[{"Namespace":["."],"NameServers":[]}]',
                    "",
                    1.0,
                )
            if "Get-WinEvent" in script:
                return net_stability.CommandResult(
                    ["powershell"],
                    0,
                    '[{"Id":1023,"Count":241},{"Id":1014,"Count":4}]',
                    "",
                    1.0,
                )
            if "Get-DnsClientServerAddress" in script:
                return net_stability.CommandResult(
                    ["powershell"],
                    0,
                    '[{"InterfaceAlias":"Wi-Fi 2","AddressFamily":2,"ServerAddresses":["192.168.1.1","0.0.0.0"]}]',
                    "",
                    1.0,
                )
            self.fail(f"unexpected script: {script}")

        # When: StableNet parses the Windows DNS policy health surface.
        health = windows_dns_policy.collect_health(fake_runner)

        # Then: the tool names the exact corruption and proposes the safe repair path.
        self.assertEqual(health.severity, "high")
        self.assertTrue(health.repair_needed)
        self.assertIn("dns_policy_corruption", health.findings)
        self.assertIn("invalid_dns_server", health.findings)
        self.assertIn("flush_dns_cache", health.recommended_actions)
        self.assertIn(
            "remove_invalid_dns_sentinel_preserving_configured_servers",
            health.recommended_actions,
        )

    def test_repair_when_resolvers_are_mixed_preserves_configured_server(self) -> None:
        # Given: a corporate resolver is followed by Windows' invalid sentinel.
        entry = windows_dns_policy.DnsServerEntry(
            "Corporate VPN", "2", ("10.20.30.40", "0.0.0.0")
        )
        health = windows_dns_policy.DnsPolicyHealth(
            True,
            "high",
            True,
            True,
            "",
            ("invalid_dns_server",),
            ("remove_invalid_dns_sentinel_preserving_configured_servers",),
            {},
            (entry,),
            (),
            (),
        )
        scripts: list[str] = []

        def fake_runner(script: str, timeout: float) -> net_stability.CommandResult:
            del timeout
            scripts.append(script)
            return net_stability.CommandResult(["powershell"], 0, "True", "", 1.0)

        # When: the repair is executed.
        result = windows_dns_policy.repair_health(fake_runner, health)

        # Then: only the existing valid resolver is retained.
        self.assertTrue(result.ok)
        resolver_action = result.actions[-1]
        self.assertEqual(resolver_action.original_servers, ("10.20.30.40", "0.0.0.0"))
        self.assertEqual(resolver_action.applied_servers, ("10.20.30.40",))
        repair_script = scripts[-1]
        self.assertIn("'10.20.30.40'", repair_script)
        self.assertNotIn("1.1.1.1", repair_script)
        self.assertNotIn("1.0.0.1", repair_script)

    def test_repair_when_resolvers_are_invalid_only_stays_advisory(self) -> None:
        # Given: Windows reports no known-good configured resolver to preserve.
        entry = windows_dns_policy.DnsServerEntry("Wi-Fi", "2", ("0.0.0.0",))
        health = windows_dns_policy.DnsPolicyHealth(
            True,
            "high",
            True,
            True,
            "",
            ("invalid_dns_server",),
            ("review_invalid_only_dns_configuration",),
            {},
            (entry,),
            (),
            (),
        )
        scripts: list[str] = []

        def fake_runner(script: str, timeout: float) -> net_stability.CommandResult:
            del timeout
            scripts.append(script)
            return net_stability.CommandResult(["powershell"], 0, "True", "", 1.0)

        # When: the repair path runs.
        result = windows_dns_policy.repair_health(fake_runner, health)

        # Then: only the cache is flushed and resolver configuration is untouched.
        self.assertTrue(result.ok)
        self.assertEqual(len(scripts), 1)
        self.assertIn("Clear-DnsClientCache", scripts[0])
        self.assertTrue(
            any("not replaced automatically" in note for note in result.notes)
        )

    def test_windows_dns_repair_creates_restore_ledger_before_mutation(self) -> None:
        # Given: a mixed corporate resolver list and an isolated backup directory.
        entry = windows_dns_policy.DnsServerEntry(
            "Corporate VPN", "2", ("10.20.30.40", "0.0.0.0")
        )
        health = windows_dns_policy.DnsPolicyHealth(
            True,
            "high",
            True,
            True,
            "",
            ("invalid_dns_server",),
            ("remove_invalid_dns_sentinel_preserving_configured_servers",),
            {},
            (entry,),
            (),
            (),
        )
        args = argparse.Namespace(dry_run=False, yes=True)

        with tempfile.TemporaryDirectory() as temporary:
            snapshot_dir = Path(temporary) / "dns-snapshot"
            snapshot_dir.mkdir()
            manifest_path = snapshot_dir / "manifest.json"
            manifest = {
                "snapshot_id": snapshot_dir.name,
                "state": {"system": {"dns_policy": health.to_report()}},
                "applied": {"system": [], "npm": []},
                "platform": {"system": "Windows"},
                "selection": {"system": True, "npm": False},
            }
            mutation_saw_ledger = False

            def fake_runner(script: str, timeout: float) -> net_stability.CommandResult:
                nonlocal mutation_saw_ledger
                del timeout
                if "Set-DnsClientServerAddress" in script:
                    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
                    mutation_saw_ledger = any(
                        item.get("type") == "windows_dns_servers"
                        and item.get("status") == "pending"
                        for item in saved["applied"]["system"]
                    )
                return net_stability.CommandResult(["powershell"], 0, "True", "", 1.0)

            # When: the standalone repair command performs the exact correction.
            with (
                mock.patch.object(
                    net_stability, "windows_dns_policy_health", return_value=health
                ),
                mock.patch.object(net_stability, "is_windows_admin", return_value=True),
                mock.patch.object(
                    net_stability,
                    "create_snapshot",
                    return_value=(snapshot_dir, manifest_path, manifest),
                ),
                mock.patch.object(
                    net_stability,
                    "run_windows_dns_policy_powershell",
                    side_effect=fake_runner,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                return_code = net_stability.command_repair_windows_dns(args)

            # Then: a restore record existed before mutation and retains exact values.
            saved = json.loads(manifest_path.read_text(encoding="utf-8"))
            resolver_record = next(
                item
                for item in saved["applied"]["system"]
                if item.get("type") == "windows_dns_servers"
            )
            self.assertEqual(return_code, 0)
            self.assertTrue(mutation_saw_ledger)
            self.assertEqual(
                resolver_record["original_servers"], ["10.20.30.40", "0.0.0.0"]
            )
            self.assertEqual(resolver_record["applied_servers"], ["10.20.30.40"])
            self.assertEqual(resolver_record["status"], "applied")

    def test_windows_dns_repair_uses_snapshot_health_after_confirmation(self) -> None:
        stale_entry = windows_dns_policy.DnsServerEntry(
            "Stale VPN", "2", ("10.0.0.53", "0.0.0.0")
        )
        snapshot_entry = windows_dns_policy.DnsServerEntry(
            "Current VPN", "2", ("192.0.2.53", "0.0.0.0")
        )
        stale_health = windows_dns_policy.DnsPolicyHealth(
            True,
            "high",
            True,
            True,
            "",
            ("invalid_dns_server",),
            ("remove_invalid_dns_sentinel_preserving_configured_servers",),
            {},
            (stale_entry,),
            (),
            (),
        )
        snapshot_health = windows_dns_policy.DnsPolicyHealth(
            True,
            "high",
            True,
            True,
            "",
            ("invalid_dns_server",),
            ("remove_invalid_dns_sentinel_preserving_configured_servers",),
            {},
            (snapshot_entry,),
            (),
            (),
        )
        scripts: list[str] = []

        with tempfile.TemporaryDirectory() as temporary:
            snapshot_dir = Path(temporary) / "dns-snapshot"
            snapshot_dir.mkdir()
            manifest_path = snapshot_dir / "manifest.json"
            manifest = {
                "snapshot_id": snapshot_dir.name,
                "state": {"system": {"dns_policy": snapshot_health.to_report()}},
                "applied": {"system": [], "npm": []},
                "platform": {"system": "Windows"},
                "selection": {"system": True, "npm": False},
            }

            def fake_runner(script: str, timeout: float) -> net_stability.CommandResult:
                del timeout
                scripts.append(script)
                return net_stability.CommandResult(["powershell"], 0, "True", "", 1.0)

            with (
                mock.patch.object(
                    net_stability,
                    "windows_dns_policy_health",
                    return_value=stale_health,
                ),
                mock.patch.object(net_stability, "is_windows_admin", return_value=True),
                mock.patch.object(
                    net_stability,
                    "create_snapshot",
                    return_value=(snapshot_dir, manifest_path, manifest),
                ),
                mock.patch.object(
                    net_stability,
                    "run_windows_dns_policy_powershell",
                    side_effect=fake_runner,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                return_code = net_stability.command_repair_windows_dns(
                    argparse.Namespace(dry_run=False, yes=True)
                )

            saved = json.loads(manifest_path.read_text(encoding="utf-8"))

        mutation_script = next(
            script for script in scripts if "Set-DnsClientServerAddress" in script
        )
        resolver_records = [
            item
            for item in saved["applied"]["system"]
            if item.get("type") == "windows_dns_servers"
        ]
        self.assertEqual(return_code, 0)
        self.assertIn("Current VPN", mutation_script)
        self.assertIn("192.0.2.53", mutation_script)
        self.assertNotIn("Stale VPN", mutation_script)
        self.assertNotIn("10.0.0.53", mutation_script)
        self.assertEqual(len(resolver_records), 1)
        resolver_record = resolver_records[0]
        self.assertEqual(resolver_record["interface_alias"], "Current VPN")
        self.assertEqual(resolver_record["original_servers"], ["192.0.2.53", "0.0.0.0"])
        self.assertEqual(resolver_record["applied_servers"], ["192.0.2.53"])
        self.assertEqual(resolver_record["status"], "applied")
        self.assertNotIn("Stale VPN", json.dumps(resolver_record))
        self.assertNotIn("10.0.0.53", json.dumps(resolver_record))

    def test_restore_dns_servers_uses_exact_original_list(self) -> None:
        # Given: an exact original resolver list from a repair ledger.
        scripts: list[str] = []

        def fake_runner(script: str, timeout: float) -> net_stability.CommandResult:
            del timeout
            scripts.append(script)
            return net_stability.CommandResult(["powershell"], 0, "True", "", 1.0)

        # When: restore is requested.
        action = windows_dns_policy.restore_dns_servers(
            fake_runner,
            "Corporate VPN",
            ("10.20.30.40", "0.0.0.0"),
        )

        # Then: both original values are restored verbatim.
        self.assertTrue(action.ok)
        self.assertIn("'10.20.30.40','0.0.0.0'", scripts[0])

    def test_command_restore_uses_exact_dns_ledger_values(self) -> None:
        manifest = {
            "schema_version": 1,
            "snapshot_id": "dns-restore",
            "created_utc": "2026-07-14T00:00:00Z",
            "platform": {"system": "Windows", "release": "test"},
            "selection": {"system": True, "npm": False},
            "state": {"system": {}},
            "applied": {
                "system": [
                    {
                        "type": "windows_dns_servers",
                        "interface_alias": "Corporate VPN",
                        "original_servers": ["10.20.30.40", "0.0.0.0"],
                        "applied_servers": ["10.20.30.40"],
                        "status": "applied",
                    }
                ],
                "npm": [],
            },
        }
        args = argparse.Namespace(
            snapshot="dns-restore",
            npm_only=False,
            system_only=True,
            no_restart=True,
            dry_run=False,
            yes=True,
        )
        scripts: list[str] = []

        def fake_runner(script: str, timeout: float) -> net_stability.CommandResult:
            del timeout
            scripts.append(script)
            return net_stability.CommandResult(["powershell"], 0, "True", "", 1.0)

        with tempfile.TemporaryDirectory() as temporary:
            snapshot_dir = Path(temporary) / "dns-restore"
            snapshot_dir.mkdir()
            with (
                mock.patch.object(
                    net_stability,
                    "resolve_snapshot",
                    return_value=(snapshot_dir, manifest),
                ),
                mock.patch.object(net_stability, "is_windows_admin", return_value=True),
                mock.patch.object(
                    net_stability,
                    "run_windows_dns_policy_powershell",
                    side_effect=fake_runner,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                return_code = net_stability.command_restore(args)

            saved = json.loads(
                (snapshot_dir / "manifest.json").read_text(encoding="utf-8")
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(len(scripts), 1)
        self.assertIn("'10.20.30.40','0.0.0.0'", scripts[0])
        system_results = saved["restore_history"][-1]["results"]["system"]
        self.assertEqual(
            system_results,
            [
                {
                    "type": "windows_dns_servers",
                    "interface_alias": "Corporate VPN",
                    "ok": True,
                }
            ],
        )

    def test_gui_dns_action_is_review_only(self) -> None:
        # Given: the GUI command specification is the user-facing DNS action.
        dns_command = next(
            command
            for command in net_stability_gui_commands.COMMANDS
            if "DNS" in command.label
        )

        # Then: the GUI cannot silently approve or execute DNS mutation.
        self.assertEqual(dns_command.label, "Review DNS repair")
        self.assertIn("--dry-run", dns_command.args)
        self.assertNotIn("--yes", dns_command.args)
        self.assertIn("Nothing is changed", dns_command.description)

    def test_failure_when_react_bricks_connect_timeout_is_retryable(self) -> None:
        # Given: the build error emitted by Node/undici when React Bricks cannot be reached.
        stderr = (
            "TypeError: fetch failed\n"
            "ConnectTimeoutError: Connect Timeout Error "
            "(attempted address: api.reactbricks.com:443, timeout: 10000ms)\n"
            "code: 'UND_ERR_CONNECT_TIMEOUT'"
        )

        # When: StableNet classifies the watched command output.
        classification = windows_dns_policy.classify_transient_network_failure(stderr)

        # Then: the failure is treated as retryable and DNS-policy relevant.
        self.assertTrue(classification.retryable)
        self.assertEqual(classification.reason, "connect_timeout")
        self.assertIn("run_dns_policy_health_check", classification.recommended_actions)

    def test_gui_smoke_when_rendered_mentions_dns_policy_repair(self) -> None:
        # Given: the GUI smoke surface is the safe way to inspect button wiring in CI.
        result = subprocess.run(
            [sys.executable, str(ROOT / "net_stability_gui.py"), "--smoke"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        # When: the smoke command reports available GUI actions.
        output = result.stdout + result.stderr

        # Then: the DNS policy repair button is advertised.
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Run speed check", output)
        self.assertIn("Review DNS repair", output)

    def test_repair_dns_when_linux_dry_run_reports_platform_repair(self) -> None:
        # Given: Linux has a resolver state that differs from the stable DNS profile.
        args = argparse.Namespace(dry_run=True, yes=True)
        output = io.StringIO()

        # When: the cross-platform DNS repair command is driven in dry-run mode.
        with (
            mock.patch.object(net_stability.platform, "system", return_value="Linux"),
            mock.patch.object(
                net_stability,
                "linux_dns_state",
                return_value={"available": True, "servers": ["192.168.1.1"]},
            ),
            contextlib.redirect_stdout(output),
        ):
            result = net_stability.command_repair_dns(args)

        # Then: Linux gets a DNS repair plan instead of the Windows-only rejection.
        rendered = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("Linux DNS repair", rendered)
        self.assertIn("flush the Linux resolver cache", rendered)
        self.assertNotIn("1.1.1.1, 1.0.0.1", rendered)

    def test_repair_dns_when_macos_dry_run_reports_platform_repair(self) -> None:
        # Given: macOS has no explicit DNS servers configured.
        args = argparse.Namespace(dry_run=True, yes=True)
        output = io.StringIO()

        # When: the cross-platform DNS repair command is driven in dry-run mode.
        with (
            mock.patch.object(net_stability.platform, "system", return_value="Darwin"),
            mock.patch.object(
                net_stability,
                "macos_dns_state",
                return_value={"available": True, "servers": [], "service": "Wi-Fi"},
            ),
            contextlib.redirect_stdout(output),
        ):
            result = net_stability.command_repair_dns(args)

        # Then: macOS gets a DNS repair plan instead of the Windows-only rejection.
        rendered = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("macOS DNS repair", rendered)
        self.assertIn("flush the macOS DNS and mDNS responder caches", rendered)
        self.assertNotIn("1.1.1.1, 1.0.0.1", rendered)


if __name__ == "__main__":
    unittest.main()
