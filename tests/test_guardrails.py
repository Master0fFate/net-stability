from __future__ import annotations

import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Final
from unittest import mock

ROOT: Final = Path(__file__).resolve().parents[1]
SCRIPT: Final = ROOT / "net_stability.py"
TOKEN_SENTINEL: Final = "token_like_guardrail_1234567890abcdef1234567890"
MAC_SENTINEL: Final = "00:11:22:aa:bb:cc"

sys.path.insert(0, str(ROOT))
import net_stability  # noqa: E402
import net_stability_ndt7  # noqa: E402

UNSAFE_ACTION_PATTERNS: Final = (
    # MTU and DNS are now paper-backed overrides (removed from denylist test)
    # re.compile(r"\b(?:set|force|guess|write|apply|change|tune)\s+(?:the\s+)?mtu\b"),
    # re.compile(r"\b(?:replace|switch|set|change)\s+(?:the\s+)?dns\b"),
    re.compile(r"\bdisable\s+(?:global\s+)?ipv6\b"),
    re.compile(r"\b(?:tcp\s*ack|tcpackfrequency|nagle|tcpnodelay)\b"),
    re.compile(
        r"\b(?:disable|turn\s+off)\s+(?:all|broad|blanket|global)\s+.*offload\b"
    ),
    re.compile(r"\b(?:disable|turn\s+off)\s+global\s+usb\s+selective\s+suspend\b"),
    re.compile(r"\b(?:enable|disable|set|tune)\s+(?:rss|vmq)\s+.*wi-?fi\b"),
    re.compile(r"\b(?:multimedia\s+scheduler|mmcss)\b"),
    re.compile(r"\b(?:force|fix|pin|prefer)\s+(?:5\s*ghz|2\.4\s*ghz|channel|band)\b"),
    re.compile(r"\bfixed\s+(?:channel|band)\b"),
)


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_no_unsafe_actions(testcase: unittest.TestCase, text: str) -> None:
    lowered = text.lower()
    for pattern in UNSAFE_ACTION_PATTERNS:
        testcase.assertIsNone(pattern.search(lowered), pattern.pattern)


def unavailable_summary():
    return {
        "gateway_ping": {"available": False},
        "public_ping": {"available": False},
        "dns": {"available": False},
        "registry_https": {"available": False},
    }


def loaded_loss_summary():
    return {
        "gateway_ping": {
            "available": True,
            "loss_percent": 0.0,
            "median_ms": 2.0,
            "p95_ms": 4.0,
        },
        "public_ping": {
            "available": True,
            "loss_percent": 10.5,
            "median_ms": 31.0,
            "p95_ms": 95.0,
            "jitter_avg_ms": 16.0,
            "jitter_max_ms": 28.0,
        },
        "dns": {"available": True, "failure_percent": 0.0},
        "registry_https": {"available": True, "failure_percent": 0.0},
    }


class CliGuardrailTests(unittest.TestCase):
    def test_help_when_requested_does_not_advertise_anti_folklore_actions(self) -> None:
        # Given: normal CLI help entry points.
        help_commands = (
            ("--help",),
            ("diagnose", "--help"),
            ("benchmark", "--help"),
            ("watch", "--help"),
            ("apply", "--help"),
        )

        for command in help_commands:
            with self.subTest(command=command):
                # When: help text is rendered through the real CLI process.
                result = run_cli(*command)

                # Then: help succeeds and does not advertise unsafe tuning recipes.
                self.assertEqual(result.returncode, 0, result.stderr)
                assert_no_unsafe_actions(self, result.stdout + result.stderr)

    def test_apply_dry_run_when_planning_changes_does_not_expose_unsafe_actions(
        self,
    ) -> None:
        # Given: dry-run apply scopes that should be non-destructive.
        scenarios = (
            ("npm-only", ("apply", "--dry-run", "--npm-only"), "Linux"),
            (
                "windows-system",
                ("apply", "--dry-run", "--system-only", "--no-restart"),
                "Windows",
            ),
            (
                "linux-system",
                ("apply", "--dry-run", "--system-only", "--no-restart"),
                "Linux",
            ),
        )

        for name, argv, platform_name in scenarios:
            with self.subTest(name=name):
                stdout = io.StringIO()
                stderr = io.StringIO()

                # When: the dry-run path is executed without writing settings.
                with contextlib.ExitStack() as stack:
                    stack.enter_context(
                        mock.patch(
                            "net_stability.platform.system", return_value=platform_name
                        )
                    )
                    stack.enter_context(
                        mock.patch(
                            "net_stability.validate_apply_context", return_value=None
                        )
                    )
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    return_code = net_stability.main(argv)

                # Then: only planned change lines are checked for unsafe actions.
                self.assertEqual(return_code, 0, stderr.getvalue())
                output = stdout.getvalue()
                self.assertIn("Dry run complete", output)
                planned_lines = "\n".join(
                    line for line in output.splitlines() if line.startswith("  - ")
                )
                assert_no_unsafe_actions(self, planned_lines)

    def test_windows_system_plan_when_dry_run_repairs_restricted_tcp_autotuning(
        self,
    ) -> None:
        # Given: Windows system tuning is rendered without writing settings.
        stdout = io.StringIO()
        stderr = io.StringIO()

        # When: the dry-run plan is generated for Windows.
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch("net_stability.platform.system", return_value="Windows")
            )
            stack.enter_context(
                mock.patch("net_stability.validate_apply_context", return_value=None)
            )
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            return_code = net_stability.main(
                ("apply", "--dry-run", "--system-only", "--no-restart")
            )

        # Then: the system plan includes repair of receive-window autotuning.
        self.assertEqual(return_code, 0, stderr.getvalue())
        output = stdout.getvalue()
        self.assertIn(
            "Restore Windows TCP receive-window auto-tuning to normal", output
        )
        planned_lines = "\n".join(
            line for line in output.splitlines() if line.startswith("  - ")
        )
        assert_no_unsafe_actions(self, planned_lines)

    def test_windows_tcp_state_when_autotuning_disabled_marks_repair_needed(
        self,
    ) -> None:
        # Given: netsh reports the local throughput-hostile state seen on this machine.
        result = net_stability.CommandResult(
            ["netsh", "interface", "tcp", "show", "global"],
            0,
            "Receive Window Auto-Tuning Level    : disabled \n",
            "",
            1.0,
        )

        # When: the Windows TCP state is parsed.
        state = net_stability.parse_windows_tcp_global_state(result)

        # Then: the disabled receive window is identified as needing repair.
        self.assertTrue(state["available"])
        self.assertEqual(state["receive_window_autotuning"], "disabled")
        self.assertTrue(net_stability.windows_tcp_autotuning_needs_repair(state))

    def test_windows_wlan_channel_evidence_recommends_router_side_fix(self) -> None:
        # Given: the 2.4 GHz link shape observed on the local TP-Link adapter.
        output = """
There is 1 interface on the system:

    Name                   : Wi-Fi 2
    Description            : TP-Link Wireless Nano USB Adapter
    State                  : connected
    SSID                   : p00dy2GHz
    Radio type             : 802.11n
    Channel                : 5
    Receive rate (Mbps)    : 120
    Transmit rate (Mbps)   : 120
    Signal                 : 68%
"""

        # When: StableNet parses the link and builds read-only recommendations.
        interfaces = net_stability.parse_windows_wlan_interfaces(output)
        quality = {
            "available": True,
            "platform": "Windows",
            "interfaces": interfaces,
        }
        recommendations = net_stability.wifi_link_recommendations(quality)

        # Then: channel/radio evidence is preserved and the fix stays router/placement-side.
        self.assertEqual(interfaces[0]["radio_type"], "802.11n")
        self.assertEqual(interfaces[0]["channel"], "5")
        recommendation_ids = {item["id"] for item in recommendations}
        self.assertIn("two_four_ghz_overlap_channel", recommendation_ids)
        self.assertIn("marginal_two_four_ghz_signal", recommendation_ids)
        for item in recommendations:
            self.assertEqual(item["mutation"].endswith("advisory only"), True)

    def test_windows_power_state_when_usb_suspend_enabled_reports_usb_state(
        self,
    ) -> None:
        # Given: Windows reports an active scheme, stable Wi-Fi policy, and enabled USB selective suspend.
        def fake_run_command(
            args: tuple[str, ...] | list[str],
            **_kwargs: object,
        ) -> net_stability.CommandResult:
            command = list(args)
            if command[:2] == ["powercfg", "/getactivescheme"]:
                return net_stability.CommandResult(
                    command,
                    0,
                    "Power Scheme GUID: 11111111-2222-3333-4444-555555555555  (Core)",
                    "",
                    1.0,
                )
            if command[:3] == [
                "powercfg",
                "/query",
                "11111111-2222-3333-4444-555555555555",
            ] and command[3] in {"SUB_WIFI", net_stability.WINDOWS_WIFI_SUBGROUP_GUID}:
                return net_stability.CommandResult(
                    command,
                    0,
                    "Current AC Power Setting Index: 0x00000000\n"
                    "Current DC Power Setting Index: 0x00000000\n",
                    "",
                    1.0,
                )
            if command[-2:] == [
                net_stability.WINDOWS_USB_SUBGROUP_GUID,
                net_stability.WINDOWS_USB_SELECTIVE_SUSPEND_GUID,
            ]:
                return net_stability.CommandResult(
                    command,
                    0,
                    "Current AC Power Setting Index: 0x00000001\n"
                    "Current DC Power Setting Index: 0x00000001\n",
                    "",
                    1.0,
                )
            self.fail(f"unexpected command: {command}")

        # When: the Windows power state is captured.
        with mock.patch("net_stability.run_command", side_effect=fake_run_command):
            state = net_stability.windows_power_state()

        # Then: USB selective suspend is exposed separately from the Wi-Fi policy.
        self.assertTrue(state["available"])
        self.assertEqual(state["ac_value"], 0)
        self.assertEqual(state["dc_value"], 0)
        self.assertEqual(state["usb_selective_suspend"]["ac_value"], 1)
        self.assertEqual(state["usb_selective_suspend"]["dc_value"], 1)

    def test_apply_windows_system_repairs_usb_wifi_power_paths(self) -> None:
        # Given: a USB Wi-Fi adapter has the exact power states seen on the failing machine.
        manifest = {
            "state": {
                "system": {
                    "tcp_global": {
                        "available": True,
                        "receive_window_autotuning": "normal",
                    },
                    "power": {
                        "available": True,
                        "scheme_guid": "11111111-2222-3333-4444-555555555555",
                        "ac_value": 0,
                        "dc_value": 0,
                        "usb_selective_suspend": {
                            "available": True,
                            "scheme_guid": "11111111-2222-3333-4444-555555555555",
                            "ac_value": 1,
                            "dc_value": 1,
                        },
                    },
                    "wifi_adapters": {
                        "available": True,
                        "adapters": [
                            {
                                "Name": "Wi-Fi 2",
                                "InterfaceDescription": "TP-Link Wireless Nano USB Adapter",
                                "InterfaceGuid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
                                "PnPDeviceID": "USB\\VID_2357&PID_011E\\00E04C000001",
                                "DevicePowerManagementEnabled": True,
                                "SelectiveSuspend": None,
                                "DeviceSleepOnDisconnect": None,
                            }
                        ],
                    },
                }
            },
            "applied": {"system": []},
        }
        ok = net_stability.CommandResult(["ok"], 0, "{}", "", 1.0)

        # When: Windows system tuning is applied in battery-inclusive mode.
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch("net_stability.atomic_write_json"))
            stack.enter_context(
                mock.patch(
                    "net_stability.windows_set_power_value",
                    return_value=[ok, ok, ok],
                )
            )
            usb_suspend = stack.enter_context(
                mock.patch(
                    "net_stability.windows_set_usb_selective_suspend",
                    return_value=[ok, ok, ok],
                )
            )
            device_power = stack.enter_context(
                mock.patch(
                    "net_stability.windows_set_device_power_management",
                    return_value=ok,
                )
            )
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            net_stability.apply_windows_system(
                manifest,
                Path("manifest.json"),
                include_battery=True,
                restart=False,
            )

        # Then: both USB-specific repairs are recorded for restore.
        usb_suspend.assert_called_once_with(
            "11111111-2222-3333-4444-555555555555", 0, 0
        )
        device_power.assert_called_once()
        applied_types = {item["type"] for item in manifest["applied"]["system"]}
        self.assertIn("windows_usb_selective_suspend", applied_types)
        self.assertIn("windows_usb_device_power", applied_types)

    def test_list_backups_when_manifest_is_unreadable_reports_invalid_entry(
        self,
    ) -> None:
        # Given: an elevated snapshot directory that the current user cannot read.
        stdout = io.StringIO()
        blocked = Path("blocked-snapshot")

        # When: list-backups renders the available snapshot table.
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch("net_stability.snapshot_directories", return_value=[blocked])
            )
            stack.enter_context(
                mock.patch(
                    "net_stability.backups_root", return_value=Path("backup-root")
                )
            )
            stack.enter_context(
                mock.patch(
                    "net_stability.load_json", side_effect=PermissionError("denied")
                )
            )
            stack.enter_context(contextlib.redirect_stdout(stdout))
            return_code = net_stability.command_list_backups(mock.Mock())

        # Then: the unreadable entry is reported without escaping as an unexpected CLI error.
        self.assertEqual(return_code, 1)
        self.assertIn("blocked-snapshot", stdout.getvalue())
        self.assertIn("invalid", stdout.getvalue())

    def test_benchmark_help_when_inputs_are_excessive_rejects_before_network_use(
        self,
    ) -> None:
        # Given: benchmark options that would create excessive local traffic or leak URL credentials.
        scenarios = (
            ("--parallel-downloads", "17"),
            ("--download-mb", "257"),
            ("--download-url", "https://user:secret@example.com/file"),
        )

        for option, value in scenarios:
            with self.subTest(option=option):
                # When: the benchmark command is parsed.
                result = run_cli("benchmark", option, value)

                # Then: argument validation fails before any benchmark starts.
                self.assertEqual(result.returncode, 2)


class ReportGuardrailTests(unittest.TestCase):
    def test_ndt7_targets_when_locate_v2_response_extracts_wss_urls_without_tokens(
        self,
    ) -> None:
        # Given: the Locate API v2 response shape with complete tokenized service URLs.
        payload = {
            "results": [
                {
                    "machine": "mlab1.example.net",
                    "location": {"city": "Testville", "country": "US"},
                    "urls": {
                        "wss:///ndt/v7/download": "wss://mlab1.example.net/ndt/v7/download?access_token=secret",
                        "wss:///ndt/v7/upload": "wss://mlab1.example.net/ndt/v7/upload?access_token=secret",
                    },
                }
            ]
        }

        # When: StableNet extracts usable NDT7 targets.
        targets = net_stability_ndt7.extract_ndt7_targets(payload)

        # Then: both directions are available internally, and report URLs can be stripped safely.
        self.assertEqual(targets[0]["machine"], "mlab1.example.net")
        self.assertIn("access_token=secret", targets[0]["download_url"])
        self.assertEqual(
            net_stability_ndt7.public_url(targets[0]["download_url"]),
            "wss://mlab1.example.net/ndt/v7/download",
        )

    def test_verify_when_download_is_below_threshold_marks_report_degraded(
        self,
    ) -> None:
        # Given: a deterministic M-Lab result matching the user's "near 10 Mbps is bad" case.
        speedtest = {
            "available": True,
            "protocol": "ndt7",
            "locate": {"targets": [{"machine": "mlab1.example.net"}]},
            "download": {
                "success": True,
                "throughput_mbps": 10.0,
                "bytes": 1_000_000,
                "duration_ms": 800.0,
            },
            "upload": None,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "verify.json"

            # When: verify runs through the public parser with all network surfaces mocked.
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch(
                        "net_stability.default_gateway", return_value="192.168.1.1"
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.collect_samples",
                        return_value=[{"phase": "verify_idle"}],
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.summarize_samples",
                        return_value=unavailable_summary(),
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.collect_wifi_link_quality",
                        return_value={
                            "available": True,
                            "platform": "test",
                            "mutation": "none",
                        },
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.run_ndt7_speedtest", return_value=speedtest
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.platform_metadata",
                        return_value={"system": "test"},
                    )
                )
                return_code = net_stability.main(
                    (
                        "verify",
                        "--samples",
                        "1",
                        "--skip-upload",
                        "--min-download-mbps",
                        "15",
                        "--output",
                        str(output),
                    )
                )

            # Then: the command exits nonzero and the report explains the failing threshold.
            self.assertEqual(return_code, 1)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["verification"]["status"], "degraded")
            self.assertIn(
                "below 15 Mbps threshold", report["verification"]["findings"][0]
            )

    def test_redacted_diagnose_report_when_generated_removes_mac_and_token_like_values(
        self,
    ) -> None:
        # Given: generated report inputs containing share-unsafe identifiers.
        sample = {
            "phase": "idle",
            "adapter": MAC_SENTINEL,
            "registry_header": f"Authorization: Bearer {TOKEN_SENTINEL}",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "diagnose.json"

            # When: diagnose writes a redacted report through the public CLI path.
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch("net_stability.default_gateway", return_value=None)
                )
                stack.enter_context(
                    mock.patch("net_stability.collect_samples", return_value=[sample])
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.summarize_samples",
                        return_value=unavailable_summary(),
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.platform_metadata",
                        return_value={
                            "adapter": MAC_SENTINEL,
                            "credential": TOKEN_SENTINEL,
                        },
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.collect_platform_diagnostics",
                        return_value={"raw": f"{MAC_SENTINEL} {TOKEN_SENTINEL}"},
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.maybe_run_network_quality", return_value=None
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.maybe_generate_windows_wlan_report",
                        return_value=None,
                    )
                )
                return_code = net_stability.main(
                    ("diagnose", "--samples", "1", "--redact", "--output", str(output))
                )

            # Then: the generated JSON report preserves shape but removes identifiers.
            self.assertEqual(return_code, 0)
            report_text = output.read_text(encoding="utf-8")
            self.assertNotIn(MAC_SENTINEL, report_text)
            self.assertNotIn(TOKEN_SENTINEL, report_text)
            report = json.loads(report_text)
            self.assertEqual(report["samples"][0]["adapter"], "<redacted-mac>")

    def test_watch_when_child_exits_preserves_exact_return_code_without_network(
        self,
    ) -> None:
        # Given: command monitoring with all network probes replaced by deterministic samples.
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "watch.json"
            child = (sys.executable, "-c", "import sys; sys.exit(37)")

            # When: the monitored child exits with a distinctive status.
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch("net_stability.default_gateway", return_value=None)
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.collect_samples",
                        return_value=[{"phase": "baseline"}],
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.collect_sample", return_value={"phase": "load"}
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.summarize_samples",
                        return_value=unavailable_summary(),
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.compare_phases",
                        return_value=["deterministic child"],
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.platform_metadata",
                        return_value={"system": "test"},
                    )
                )
                return_code = net_stability.main(
                    (
                        "watch",
                        "--baseline-seconds",
                        "0.1",
                        "--interval",
                        "1",
                        "--output",
                        str(output),
                        "--",
                        *child,
                    )
                )

            # Then: both process status and report field match the child exactly.
            self.assertEqual(return_code, 37)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["command_returncode"], 37)

    def test_ping_summary_when_latencies_vary_reports_jitter(self) -> None:
        # Given: successful public-ping samples with uneven latency deltas.
        samples = [
            {"public_ping": {"available": True, "success": True, "latency_ms": value}}
            for value in (20.0, 36.0, 25.0, 41.0)
        ]

        # When: the ping records are summarized.
        summary = net_stability.ping_summary(samples, "public_ping")

        # Then: jitter is reported as first-order latency variation.
        self.assertEqual(summary["jitter_avg_ms"], 14.333)
        self.assertEqual(summary["jitter_max_ms"], 16.0)

    def test_pressure_classification_when_download_loss_spares_gateway_recommends_sqm(
        self,
    ) -> None:
        # Given: download load shows the user's symptom: remote loss and jitter, stable gateway.
        baseline = {
            "gateway_ping": {"available": True, "loss_percent": 0.0, "median_ms": 2.0},
            "public_ping": {
                "available": True,
                "loss_percent": 0.0,
                "median_ms": 25.0,
                "p95_ms": 30.0,
            },
            "dns": {"available": True, "failure_percent": 0.0},
            "registry_https": {"available": True, "failure_percent": 0.0},
        }

        # When: StableNet classifies the loaded benchmark.
        observations, recommendations = net_stability.classify_measurement(
            baseline,
            loaded_loss_summary(),
        )

        # Then: the report points at router/WAN queue pressure instead of DNS tweaks.
        self.assertIn(
            "obs-download_loaded_loss_or_jitter", {item["id"] for item in observations}
        )
        self.assertIn("rec-download-sqm-aqm", {item["id"] for item in recommendations})

    def test_benchmark_when_mocked_writes_loaded_report(self) -> None:
        # Given: benchmark internals are replaced by deterministic no-network data.
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "benchmark.json"

            # When: the benchmark command is driven through the real CLI parser.
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch(
                        "net_stability.default_gateway", return_value="192.168.1.1"
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.collect_samples",
                        return_value=[{"phase": "baseline"}],
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.summarize_samples",
                        side_effect=[unavailable_summary(), loaded_loss_summary()],
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.run_download_load",
                        return_value=(
                            [{"phase": "download_load"}],
                            {
                                "url": "https://speed.cloudflare.com/__down?bytes=1048576",
                                "parallel": 1,
                                "bytes_read": 1048576,
                                "successes": 1,
                                "failures": 0,
                                "throughput_mbps": 8.0,
                                "workers": [],
                            },
                        ),
                    )
                )
                stack.enter_context(
                    mock.patch("net_stability.adapter_counter_state", return_value=None)
                )
                stack.enter_context(
                    mock.patch(
                        "net_stability.platform_metadata",
                        return_value={"system": "test"},
                    )
                )
                return_code = net_stability.main(
                    (
                        "benchmark",
                        "--baseline-seconds",
                        "1",
                        "--load-seconds",
                        "1",
                        "--interval",
                        "1",
                        "--parallel-downloads",
                        "1",
                        "--download-mb",
                        "1",
                        "--output",
                        str(output),
                    )
                )

            # Then: the saved report includes load, throughput, and SQM guidance.
            self.assertEqual(return_code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["benchmark"]["direction"], "download")
            self.assertEqual(
                report["load_summary"]["public_ping"]["jitter_avg_ms"], 16.0
            )
            self.assertIn(
                "rec-download-sqm-aqm",
                {item["id"] for item in report["recommendations"]},
            )


if __name__ == "__main__":
    unittest.main()
