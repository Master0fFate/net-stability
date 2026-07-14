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
from modules import net_stability  # noqa: E402
from modules import net_stability_gui  # noqa: E402
from modules import net_stability_link_diagnostics  # noqa: E402
from modules import net_stability_ndt7  # noqa: E402
from modules import net_stability_router_diagnostics  # noqa: E402
from modules import net_stability_router_rules  # noqa: E402
from modules import net_stability_wifi_analysis  # noqa: E402

UNSAFE_ACTION_PATTERNS: Final = (
    re.compile(r"\b(?:set|force|guess|write|apply|change|tune)\s+(?:the\s+)?mtu\b"),
    re.compile(r"\b(?:replace|switch|set|change|overwrite)\s+(?:the\s+)?dns\b"),
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


def clean_router_baseline_summary():
    return {
        "gateway_ping": {
            "available": True,
            "loss_percent": 0.0,
            "median_ms": 1.0,
            "p95_ms": 2.0,
        },
        "public_ping": {
            "available": True,
            "loss_percent": 0.0,
            "median_ms": 24.0,
            "p95_ms": 30.0,
            "jitter_avg_ms": 1.0,
        },
        "dns": {"available": True, "failure_percent": 0.0, "median_ms": 25.0},
        "registry_https": {
            "available": True,
            "failure_percent": 0.0,
            "median_ms": 280.0,
        },
    }


class CliGuardrailTests(unittest.TestCase):
    def test_release_workflow_preserves_tag_and_macos_bundle_invariants(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

        self.assertEqual(workflow.count("target: macos-arm64"), 1)
        self.assertIn("os: macos-14", workflow)
        self.assertIn("expected_arch: ARM64", workflow)
        self.assertIn("ref: ${{ github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn(
            'git show-ref --verify --quiet "refs/tags/${RELEASE_TAG}"', workflow
        )
        self.assertIn('if [ "${HEAD_COMMIT}" != "${TAG_COMMIT}" ]', workflow)
        self.assertIn("net-stability-gui-macos-*.app", workflow)
        self.assertIn("hdiutil attach", workflow)
        self.assertIn("! -path '*.app/*'", workflow)
        self.assertIn("name: net-stability-${{ matrix.target }}", workflow)

    def test_release_builder_requires_a_real_macos_app_bundle(self) -> None:
        source = (ROOT / "scripts" / "build_release.py").read_text(encoding="utf-8")

        self.assertIn('return settings.out_dir / f"{name}.app"', source)
        self.assertIn('gui_output.suffix != ".app"', source)
        self.assertIn('gui_output / "Contents" / "Info.plist"', source)
        self.assertIn('gui_output / "Contents" / "MacOS"', source)
        self.assertIn('windowed=(system in {"windows", "macos"})', source)

    def test_help_when_requested_does_not_advertise_anti_folklore_actions(self) -> None:
        # Given: normal CLI help entry points.
        help_commands = (
            ("--help",),
            ("diagnose", "--help"),
            ("benchmark", "--help"),
            ("router-diagnose", "--help"),
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

    def test_audit_output_does_not_publish_obsolete_tuning_claims(self) -> None:
        # Given: the public audit command runs without platform-specific diagnostics.
        forbidden_claims = (
            "fixed mtu=1500",
            "dns replacement to 1.1.1.1",
            "bbr congestion control",
            "fq_codel on linux",
            "qos reservable bandwidth set to 0%",
        )

        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "audit.json"

            # When: the real CLI renders and writes its audit surface.
            result = run_cli(
                "audit",
                "--no-platform-diagnostics",
                "--output",
                str(output_path),
            )

            # Then: neither the console nor report repeats obsolete recipes.
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = (result.stdout + result.stderr).lower()
            report = output_path.read_text(encoding="utf-8").lower()
            for claim in forbidden_claims:
                with self.subTest(claim=claim):
                    self.assertNotIn(claim, rendered)
                    self.assertNotIn(claim, report)

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

    def test_linux_reset_reports_actual_failed_command_and_nonzero_status(self) -> None:
        # Given: the Linux reset command fails for the command that was attempted.
        failed = net_stability.CommandResult(
            ["systemctl", "restart", "systemd-networkd"],
            5,
            "",
            "unit failed",
            1.0,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        # When: the explicit reset action runs.
        with (
            mock.patch("net_stability.platform.system", return_value="Linux"),
            mock.patch("net_stability.os.geteuid", return_value=0, create=True),
            mock.patch("net_stability.linux_reset_network", return_value=[failed]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            return_code = net_stability.command_reset_network(mock.Mock(yes=True))

        # Then: failure is returned and the label comes from the actual command.
        self.assertEqual(return_code, 2)
        self.assertIn("systemctl restart systemd-networkd", stderr.getvalue())
        self.assertNotIn("Network stack reset.", stdout.getvalue())

    def test_macos_reset_reports_failed_command_and_nonzero_status(self) -> None:
        # Given: one macOS cache command fails.
        failed = net_stability.CommandResult(
            ["killall", "-HUP", "mDNSResponder"],
            1,
            "",
            "no process found",
            1.0,
        )
        stderr = io.StringIO()

        # When: the explicit reset action runs.
        with (
            mock.patch("net_stability.platform.system", return_value="Darwin"),
            mock.patch("net_stability.os.geteuid", return_value=0, create=True),
            mock.patch(
                "net_stability.macos_reset_network_config", return_value=[failed]
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(stderr),
        ):
            return_code = net_stability.command_reset_network(mock.Mock(yes=True))

        # Then: the failed command is named and the result is nonzero.
        self.assertEqual(return_code, 2)
        self.assertIn("killall -HUP mDNSResponder", stderr.getvalue())

    def test_apply_copy_describes_actual_platform_operations(self) -> None:
        scenarios = (
            (
                "Windows",
                "Repair Windows DNS policy only when health checks find invalid resolver state",
            ),
            (
                "Linux",
                "No automatic Linux system mutation; preserve resolver and kernel policy",
            ),
            (
                "Darwin",
                "No automatic macOS system mutation; preserve resolver and sysctl policy",
            ),
        )

        for platform_name, expected in scenarios:
            with self.subTest(platform=platform_name):
                stdout = io.StringIO()
                with (
                    mock.patch(
                        "net_stability.platform.system", return_value=platform_name
                    ),
                    contextlib.redirect_stdout(stdout),
                ):
                    return_code = net_stability.main(
                        ("apply", "--dry-run", "--system-only")
                    )

                output = stdout.getvalue()
                self.assertEqual(return_code, 0)
                self.assertIn(expected, output)
                self.assertNotIn("disconnect", output.lower())
                self.assertNotIn("restart", output.lower())

    def test_reset_copy_describes_actual_platform_operations(self) -> None:
        success = net_stability.CommandResult(["refresh"], 0, "", "", 1.0)
        scenarios = (
            (
                "Windows",
                "Windows network stack reset",
                "Resets TCP/IP and Winsock",
                "net_stability.windows_reset_network_stack",
                [success, success, success],
            ),
            (
                "Linux",
                "Linux network service refresh",
                "Restarts the detected network service",
                "net_stability.linux_reset_network",
                [success],
            ),
            (
                "Darwin",
                "macOS transient network cache refresh",
                "Flushes route and DNS caches",
                "net_stability.macos_reset_network_config",
                [success],
            ),
        )

        for platform_name, title, detail, operation, results in scenarios:
            with self.subTest(platform=platform_name):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with contextlib.ExitStack() as stack:
                    stack.enter_context(
                        mock.patch(
                            "net_stability.platform.system", return_value=platform_name
                        )
                    )
                    stack.enter_context(mock.patch(operation, return_value=results))
                    if platform_name == "Windows":
                        stack.enter_context(
                            mock.patch(
                                "net_stability.is_windows_admin", return_value=True
                            )
                        )
                    else:
                        stack.enter_context(
                            mock.patch(
                                "net_stability.os.geteuid", return_value=0, create=True
                            )
                        )
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    return_code = net_stability.command_reset_network(
                        mock.Mock(yes=True)
                    )

                output = stdout.getvalue() + stderr.getvalue()
                self.assertEqual(return_code, 0)
                self.assertIn(title, output)
                self.assertIn(detail, output)
                self.assertNotIn("OS defaults", output)
                if platform_name != "Windows":
                    self.assertNotIn("Winsock", output)

    def test_linux_legacy_sysctl_without_file_metadata_preserves_file(self) -> None:
        manifest = {
            "applied": {
                "system": [
                    {
                        "type": "sysctl_conf",
                        "original": {"net.ipv4.tcp_rmem": "4096 87380 6291456"},
                    }
                ]
            }
        }
        commands: list[list[str]] = []

        def fake_run(args, timeout):
            del timeout
            commands.append(args)
            return net_stability.CommandResult(args, 0, "", "", 1.0)

        stderr = io.StringIO()
        with (
            mock.patch("net_stability.run_command", side_effect=fake_run),
            mock.patch("net_stability.linux_restore_sysctl_conf") as restore_file,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(stderr),
        ):
            results = net_stability.restore_linux_extended_tuning(manifest)

        restore_file.assert_not_called()
        self.assertEqual(
            commands,
            [["sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 6291456"]],
        )
        self.assertEqual(
            results,
            [
                {
                    "type": "sysctl_conf",
                    "ok": False,
                    "runtime_restored": True,
                    "persistent_restored": False,
                    "manual_restore_required": True,
                }
            ],
        )
        self.assertIn("file was preserved", stderr.getvalue())

    def test_linux_legacy_sysctl_explicit_absent_file_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy-sysctl.conf"
            path.write_text("legacy", encoding="utf-8")
            manifest = {
                "applied": {
                    "system": [
                        {
                            "type": "sysctl_conf",
                            "original": {"net.core.rmem_max": "212992"},
                            "original_file": {
                                "path": str(path),
                                "existed": False,
                                "content": None,
                            },
                        }
                    ]
                }
            }
            success = net_stability.CommandResult(["sysctl"], 0, "", "", 1.0)

            with (
                mock.patch("net_stability.run_command", return_value=success),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                results = net_stability.restore_linux_extended_tuning(manifest)

            self.assertFalse(path.exists())
        self.assertTrue(results[0]["ok"])
        self.assertTrue(results[0]["runtime_restored"])
        self.assertTrue(results[0]["persistent_restored"])

    def test_macos_legacy_tcp_buffers_without_file_metadata_preserves_file(
        self,
    ) -> None:
        manifest = {
            "applied": {
                "system": [
                    {
                        "type": "tcp_buffers",
                        "original_send": 65536,
                        "original_recv": 131072,
                    }
                ]
            }
        }
        success = net_stability.CommandResult(["sysctl"], 0, "", "", 1.0)
        stderr = io.StringIO()

        with (
            mock.patch(
                "net_stability.macos_set_tcp_buffers",
                return_value=[success, success],
            ) as restore_runtime,
            mock.patch("net_stability.macos_restore_sysctl_conf") as restore_file,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(stderr),
        ):
            results = net_stability.restore_macos_extended_tuning(manifest)

        restore_runtime.assert_called_once_with(65536, 131072)
        restore_file.assert_not_called()
        self.assertEqual(
            results,
            [
                {
                    "type": "tcp_buffers",
                    "ok": False,
                    "runtime_restored": True,
                    "persistent_restored": False,
                    "manual_restore_required": True,
                }
            ],
        )
        self.assertIn("exact persistent rollback is unavailable", stderr.getvalue())

    def test_macos_legacy_tcp_buffers_explicit_absent_file_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sysctl.conf"
            path.write_text("legacy", encoding="utf-8")
            manifest = {
                "applied": {
                    "system": [
                        {
                            "type": "tcp_buffers",
                            "original_send": 65536,
                            "original_recv": 131072,
                            "original_file": {
                                "path": str(path),
                                "existed": False,
                                "content": None,
                            },
                        }
                    ]
                }
            }
            success = net_stability.CommandResult(["sysctl"], 0, "", "", 1.0)

            with (
                mock.patch(
                    "net_stability.macos_set_tcp_buffers",
                    return_value=[success, success],
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                results = net_stability.restore_macos_extended_tuning(manifest)

            self.assertFalse(path.exists())
        self.assertTrue(results[0]["ok"])
        self.assertTrue(results[0]["runtime_restored"])
        self.assertTrue(results[0]["persistent_restored"])

    def test_linux_legacy_ring_buffer_recovers_originals_from_state(self) -> None:
        manifest = {
            "state": {
                "system": {
                    "ring_buffers": {
                        "interfaces": [
                            {
                                "name": "eth0",
                                "original_rx": 512,
                                "original_tx": 256,
                            }
                        ]
                    }
                }
            },
            "applied": {"system": [{"type": "ring_buffer", "interface": "eth0"}]},
        }
        success = net_stability.CommandResult(["ethtool"], 0, "", "", 1.0)

        with (
            mock.patch(
                "net_stability.linux_set_nic_ring_buffer", return_value=success
            ) as restore_ring,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            results = net_stability.restore_linux_extended_tuning(manifest)

        restore_ring.assert_called_once_with("eth0", 512, 256)
        self.assertEqual(
            results, [{"type": "ring_buffer", "ok": True, "interface": "eth0"}]
        )

    def test_linux_legacy_ring_buffer_without_originals_preserves_current(self) -> None:
        manifest = {
            "state": {"system": {"ring_buffers": {"interfaces": []}}},
            "applied": {"system": [{"type": "ring_buffer", "interface": "eth0"}]},
        }
        stderr = io.StringIO()

        with (
            mock.patch("net_stability.linux_set_nic_ring_buffer") as restore_ring,
            contextlib.redirect_stderr(stderr),
        ):
            results = net_stability.restore_linux_extended_tuning(manifest)

        restore_ring.assert_not_called()
        self.assertEqual(
            results,
            [
                {
                    "type": "ring_buffer",
                    "ok": False,
                    "skipped": True,
                    "interface": "eth0",
                    "manual_restore_required": True,
                }
            ],
        )
        self.assertIn("current ring buffer settings", stderr.getvalue())
        self.assertIn("manual restoration required", stderr.getvalue())

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

    def test_extracted_analysis_modules_preserve_compatibility_exports(self) -> None:
        # Given: callers may still import established helpers from net_stability.
        compatibility_pairs = (
            (
                net_stability.parse_windows_wlan_interfaces,
                net_stability_wifi_analysis.parse_windows_wlan_interfaces,
            ),
            (
                net_stability.wifi_link_recommendations,
                net_stability_wifi_analysis.wifi_link_recommendations,
            ),
            (
                net_stability.bufferbloat_assessment,
                net_stability_router_diagnostics.bufferbloat_assessment,
            ),
            (
                net_stability.router_side_diagnosis,
                net_stability_router_diagnostics.router_side_diagnosis,
            ),
            (
                net_stability._apply_wan_queue_rule,
                net_stability_router_rules.apply_wan_queue_rule,
            ),
        )

        # Then: the compatibility layer delegates to the extracted implementations.
        for legacy_export, extracted_export in compatibility_pairs:
            with self.subTest(export=legacy_export.__name__):
                self.assertIs(legacy_export, extracted_export)

    def test_gui_done_event_restores_controls_and_preserves_result(self) -> None:
        # Given: a completed task event reaches the GUI queue.
        gui = net_stability_gui.NetStabilityGui.__new__(
            net_stability_gui.NetStabilityGui
        )
        gui.events = net_stability_gui.queue.Queue()
        gui.events.put("DONE:0:Run diagnostics")
        gui.running = True
        gui.process = mock.Mock()
        gui.cancel_requested = False
        gui.activity = mock.Mock()
        gui.cancel_button = mock.Mock()
        gui.status_var = mock.Mock()
        gui.root = mock.Mock()
        gui.stage_vars = {
            name: mock.Mock(**{"get.return_value": "Running"})
            for name in net_stability_gui.STAGE_ORDER
        }
        gui._set_controls_state = mock.Mock()

        # When: the structured completion event is drained.
        gui._drain_events()

        # Then: activity stops, controls return, and success remains visible.
        self.assertFalse(gui.running)
        self.assertIsNone(gui.process)
        gui.activity.stop.assert_called_once_with()
        gui.status_var.set.assert_called_once_with("Run diagnostics complete")
        gui._set_controls_state.assert_called_once_with(net_stability_gui.tk.NORMAL)

    def test_packaged_gui_routes_commands_to_sibling_cli(self) -> None:
        # Given: PyInstaller runs the GUI from the release bundle.
        spec = net_stability_gui.COMMANDS[0]
        executable = str(ROOT / "net-stability-gui-windows-x86_64.exe")

        # When: the GUI resolves the command target in frozen mode.
        with (
            mock.patch.object(net_stability_gui.sys, "frozen", True, create=True),
            mock.patch.object(net_stability_gui.sys, "executable", executable),
        ):
            command = net_stability_gui.command_for(spec)

        # Then: it launches the console CLI sibling rather than recursing into itself.
        self.assertEqual(command[0], str(ROOT / "net-stability-windows-x86_64.exe"))
        self.assertEqual(command[1:], spec.args)

    def test_packaged_gui_prefers_embedded_cli(self) -> None:
        # Given: the one-file GUI has extracted its bundled CLI companion.
        spec = net_stability_gui.COMMANDS[0]
        executable = str(ROOT / "net-stability-gui-windows-x86_64.exe")
        with tempfile.TemporaryDirectory() as temporary:
            embedded = Path(temporary) / "net-stability-windows-x86_64.exe"
            embedded.touch()

            # When: the frozen GUI resolves its command target.
            with (
                mock.patch.object(net_stability_gui.sys, "frozen", True, create=True),
                mock.patch.object(net_stability_gui.sys, "executable", executable),
                mock.patch.object(
                    net_stability_gui.sys, "_MEIPASS", temporary, create=True
                ),
            ):
                command = net_stability_gui.command_for(spec)

        # Then: the self-contained bundle target wins over an external sibling.
        self.assertEqual(command[0], str(embedded))
        self.assertEqual(command[1:], spec.args)

    def test_capability_matrix_reports_only_current_bounded_mutations(self) -> None:
        # Given: capability reporting is part of the public diagnostic contract.
        forbidden_capabilities = {
            "MTU optimization (1500)",
            "QoS reservable bandwidth 0%",
            "TCP retransmission tuning",
            "sysctl TCP/IP tuning (buffers, BBR, fq_codel)",
            "DNS optimization",
            "TCP buffer tuning",
        }

        for system in ("Windows", "Linux", "Darwin"):
            with self.subTest(system=system):
                with mock.patch("net_stability.platform.system", return_value=system):
                    matrix = net_stability.capability_matrix()

                labels = {item["capability"] for item in matrix}
                self.assertTrue(labels.isdisjoint(forbidden_capabilities))
                for item in matrix:
                    assert_no_unsafe_actions(self, item["mutation"])

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

    def test_linux_wifi_channel_evidence_recommends_router_side_fix(self) -> None:
        # Given: Linux nmcli exposes the same overlapping 2.4 GHz shape.
        quality = {
            "available": True,
            "platform": "Linux",
            "reports": {
                "nmcli_wifi_terse": {"stdout": "*:p00dy2GHz:5:120 Mbit/s:68:wlan0\n"}
            },
        }

        # When: StableNet normalizes link evidence across OSes.
        records = net_stability.wifi_link_records(quality)
        recommendations = net_stability.wifi_link_recommendations(quality)

        # Then: router-side channel and placement advice is available without OS mutation.
        self.assertEqual(records[0]["name"], "wlan0")
        self.assertEqual(records[0]["channel"], "5")
        recommendation_ids = {item["id"] for item in recommendations}
        self.assertIn("two_four_ghz_overlap_channel", recommendation_ids)
        self.assertIn("marginal_two_four_ghz_signal", recommendation_ids)

    def test_macos_wifi_channel_evidence_recommends_router_side_fix(self) -> None:
        # Given: macOS system_profiler exposes current Wi-Fi channel evidence.
        output = """
Wi-Fi:
  Interfaces:
    en0:
      Current Network Information:
        p00dy2GHz:
          PHY Mode: 802.11n
          Channel: 5
          Signal / Noise: -52 dBm / -90 dBm
          Transmit Rate: 120
"""
        quality = {
            "available": True,
            "platform": "macOS",
            "reports": {"airport_profiler": {"stdout": output}},
        }

        # When: the profiler output is converted into StableNet link evidence.
        records = net_stability.wifi_link_records(quality)
        recommendations = net_stability.wifi_link_recommendations(quality)

        # Then: channel evidence is preserved and the router/AP action remains advisory.
        self.assertEqual(records[0]["name"], "p00dy2GHz")
        self.assertEqual(records[0]["channel"], "5")
        channel_recommendation = [
            item
            for item in recommendations
            if item["id"] == "two_four_ghz_overlap_channel"
        ][0]
        self.assertEqual(
            channel_recommendation["mutation"], "router-side advisory only"
        )

    def test_router_diagnosis_recommends_sqm_only_when_gateway_stays_clean(
        self,
    ) -> None:
        # Given: the gateway remains clean while public jitter/loss rises under load.
        wifi_link_quality = {
            "available": True,
            "platform": "Windows",
            "interfaces": [],
            "recommendations": [],
        }
        download_report = {"throughput_mbps": 18.5, "failures": 0}

        # When: the router-side classifier reviews the loaded evidence.
        diagnosis = net_stability.router_side_diagnosis(
            clean_router_baseline_summary(),
            loaded_loss_summary(),
            wifi_link_quality,
            download_report,
            18.0,
        )

        # Then: the suite recommends manual SQM/AQM verification, not host folklore.
        self.assertEqual(diagnosis["verdict"], "router_wan_queue_likely")
        optimization_ids = {item["id"] for item in diagnosis["optimizations"]}
        self.assertIn("router-sqm-aqm", optimization_ids)
        for item in diagnosis["optimizations"]:
            self.assertFalse(item["automatic"])
            self.assertEqual(item["mutation"], "router-admin manual only")

    def test_router_diagnosis_suppresses_throughput_when_load_cap_is_too_small(
        self,
    ) -> None:
        # Given: a quick smoke run cannot physically transfer enough bytes to prove 18 Mbps.
        wifi_link_quality = {
            "available": True,
            "platform": "Windows",
            "interfaces": [],
            "recommendations": [],
        }
        download_report = {"throughput_mbps": 3.5, "failures": 0}

        # When: the classifier receives the configured capacity ceiling.
        diagnosis = net_stability.router_side_diagnosis(
            clean_router_baseline_summary(),
            loaded_loss_summary(),
            wifi_link_quality,
            download_report,
            18.0,
            load_capacity_mbps=4.0,
        )

        # Then: it keeps real queue evidence but does not invent a throughput-cap finding.
        finding_ids = {item["id"] for item in diagnosis["findings"]}
        self.assertIn("wan-queue-pressure", finding_ids)
        self.assertNotIn("throughput-below-target-with-clean-first-hop", finding_ids)
        self.assertIn(
            "throughput findings are suppressed", diagnosis["limitations"][-1]
        )

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

    def test_apply_windows_system_does_not_mutate_usb_wifi_power_paths(self) -> None:
        # Given: a captured USB Wi-Fi state that must remain untouched by normal apply.
        manifest = {"state": {"system": {}}, "applied": {"system": []}}

        # When: the conservative Windows system path is selected.
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch("net_stability.platform.system", return_value="Windows")
            )
            safe_repairs = stack.enter_context(
                mock.patch("net_stability.apply_windows_safe_repairs")
            )
            usb_suspend = stack.enter_context(
                mock.patch("net_stability.windows_set_usb_selective_suspend")
            )
            device_power = stack.enter_context(
                mock.patch("net_stability.windows_set_device_power_management")
            )
            with contextlib.redirect_stdout(io.StringIO()):
                net_stability.apply_system_state(
                    manifest,
                    Path("manifest.json"),
                    include_battery=True,
                    restart=False,
                )

        # Then: only evidence-gated repairs are delegated; blanket USB changes are not.
        safe_repairs.assert_called_once_with(manifest, Path("manifest.json"))
        usb_suspend.assert_not_called()
        device_power.assert_not_called()

    def test_ethernet_parser_preserves_physical_link_and_error_counters(self) -> None:
        # Given: ethtool exposes negotiated link state and explicit error counters.
        link = net_stability_link_diagnostics.parse_ethtool_link(
            "Speed: 1000Mb/s\nDuplex: full\nAuto-negotiation: on\nLink detected: yes\n"
        )
        counters = net_stability_link_diagnostics.parse_ethtool_stats(
            "rx_crc_errors: 4\ntx_errors: 0\nrx_packets: 900\n"
        )

        # Then: evidence is retained without turning speed into an optimization command.
        self.assertEqual(link["speed"], "1000Mb/s")
        self.assertEqual(link["duplex"], "full")
        self.assertEqual(link["carrier"], "yes")
        self.assertEqual(counters, {"rx_crc_errors": 4, "tx_errors": 0})

    def test_windows_ethernet_inventory_is_read_only_and_structured(self) -> None:
        # Given: PowerShell exposes a physical adapter with negotiated link fields.
        result = net_stability.CommandResult(
            ["powershell"],
            0,
            '{"Name":"Ethernet","Status":"Up","LinkSpeed":"1 Gbps",'
            '"FullDuplex":true,"AutoNegotiationEnabled":true}',
            "",
            1.0,
        )

        # When: the cross-platform Ethernet collector normalizes the report.
        quality = net_stability_link_diagnostics.collect_windows_ethernet(
            lambda _script, timeout: result
        )

        # Then: adapter ownership and mutation contract remain explicit.
        self.assertTrue(quality["available"])
        self.assertEqual(quality["interfaces"][0]["LinkSpeed"], "1 Gbps")
        self.assertEqual(quality["mutation"], "none")

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
