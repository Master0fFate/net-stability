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

UNSAFE_ACTION_PATTERNS: Final = (
    # MTU and DNS are now paper-backed overrides (removed from denylist test)
    # re.compile(r"\b(?:set|force|guess|write|apply|change|tune)\s+(?:the\s+)?mtu\b"),
    # re.compile(r"\b(?:replace|switch|set|change)\s+(?:the\s+)?dns\b"),
    re.compile(r"\bdisable\s+(?:global\s+)?ipv6\b"),
    re.compile(r"\b(?:tcp\s*ack|tcpackfrequency|nagle|tcpnodelay)\b"),
    # Selective offload disable is now paper-backed (removed from denylist test)
    # re.compile(r"\b(?:disable|turn\s+off)\s+(?:all|broad|blanket|global)\s+.*offload\b"),
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
        "gateway_ping": {"available": True, "loss_percent": 0.0, "median_ms": 2.0, "p95_ms": 4.0},
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

    def test_apply_dry_run_when_planning_changes_does_not_expose_unsafe_actions(self) -> None:
        # Given: dry-run apply scopes that should be non-destructive.
        scenarios = (
            ("npm-only", ("apply", "--dry-run", "--npm-only"), "Linux"),
            ("windows-system", ("apply", "--dry-run", "--system-only", "--no-restart"), "Windows"),
            ("linux-system", ("apply", "--dry-run", "--system-only", "--no-restart"), "Linux"),
        )

        for name, argv, platform_name in scenarios:
            with self.subTest(name=name):
                stdout = io.StringIO()
                stderr = io.StringIO()

                # When: the dry-run path is executed without writing settings.
                with contextlib.ExitStack() as stack:
                    stack.enter_context(
                        mock.patch("net_stability.platform.system", return_value=platform_name)
                    )
                    stack.enter_context(
                        mock.patch("net_stability.validate_apply_context", return_value=None)
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

    def test_windows_system_plan_when_dry_run_repairs_restricted_tcp_autotuning(self) -> None:
        # Given: Windows system tuning is rendered without writing settings.
        stdout = io.StringIO()
        stderr = io.StringIO()

        # When: the dry-run plan is generated for Windows.
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch("net_stability.platform.system", return_value="Windows"))
            stack.enter_context(mock.patch("net_stability.validate_apply_context", return_value=None))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            return_code = net_stability.main(("apply", "--dry-run", "--system-only", "--no-restart"))

        # Then: the system plan includes repair of receive-window autotuning.
        self.assertEqual(return_code, 0, stderr.getvalue())
        output = stdout.getvalue()
        self.assertIn("Restore Windows TCP receive-window auto-tuning to normal", output)
        planned_lines = "\n".join(line for line in output.splitlines() if line.startswith("  - "))
        assert_no_unsafe_actions(self, planned_lines)

    def test_windows_tcp_state_when_autotuning_disabled_marks_repair_needed(self) -> None:
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

    def test_benchmark_help_when_inputs_are_excessive_rejects_before_network_use(self) -> None:
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
    def test_redacted_diagnose_report_when_generated_removes_mac_and_token_like_values(self) -> None:
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
                stack.enter_context(mock.patch("net_stability.default_gateway", return_value=None))
                stack.enter_context(mock.patch("net_stability.collect_samples", return_value=[sample]))
                stack.enter_context(
                    mock.patch("net_stability.summarize_samples", return_value=unavailable_summary())
                )
                stack.enter_context(
                    mock.patch(
                    "net_stability.platform_metadata",
                    return_value={"adapter": MAC_SENTINEL, "credential": TOKEN_SENTINEL},
                    )
                )
                stack.enter_context(
                    mock.patch(
                    "net_stability.collect_platform_diagnostics",
                    return_value={"raw": f"{MAC_SENTINEL} {TOKEN_SENTINEL}"},
                    )
                )
                stack.enter_context(
                    mock.patch("net_stability.maybe_run_network_quality", return_value=None)
                )
                stack.enter_context(
                    mock.patch("net_stability.maybe_generate_windows_wlan_report", return_value=None)
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

    def test_watch_when_child_exits_preserves_exact_return_code_without_network(self) -> None:
        # Given: command monitoring with all network probes replaced by deterministic samples.
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "watch.json"
            child = (sys.executable, "-c", "import sys; sys.exit(37)")

            # When: the monitored child exits with a distinctive status.
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch("net_stability.default_gateway", return_value=None))
                stack.enter_context(
                    mock.patch("net_stability.collect_samples", return_value=[{"phase": "baseline"}])
                )
                stack.enter_context(
                    mock.patch("net_stability.collect_sample", return_value={"phase": "load"})
                )
                stack.enter_context(
                    mock.patch("net_stability.summarize_samples", return_value=unavailable_summary())
                )
                stack.enter_context(
                    mock.patch("net_stability.compare_phases", return_value=["deterministic child"])
                )
                stack.enter_context(
                    mock.patch("net_stability.platform_metadata", return_value={"system": "test"})
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

    def test_pressure_classification_when_download_loss_spares_gateway_recommends_sqm(self) -> None:
        # Given: download load shows the user's symptom: remote loss and jitter, stable gateway.
        baseline = {
            "gateway_ping": {"available": True, "loss_percent": 0.0, "median_ms": 2.0},
            "public_ping": {"available": True, "loss_percent": 0.0, "median_ms": 25.0, "p95_ms": 30.0},
            "dns": {"available": True, "failure_percent": 0.0},
            "registry_https": {"available": True, "failure_percent": 0.0},
        }

        # When: StableNet classifies the loaded benchmark.
        observations, recommendations = net_stability.classify_measurement(
            baseline,
            loaded_loss_summary(),
        )

        # Then: the report points at router/WAN queue pressure instead of DNS tweaks.
        self.assertIn("obs-download_loaded_loss_or_jitter", {item["id"] for item in observations})
        self.assertIn("rec-download-sqm-aqm", {item["id"] for item in recommendations})

    def test_benchmark_when_mocked_writes_loaded_report(self) -> None:
        # Given: benchmark internals are replaced by deterministic no-network data.
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "benchmark.json"

            # When: the benchmark command is driven through the real CLI parser.
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch("net_stability.default_gateway", return_value="192.168.1.1"))
                stack.enter_context(
                    mock.patch("net_stability.collect_samples", return_value=[{"phase": "baseline"}])
                )
                stack.enter_context(
                    mock.patch("net_stability.summarize_samples", side_effect=[unavailable_summary(), loaded_loss_summary()])
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
                stack.enter_context(mock.patch("net_stability.adapter_counter_state", return_value=None))
                stack.enter_context(mock.patch("net_stability.platform_metadata", return_value={"system": "test"}))
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
            self.assertEqual(report["load_summary"]["public_ping"]["jitter_avg_ms"], 16.0)
            self.assertIn("rec-download-sqm-aqm", {item["id"] for item in report["recommendations"]})


if __name__ == "__main__":
    unittest.main()
