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
    re.compile(r"\b(?:set|force|guess|write|apply|change|tune)\s+(?:the\s+)?mtu\b"),
    re.compile(r"\b(?:replace|switch|set|change)\s+(?:the\s+)?dns\b"),
    re.compile(r"\bdisable\s+(?:global\s+)?ipv6\b"),
    re.compile(r"\b(?:tcp\s*ack|tcpackfrequency|nagle|tcpnodelay)\b"),
    re.compile(r"\b(?:disable|turn\s+off)\s+(?:all|broad|blanket|global)\s+.*offload\b"),
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


class CliGuardrailTests(unittest.TestCase):
    def test_help_when_requested_does_not_advertise_anti_folklore_actions(self) -> None:
        # Given: normal CLI help entry points.
        help_commands = (
            ("--help",),
            ("diagnose", "--help"),
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


if __name__ == "__main__":
    unittest.main()
