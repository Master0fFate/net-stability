from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
import net_stability  # noqa: E402
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
        self.assertIn("set_clean_dns_servers", health.recommended_actions)

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
        self.assertIn("Repair Windows DNS policy", output)


if __name__ == "__main__":
    unittest.main()
