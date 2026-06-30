from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal


StageName = Literal["check", "audit", "backup", "npm", "system", "tuning", "reset", "done"]


@dataclass(frozen=True, slots=True)
class CommandSpec:
    label: str
    args: tuple[str, ...]
    description: str
    primary: bool = False


COMMANDS: Final[tuple[CommandSpec, ...]] = (
    CommandSpec(
        "Audit evidence first",
        ("audit", "--redact"),
        "Create a read-only evidence, capability, and safety-policy report.",
        primary=True,
    ),
    CommandSpec(
        "Full Optimization",
        ("apply", "--yes"),
        "Back up and apply ALL supported DNS policy, TCP/IP, Wi-Fi, and npm reliability optimizations.",
        primary=True,
    ),
    CommandSpec(
        "Repair DNS",
        ("repair-dns", "--yes"),
        "Repair platform DNS state: Windows policy health, Linux resolver cache, or macOS DNS cache.",
    ),
    CommandSpec(
        "Measure idle baseline",
        ("measure", "idle", "--samples", "5", "--redact"),
        "Collect baseline gateway, remote, DNS, and HTTPS measurements.",
    ),
    CommandSpec(
        "Benchmark pressure points",
        (
            "benchmark",
            "--baseline-seconds",
            "5",
            "--load-seconds",
            "15",
            "--parallel-downloads",
            "3",
            "--download-mb",
            "8",
            "--redact",
        ),
        "Run a read-only loaded benchmark for download loss, jitter, DNS, HTTPS, and adapter counters.",
    ),
    CommandSpec(
        "Run full diagnostics",
        ("diagnose", "--samples", "5", "--redact"),
        "Measure network health and save a redacted JSON report.",
    ),
    CommandSpec(
        "Optimize connection",
        ("apply", "--system-only", "--yes"),
        "Apply system-level OS reliability and tuning settings (requires admin).",
    ),
    CommandSpec(
        "Optimize npm only",
        ("apply", "--npm-only", "--yes"),
        "Use only user-level npm settings. Does not require administrator rights.",
    ),
    CommandSpec(
        "Reset Network Stack",
        ("reset-network", "--yes"),
        "Reset TCP/IP, Winsock, and DNS to OS defaults (requires reboot).",
    ),
    CommandSpec(
        "Restore latest backup",
        ("restore", "latest", "--yes"),
        "Undo the most recent Net Stability change set.",
    ),
    CommandSpec(
        "Show backups",
        ("list-backups",),
        "List restore points created by this tool.",
    ),
)

STAGE_LABELS: Final[dict[StageName, str]] = {
    "check": "Check the connection and platform",
    "audit": "Map evidence and safe capabilities",
    "backup": "Create a restore point",
    "npm": "Tune npm for weak links",
    "system": "Apply OS Wi-Fi power and adapter settings",
    "tuning": "Apply TCP/IP, DNS, and buffer tuning",
    "reset": "Reset network stack",
    "done": "Show the result and restore path",
}

STAGE_ORDER: Final[tuple[StageName, ...]] = ("check", "audit", "backup", "npm", "system", "tuning", "reset", "done")
