from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal


StageName = Literal["check", "audit", "system", "backup", "done"]


@dataclass(frozen=True, slots=True)
class CommandSpec:
    label: str
    args: tuple[str, ...]
    description: str
    primary: bool = False
    mutates: bool = False
    confirmation: str | None = None
    cancellable: bool = True

    def __post_init__(self) -> None:
        if self.mutates and not self.confirmation:
            raise ValueError("mutating commands require confirmation text")
        if self.mutates and self.cancellable:
            raise ValueError("mutating commands cannot be cancellable")
        if self.confirmation and not self.mutates:
            raise ValueError("confirmation text is reserved for mutating commands")


COMMANDS: Final[tuple[CommandSpec, ...]] = (
    CommandSpec(
        "Run diagnostics",
        ("diagnose", "--samples", "5", "--redact"),
        "Measure the local link, path, DNS, and application health without changing settings.",
        primary=True,
    ),
    CommandSpec(
        "Review recommended changes",
        ("apply", "--dry-run", "--system-only", "--no-restart"),
        "Show the small set of evidence-gated repairs available on this platform. Nothing is changed.",
    ),
    CommandSpec(
        "View restore points",
        ("list-backups",),
        "List saved restore points. Restoring one remains an explicit CLI action.",
    ),
    CommandSpec(
        "Apply recommended changes",
        ("apply", "--system-only", "--no-restart", "--yes"),
        "Create a restore point and apply only evidence-gated system repairs available on this platform. npm settings are not changed.",
        mutates=True,
        confirmation=(
            "Create a restore point and apply the reviewed system changes?\n\n"
            "Only evidence-gated repairs will be attempted. npm settings stay unchanged. "
            "After this starts, it cannot be stopped safely."
        ),
        cancellable=False,
    ),
    CommandSpec(
        "Run speed check",
        ("verify", "--redact"),
        "Measure loaded latency and M-Lab goodput without changing settings.",
    ),
    CommandSpec(
        "Inspect link",
        ("link-quality", "--redact"),
        "Inspect Ethernet carrier and errors plus Wi-Fi signal, channel, and rates.",
    ),
    CommandSpec(
        "Diagnose router path",
        (
            "router-diagnose",
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
        "Separate local Wi-Fi, router queue, and WAN symptoms with loaded evidence.",
    ),
    CommandSpec(
        "Review DNS repair",
        ("repair-dns", "--dry-run"),
        "Inspect the platform DNS repair plan. Nothing is changed from the GUI.",
    ),
)

STAGE_LABELS: Final[dict[StageName, str]] = {
    "check": "Check connection and platform",
    "audit": "Collect and classify evidence",
    "system": "Inspect link and OS context",
    "backup": "Confirm restore context",
    "done": "Finish with findings and limits",
}

STAGE_ORDER: Final[tuple[StageName, ...]] = (
    "check",
    "audit",
    "system",
    "backup",
    "done",
)
