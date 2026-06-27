from __future__ import annotations

from windows_dns_policy_models import (
    DnsPolicyHealth,
    DnsServerEntry,
    PowerShellResult,
    PowerShellRunner,
    RepairAction,
    RepairResult,
    TransientFailureClassification,
    classify_transient_network_failure,
)
from windows_dns_policy_repair import repair_health, restore_dns_servers
from windows_dns_policy_shell import collect_health, health_from_report

__all__ = [
    "DnsPolicyHealth",
    "DnsServerEntry",
    "PowerShellResult",
    "PowerShellRunner",
    "RepairAction",
    "RepairResult",
    "TransientFailureClassification",
    "classify_transient_network_failure",
    "collect_health",
    "health_from_report",
    "repair_health",
    "restore_dns_servers",
]
