from __future__ import annotations

from importlib import import_module

_models = import_module("modules.windows_dns_policy_models")
_repair = import_module("modules.windows_dns_policy_repair")
_shell = import_module("modules.windows_dns_policy_shell")
DnsPolicyHealth = _models.DnsPolicyHealth
DnsServerEntry = _models.DnsServerEntry
PowerShellResult = _models.PowerShellResult
PowerShellRunner = _models.PowerShellRunner
RepairAction = _models.RepairAction
RepairResult = _models.RepairResult
TransientFailureClassification = _models.TransientFailureClassification
classify_transient_network_failure = _models.classify_transient_network_failure
planned_dns_server_repairs = _repair.planned_dns_server_repairs
repair_health = _repair.repair_health
restore_dns_servers = _repair.restore_dns_servers
collect_health = _shell.collect_health
health_from_report = _shell.health_from_report

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
    "planned_dns_server_repairs",
    "repair_health",
    "restore_dns_servers",
]
