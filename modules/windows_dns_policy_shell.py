from __future__ import annotations

import json
from importlib import import_module
from typing import Any, Dict, List, Mapping, Optional, Tuple

_models = import_module("modules.windows_dns_policy_models")
DNS_POLICY_EVENT_IDS = _models.DNS_POLICY_EVENT_IDS
DnsPolicyHealth = _models.DnsPolicyHealth
DnsServerEntry = _models.DnsServerEntry
PowerShellResult = _models.PowerShellResult
PowerShellRunner = _models.PowerShellRunner


def collect_health(runner: PowerShellRunner) -> DnsPolicyHealth:
    nrpt = _query_nrpt_effective(runner)
    rules = _query_nrpt_rules(runner)
    event_counts = _query_dns_events(runner)
    dns_servers = _query_dns_servers(runner)
    return _build_health(nrpt, rules, event_counts, dns_servers)


def health_from_report(report: Mapping[str, Any]) -> DnsPolicyHealth:
    event_counts = {
        int(key): int(value)
        for key, value in _mapping(report.get("event_counts")).items()
        if str(key).isdigit()
    }
    servers = tuple(
        DnsServerEntry(
            str(item.get("interface_alias") or ""),
            str(item.get("address_family") or ""),
            tuple(str(server) for server in _sequence(item.get("servers"))),
        )
        for item in _sequence(report.get("dns_servers"))
        if isinstance(item, Mapping)
    )
    rules = tuple(
        item
        for item in _sequence(report.get("nrpt_rules"))
        if isinstance(item, Mapping)
    )
    findings = tuple(str(item) for item in _sequence(report.get("findings")))
    actions = tuple(str(item) for item in _sequence(report.get("recommended_actions")))
    limitations = tuple(str(item) for item in _sequence(report.get("limitations")))
    return DnsPolicyHealth(
        bool(report.get("available")),
        str(report.get("severity") or "unknown"),
        bool(report.get("repair_needed")),
        bool(report.get("nrpt_effective_ok")),
        str(report.get("nrpt_error") or ""),
        findings,
        actions,
        event_counts,
        servers,
        rules,
        limitations,
    )


def _query_nrpt_effective(runner: PowerShellRunner) -> Mapping[str, Any]:
    script = (
        "$ErrorActionPreference='Stop';"
        "try {"
        "  $items=@(Get-DnsClientNrptPolicy -Effective);"
        "  [pscustomobject]@{Ok=$true;Error='';Items=$items}"
        "} catch {"
        "  [pscustomobject]@{Ok=$false;Error=[string]$_.Exception.Message;Items=@()}"
        "} | ConvertTo-Json -Depth 8 -Compress"
    )
    return _json_mapping(runner(script, 20.0))


def _query_nrpt_rules(runner: PowerShellRunner) -> Tuple[Mapping[str, Any], ...]:
    script = (
        "$items=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | "
        "Select-Object Namespace,NameServers,DisplayName,Comment);"
        "ConvertTo-Json -InputObject $items -Depth 8 -Compress"
    )
    return tuple(
        item
        for item in _json_sequence(runner(script, 20.0))
        if isinstance(item, Mapping)
    )


def _query_dns_events(runner: PowerShellRunner) -> Mapping[int, int]:
    script = (
        "$start=(Get-Date).AddHours(-3);"
        "$items=@(Get-WinEvent -FilterHashtable @{LogName='System';"
        "ProviderName='Microsoft-Windows-DNS-Client';Id=1014,1023;StartTime=$start} "
        "-ErrorAction SilentlyContinue);"
        "$items | Group-Object Id | ForEach-Object {"
        "[pscustomobject]@{Id=[int]$_.Name;Count=[int]$_.Count}"
        "} | ConvertTo-Json -Depth 4 -Compress"
    )
    counts: Dict[int, int] = {}
    for item in _json_sequence(runner(script, 20.0)):
        if not isinstance(item, Mapping):
            continue
        event_id = _int_or_none(item.get("Id"))
        count = _int_or_none(item.get("Count"))
        if event_id in DNS_POLICY_EVENT_IDS and count is not None:
            counts[event_id] = count
    return counts


def _query_dns_servers(runner: PowerShellRunner) -> Tuple[DnsServerEntry, ...]:
    script = (
        "$items=@(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceAlias,AddressFamily,ServerAddresses);"
        "ConvertTo-Json -InputObject $items -Depth 5 -Compress"
    )
    entries: List[DnsServerEntry] = []
    for item in _json_sequence(runner(script, 20.0)):
        if not isinstance(item, Mapping):
            continue
        entries.append(
            DnsServerEntry(
                str(item.get("InterfaceAlias") or ""),
                str(item.get("AddressFamily") or ""),
                tuple(str(server) for server in _sequence(item.get("ServerAddresses"))),
            )
        )
    return tuple(entries)


def _build_health(
    nrpt: Mapping[str, Any],
    rules: Tuple[Mapping[str, Any], ...],
    event_counts: Mapping[int, int],
    dns_servers: Tuple[DnsServerEntry, ...],
) -> DnsPolicyHealth:
    nrpt_ok = bool(nrpt.get("Ok"))
    nrpt_error = str(nrpt.get("Error") or "")
    findings: List[str] = []
    if not nrpt_ok or event_counts.get(1023, 0) > 0:
        findings.append("dns_policy_corruption")
    if event_counts.get(1014, 0) > 0:
        findings.append("dns_resolution_timeouts")
    if any(entry.has_invalid_server for entry in dns_servers):
        findings.append("invalid_dns_server")

    actions: List[str] = []
    if findings:
        actions.append("flush_dns_cache")
    if any(entry.can_remove_invalid_server for entry in dns_servers):
        actions.append("remove_invalid_dns_sentinel_preserving_configured_servers")
    if any(
        entry.has_invalid_server and not entry.valid_servers for entry in dns_servers
    ):
        actions.append("review_invalid_only_dns_configuration")
    if "dns_policy_corruption" in findings:
        actions.append("reboot_or_reset_network_if_nrpt_persists")

    severity = "low"
    if "dns_resolution_timeouts" in findings:
        severity = "medium"
    if "dns_policy_corruption" in findings or "invalid_dns_server" in findings:
        severity = "high"

    return DnsPolicyHealth(
        True,
        severity,
        bool(findings),
        nrpt_ok,
        nrpt_error,
        tuple(dict.fromkeys(findings)),
        tuple(dict.fromkeys(actions)),
        event_counts,
        dns_servers,
        rules,
        ("NRPT rules are reported but not deleted automatically.",),
    )


def _json_mapping(result: PowerShellResult) -> Mapping[str, Any]:
    parsed = _json_value(result)
    if isinstance(parsed, Mapping):
        return parsed
    return {
        "Ok": False,
        "Error": "PowerShell returned a non-object JSON value",
        "Items": [],
    }


def _json_sequence(result: PowerShellResult) -> Tuple[Any, ...]:
    parsed = _json_value(result)
    if isinstance(parsed, list):
        return tuple(parsed)
    if parsed is None or parsed == "":
        return ()
    return (parsed,)


def _json_value(result: PowerShellResult) -> Any:
    if not result.ok:
        return {
            "Ok": False,
            "Error": result.error or result.stderr.strip(),
            "Items": [],
        }
    text = result.stdout.strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"Ok": False, "Error": text[:500], "Items": []}


def _sequence(value: Any) -> Tuple[Any, ...]:
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, tuple):
        return value
    if value is None:
        return ()
    return (value,)


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
