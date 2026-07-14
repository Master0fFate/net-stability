from __future__ import annotations

from importlib import import_module
from typing import List, Sequence

_models = import_module("modules.windows_dns_policy_models")
PowerShellResult = _models.PowerShellResult
PowerShellRunner = _models.PowerShellRunner
DnsPolicyHealth = _models.DnsPolicyHealth
RepairAction = _models.RepairAction
RepairResult = _models.RepairResult


def planned_dns_server_repairs(
    health: DnsPolicyHealth,
) -> tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...]:
    return tuple(
        (entry.interface_alias, entry.servers, entry.valid_servers)
        for entry in health.dns_servers
        if entry.can_remove_invalid_server
    )


def repair_health(
    runner: PowerShellRunner,
    health: DnsPolicyHealth,
) -> RepairResult:
    actions: List[RepairAction] = []
    notes: List[str] = []
    if not health.repair_needed:
        return RepairResult(
            True, False, (), ("Windows DNS policy health does not need repair.",)
        )

    flush = runner("Clear-DnsClientCache -ErrorAction SilentlyContinue; $true", 10.0)
    actions.append(_action_from_result("flush_dns_cache", flush))

    for (
        interface_alias,
        original_servers,
        applied_servers,
    ) in planned_dns_server_repairs(health):
        script = (
            "$ErrorActionPreference='Stop';"
            f"Set-DnsClientServerAddress -InterfaceAlias {_ps_quote(interface_alias)} "
            f"-ServerAddresses @({_ps_array(applied_servers)}) -ErrorAction Stop;"
            "$true"
        )
        result = runner(script, 15.0)
        actions.append(
            _action_from_result(
                "remove_invalid_dns_sentinel",
                result,
                interface_alias=interface_alias,
                original_servers=original_servers,
                applied_servers=applied_servers,
            )
        )

    invalid_only = [
        entry.interface_alias
        for entry in health.dns_servers
        if entry.has_invalid_server and not entry.valid_servers
    ]
    if invalid_only:
        notes.append(
            "Invalid-only DNS configuration was not replaced automatically; review: "
            + ", ".join(invalid_only)
        )

    if "dns_policy_corruption" in health.findings:
        notes.append(
            "NRPT policy corruption was detected; VPN or enterprise DNS rules were not deleted automatically."
        )
        notes.append(
            "If corruption remains after this repair, reboot or run the network stack reset."
        )

    return RepairResult(
        all(action.ok for action in actions),
        "dns_policy_corruption" in health.findings,
        tuple(actions),
        tuple(notes),
    )


def restore_dns_servers(
    runner: PowerShellRunner,
    interface_alias: str,
    original_servers: Sequence[str],
) -> RepairAction:
    if original_servers:
        script = (
            "$ErrorActionPreference='Stop';"
            f"Set-DnsClientServerAddress -InterfaceAlias {_ps_quote(interface_alias)} "
            f"-ServerAddresses @({_ps_array(tuple(original_servers))}) -ErrorAction Stop;"
            "$true"
        )
    else:
        script = (
            "$ErrorActionPreference='Stop';"
            f"Set-DnsClientServerAddress -InterfaceAlias {_ps_quote(interface_alias)} "
            "-ResetServerAddresses -ErrorAction Stop;"
            "$true"
        )
    result = runner(script, 15.0)
    return _action_from_result(
        "restore_dns_servers",
        result,
        interface_alias=interface_alias,
        original_servers=tuple(original_servers),
    )


def _action_from_result(
    name: str,
    result: PowerShellResult,
    interface_alias: str = "",
    original_servers: Sequence[str] = (),
    applied_servers: Sequence[str] = (),
) -> RepairAction:
    detail = result.error or result.stderr.strip() or result.stdout.strip()
    return RepairAction(
        name,
        result.ok,
        detail,
        interface_alias,
        tuple(original_servers),
        tuple(applied_servers),
    )


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _ps_array(values: Sequence[str]) -> str:
    return ",".join(_ps_quote(value) for value in values)
