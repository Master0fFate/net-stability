"""Read-only Ethernet link evidence shared by the CLI and GUI."""

from __future__ import annotations

import json
import os
import re
import shutil
from typing import Any, Callable, Mapping, Optional, Sequence


CommandRunner = Callable[[Sequence[str]], Any]
PowerShellRunner = Callable[[str], Any]


def _report(result: Any, limit: int = 20_000) -> dict[str, Any]:
    return result.to_report(limit=limit)


def _number(value: str) -> int | None:
    match = re.search(r"\d+", value)
    return int(match.group()) if match else None


def parse_ethtool_link(output: str) -> dict[str, Any]:
    """Parse stable physical-link fields without inferring health from speed alone."""
    fields: dict[str, Any] = {}
    labels = {
        "speed": "speed",
        "duplex": "duplex",
        "auto-negotiation": "autonegotiation",
        "link detected": "carrier",
    }
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        normalized = key.lower()
        if normalized in labels:
            fields[labels[normalized]] = value
    return fields


def parse_ethtool_stats(output: str) -> dict[str, int]:
    """Keep only explicit error/drop/retry counters from ethtool statistics."""
    counters: dict[str, int] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if not re.search(
            r"error|drop|miss|crc|fault|timeout|retry|collision", key, re.I
        ):
            continue
        number = _number(value)
        if number is not None:
            counters[key] = number
    return counters


def _linux_interfaces(run_command: CommandRunner) -> list[str]:
    result = run_command(["ip", "-o", "link", "show"])
    if not getattr(result, "ok", False):
        return []
    names: list[str] = []
    for line in result.stdout.splitlines():
        match = re.match(r"\d+:\s+([^:]+):", line)
        if not match:
            continue
        name = match.group(1).split("@", 1)[0]
        lowered = name.lower()
        if name != "lo" and not lowered.startswith(
            ("wl", "wlan", "wwan", "br-", "docker", "vir")
        ):
            names.append(name)
    return names[:8]


def collect_linux_ethernet(
    run_command: CommandRunner, which: Callable[[str], Optional[str]] = shutil.which
) -> dict[str, Any]:
    interfaces = _linux_interfaces(run_command) if which("ip") else []
    records: list[dict[str, Any]] = []
    for interface in interfaces:
        link = run_command(["ethtool", interface]) if which("ethtool") else None
        stats = run_command(["ethtool", "-S", interface]) if which("ethtool") else None
        record: dict[str, Any] = {"name": interface, "source": "ip and ethtool"}
        if link is not None:
            record.update(parse_ethtool_link(link.stdout))
            record["link_report"] = _report(link)
        if stats is not None:
            record["counters"] = parse_ethtool_stats(stats.stdout)
        records.append(record)
    return {
        "available": bool(records),
        "platform": "Linux",
        "source": "ip and ethtool",
        "interfaces": records,
        "mutation": "none",
    }


def collect_windows_ethernet(
    run_powershell: PowerShellRunner,
) -> dict[str, Any]:
    script = (
        "Get-NetAdapter -Physical | "
        "Where-Object {$_.MediaType -match '802.3|Ethernet' -or $_.Name -notmatch 'Wi-Fi|Wireless'} | "
        "Select-Object Name,InterfaceDescription,Status,LinkSpeed,MediaConnectState,"
        "FullDuplex,AutoNegotiationEnabled,MacAddress | ConvertTo-Json -Compress"
    )
    result = run_powershell(script, timeout=15)
    records: list[dict[str, Any]] = []
    if result.ok and result.stdout.strip():
        try:
            payload = json.loads(result.stdout)
            values = payload if isinstance(payload, list) else [payload]
            records = [dict(item) for item in values if isinstance(item, Mapping)]
        except json.JSONDecodeError:
            records = []
    return {
        "available": result.ok,
        "platform": "Windows",
        "source": "Get-NetAdapter -Physical",
        "interfaces": records,
        "raw": _report(result),
        "mutation": "none",
    }


def _mac_interfaces(run_command: CommandRunner) -> list[str]:
    result = run_command(["networksetup", "-listallhardwareports"])
    if not getattr(result, "ok", False):
        return []
    interfaces: list[str] = []
    current_port = ""
    for line in result.stdout.splitlines():
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Device:") and current_port:
            device = line.split(":", 1)[1].strip()
            if "ethernet" in current_port or "thunderbolt" in current_port:
                interfaces.append(device)
            current_port = ""
    return interfaces[:8]


def collect_macos_ethernet(run_command: CommandRunner) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for interface in _mac_interfaces(run_command):
        media = run_command(["networksetup", "-getMedia", interface])
        status = run_command(["ifconfig", interface])
        records.append(
            {
                "name": interface,
                "media": media.stdout.strip(),
                "carrier": "status: active" in status.stdout.lower(),
                "status_report": _report(status),
                "source": "networksetup and ifconfig",
            }
        )
    return {
        "available": bool(records),
        "platform": "macOS",
        "source": "networksetup and ifconfig",
        "interfaces": records,
        "mutation": "none",
    }


def collect_path_context(
    system: str,
    run_command: CommandRunner,
    run_powershell: PowerShellRunner,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> dict[str, Any]:
    """Collect route, dual-stack, VPN/proxy, and PMTU context without mutation."""
    reports: dict[str, Any] = {}
    if system == "Windows":
        reports["interfaces_routes"] = _report(
            run_powershell(
                "Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceIndex,"
                "IPv4Address,IPv6Address,IPv4DefaultGateway,DNSServer | ConvertTo-Json -Compress",
                timeout=20,
            )
        )
        reports["proxy"] = _report(run_command(["netsh", "winhttp", "show", "proxy"]))
        reports["vpn"] = _report(
            run_powershell(
                "Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | "
                "Select-Object Name,ConnectionStatus,ServerAddress,TunnelType | ConvertTo-Json -Compress",
                timeout=15,
            )
        )
        reports["pmtu_probe"] = _report(
            run_command(["ping", "-f", "-n", "1", "-l", "1472", "1.1.1.1"])
        )
    elif system == "Linux":
        for label, command in (
            ("interfaces", ["ip", "-brief", "address"]),
            ("routes_ipv4", ["ip", "route"]),
            ("routes_ipv6", ["ip", "-6", "route"]),
        ):
            if which(command[0]):
                reports[label] = _report(run_command(command))
        if which("nmcli"):
            reports["active_connections"] = _report(
                run_command(
                    [
                        "nmcli",
                        "-t",
                        "-f",
                        "NAME,TYPE,DEVICE,STATE",
                        "connection",
                        "show",
                        "--active",
                    ]
                )
            )
        reports["proxy_environment"] = {
            key.lower(): "set"
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
            if os.environ.get(key)
        }
        if which("ping"):
            reports["pmtu_probe"] = _report(
                run_command(["ping", "-M", "do", "-c", "1", "-s", "1472", "1.1.1.1"])
            )
    elif system == "Darwin":
        reports["interfaces"] = _report(run_command(["ifconfig"]))
        reports["routes_ipv4"] = _report(run_command(["route", "-n", "get", "default"]))
        reports["proxy"] = _report(run_command(["scutil", "--proxy"]))
        reports["vpn"] = _report(run_command(["scutil", "--nc", "list"]))
        reports["pmtu_probe"] = _report(
            run_command(["ping", "-D", "-c", "1", "-s", "1472", "1.1.1.1"])
        )
    return {"available": bool(reports), "reports": reports, "mutation": "none"}


def collect_ethernet_link_quality(
    system: str,
    run_command: CommandRunner,
    run_powershell: PowerShellRunner,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> dict[str, Any]:
    """Collect physical Ethernet evidence; never changes adapter state."""
    if system == "Windows":
        return collect_windows_ethernet(run_powershell)
    if system == "Linux":
        return collect_linux_ethernet(run_command, which)
    if system == "Darwin":
        return collect_macos_ethernet(run_command)
    return {
        "available": False,
        "platform": system,
        "source": "unsupported platform",
        "interfaces": [],
        "mutation": "none",
    }
