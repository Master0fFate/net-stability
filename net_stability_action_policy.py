"""Safety policy and user-facing action planning for Net Stability.

This module is intentionally platform-agnostic.  The runtime passes the detected
platform into the planner so the CLI and GUI share one conservative contract.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List


def optimizer_action_ledger() -> List[Dict[str, Any]]:
    """Describe supported evidence and explicitly bounded mutations."""
    return [
        {
            "id": "measure-idle",
            "title": "Idle DNS, HTTPS, gateway, and public latency probes",
            "platforms": ["Windows", "Linux", "macOS"],
            "mutation": "none",
            "evidence": "local ping plus DNS and HTTPS probes",
            "precheck": "network command availability",
            "postcheck": "JSON report with loss, latency, jitter, DNS, and HTTPS summaries",
            "reversible": "not applicable",
        },
        {
            "id": "measure-ndt7",
            "title": "M-Lab NDT7 application goodput test",
            "platforms": ["Windows", "Linux", "macOS"],
            "mutation": "none",
            "evidence": "M-Lab Locate API v2 and NDT7 WebSocket/TLS protocol",
            "precheck": "Locate API returns usable WSS download/upload URLs",
            "postcheck": "download/upload Mbps and server metadata saved without access tokens",
            "reversible": "not applicable",
        },
        {
            "id": "inspect-ethernet-wifi-link",
            "title": "Ethernet and Wi-Fi link quality inventory",
            "platforms": ["Windows", "Linux", "macOS"],
            "mutation": "none",
            "evidence": "documented OS diagnostics for carrier, speed, duplex, signal, channel, rates, and errors",
            "precheck": "platform link-inspection command availability",
            "postcheck": "structured link evidence stored in the report when exposed by the OS",
            "reversible": "not applicable",
        },
        {
            "id": "apply-npm-weak-link-profile",
            "title": "npm weak-link retry and concurrency profile",
            "platforms": ["Windows", "Linux", "macOS"],
            "mutation": "user npm configuration only; explicit opt-in",
            "evidence": "npm user config semantics and snapshot readback",
            "precheck": "npm executable and non-root user context",
            "postcheck": "snapshot-backed manifest and npm config readback",
            "reversible": "restore command restores exact previous user config",
        },
        {
            "id": "apply-windows-dns-policy-repair",
            "title": "Windows DNS policy repair when health checks find corruption",
            "platforms": ["Windows"],
            "mutation": "repair only invalid resolver state and flush the cache; no DNS speed replacement",
            "evidence": "NRPT health, DNS Client events, and resolver inventory",
            "precheck": "health classifier identifies a repairable fault",
            "postcheck": "repair result and follow-up health evidence in manifest",
            "reversible": "snapshot-backed resolver restore; NRPT rules are never deleted automatically",
        },
        {
            "id": "repair-windows-tcp-autotuning",
            "title": "Windows receive-window auto-tuning repair when abnormal",
            "platforms": ["Windows"],
            "mutation": "set netsh auto-tuning to normal only from a known restricted state",
            "evidence": "netsh TCP global state",
            "precheck": "current value is disabled, restricted, highlyrestricted, or experimental",
            "postcheck": "manifest records original and applied values",
            "reversible": "snapshot-backed restore",
        },
        {
            "id": "deny-folklore",
            "title": "Deny unsafe or unproven optimizer folklore",
            "platforms": ["Windows", "Linux", "macOS"],
            "mutation": "none",
            "evidence": "explicit denylist and regression tests",
            "precheck": "planned action text and audit denylist",
            "postcheck": "guardrail tests reject advertised unsafe actions",
            "reversible": "not applicable",
        },
    ]


def planned_changes(
    system: str,
    do_system: bool,
    do_npm: bool,
    include_battery: bool,
    maxsockets: int,
) -> List[str]:
    """Return the exact conservative actions a command may perform."""
    changes: List[str] = []
    if do_system:
        if system == "Windows":
            changes.extend(
                [
                    "Repair Windows DNS policy only when health checks find invalid resolver state",
                    "Restore Windows TCP receive-window auto-tuning to normal when restricted or disabled",
                ]
            )
        elif system == "Linux":
            changes.append(
                "No automatic Linux system mutation; preserve resolver and kernel policy"
            )
        elif system == "Darwin":
            changes.append(
                "No automatic macOS system mutation; preserve resolver and sysctl policy"
            )
        else:
            changes.append(f"No system setting for {system}")
    if do_npm:
        changes.append(
            f"Apply the explicit opt-in npm weak-link profile (maxsockets={maxsockets}, retries, longer timeout, prefer-offline)"
        )
    return changes


def _measurement_capabilities() -> List[Dict[str, str]]:
    return [
        {
            "capability": "Idle gateway and remote latency probes",
            "available": "yes",
            "source": "ping with DNS and HTTPS corroboration",
            "privilege": "none",
            "mutation": "none",
        },
        {
            "capability": "Application command watch",
            "available": "yes",
            "source": "subprocess without shell",
            "privilege": "none",
            "mutation": "none",
        },
        {
            "capability": "Download-loaded benchmark",
            "available": "yes",
            "source": "bounded HTTPS load with gateway, public, DNS, and HTTPS probes",
            "privilege": "none",
            "mutation": "none; report output only",
        },
        {
            "capability": "Router-side diagnosis",
            "available": "yes",
            "source": "first-hop and remote-path evidence with link context",
            "privilege": "none",
            "mutation": "none; manual router/AP recommendations only",
        },
        {
            "capability": "M-Lab NDT7 application speed test",
            "available": "yes",
            "source": "M-Lab Locate API v2 and NDT7 WebSocket/TLS",
            "privilege": "none",
            "mutation": "none; report output only",
        },
        {
            "capability": "Ethernet and Wi-Fi link inspection",
            "available": "conditional",
            "source": "documented platform link and adapter commands",
            "privilege": "none",
            "mutation": "none",
        },
        {
            "capability": "Route, dual-stack, VPN/proxy, and PMTU context",
            "available": "conditional",
            "source": "platform route/address tools and a bounded PMTU probe",
            "privilege": "none",
            "mutation": "none",
        },
    ]


def _boundary_capabilities(npm_available: bool) -> List[Dict[str, str]]:
    return [
        {
            "capability": "npm weak-link profile",
            "available": "yes" if npm_available else "no",
            "source": "npm user configuration",
            "privilege": "user",
            "mutation": "explicit opt-in; snapshot-backed",
        },
        {
            "capability": "Router SQM/AQM control",
            "available": "no",
            "source": "endpoint-only tool boundary",
            "privilege": "router administrator",
            "mutation": "advice only",
        },
    ]


def _windows_capabilities() -> List[Dict[str, str]]:
    return [
        {
            "capability": "Windows adapter inventory",
            "available": "yes",
            "source": "PowerShell NetAdapter structured JSON and netsh WLAN",
            "privilege": "none",
            "mutation": "none",
        },
        {
            "capability": "Windows DNS policy health and repair",
            "available": "conditional",
            "source": "NRPT health, DNS Client events, and resolver inventory",
            "privilege": "administrator to repair",
            "mutation": "evidence-gated cache/policy repair; snapshot-backed",
        },
        {
            "capability": "Windows receive-window auto-tuning repair",
            "available": "conditional",
            "source": "netsh TCP global state",
            "privilege": "administrator to repair",
            "mutation": "restore abnormal restricted state to normal; snapshot-backed",
        },
        {
            "capability": "Network stack reset",
            "available": "conditional",
            "source": "netsh and ipconfig",
            "privilege": "administrator",
            "mutation": "explicit troubleshooting action; reboot may be required",
        },
        {
            "capability": "Windows WLAN report",
            "available": "conditional",
            "source": "netsh wlan report",
            "privilege": "user",
            "mutation": "none",
        },
    ]


def _linux_capabilities(
    command_available: Callable[[str], bool],
) -> List[Dict[str, str]]:
    return [
        {
            "capability": "NetworkManager Wi-Fi inventory",
            "available": "yes" if command_available("nmcli") else "no",
            "source": "nmcli structured fields",
            "privilege": "none",
            "mutation": "none",
        },
        {
            "capability": "Linux Ethernet counters",
            "available": "yes" if command_available("ethtool") else "no",
            "source": "ip and ethtool",
            "privilege": "none for supported reads",
            "mutation": "none",
        },
        {
            "capability": "Explicit resolver cache repair",
            "available": "yes" if command_available("resolvectl") else "conditional",
            "source": "repair-dns via resolvectl or a supported resolver service",
            "privilege": "platform-dependent",
            "mutation": "explicit command only; DNS configuration preserved",
        },
    ]


def _macos_capabilities(
    command_available: Callable[[str], bool],
) -> List[Dict[str, str]]:
    return [
        {
            "capability": "Working-condition responsiveness",
            "available": "yes" if command_available("networkQuality") else "no",
            "source": "networkQuality",
            "privilege": "none",
            "mutation": "none",
        },
        {
            "capability": "macOS link and route inspection",
            "available": "yes",
            "source": "networksetup, system_profiler, ifconfig, route, and scutil",
            "privilege": "none",
            "mutation": "none",
        },
        {
            "capability": "Explicit DNS cache repair",
            "available": "conditional",
            "source": "repair-dns via dscacheutil and mDNSResponder",
            "privilege": "administrator",
            "mutation": "explicit command only; resolver and sysctl configuration preserved",
        },
    ]


def _platform_capabilities(
    system: str, command_available: Callable[[str], bool]
) -> List[Dict[str, str]]:
    if system == "Windows":
        return _windows_capabilities()
    if system == "Linux":
        return _linux_capabilities(command_available)
    if system == "Darwin":
        return _macos_capabilities(command_available)
    return [
        {
            "capability": f"{system} system repair",
            "available": "no",
            "source": "unsupported platform",
            "privilege": "n/a",
            "mutation": "none",
        }
    ]


def capability_matrix(
    system: str,
    npm_available: bool,
    command_available: Callable[[str], bool],
) -> List[Dict[str, str]]:
    """Describe supported evidence and narrowly bounded write paths."""
    return [
        *_measurement_capabilities(),
        *_boundary_capabilities(npm_available),
        *_platform_capabilities(system, command_available),
    ]
