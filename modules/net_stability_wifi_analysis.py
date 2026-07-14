"""Pure Wi-Fi parser and recommendation helpers.

No function in this module performs network I/O or changes system state.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional


def parse_key_value_lines(output: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized = re.sub(r"\s+", "_", key.strip().lower())
        if normalized:
            parsed[normalized] = value.strip()
    return parsed


def parse_windows_wlan_interfaces(output: str) -> List[Dict[str, str]]:
    interfaces: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    useful_keys = {
        "state",
        "ssid",
        "bssid",
        "radio_type",
        "channel",
        "signal",
        "receive_rate_(mbps)",
        "transmit_rate_(mbps)",
    }
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                interfaces.append(current)
                current = {}
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        normalized = re.sub(r"\s+", "_", key.strip().lower())
        if normalized == "name" and current:
            interfaces.append(current)
            current = {}
        current[normalized] = value.strip()
    if current:
        interfaces.append(current)
    return [item for item in interfaces if useful_keys.intersection(item)]


def first_number(value: Any) -> Optional[float]:
    match = re.search(r"-?\d+(?:[.,]\d+)?", str(value or ""))
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", "."))
    except ValueError:
        return None


def split_nmcli_terse(line: str) -> List[str]:
    fields: List[str] = []
    current: List[str] = []
    escaped = False
    for char in line.rstrip("\n"):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
            continue
        current.append(char)
    fields.append("".join(current))
    return fields


def parse_linux_nmcli_wifi_terse(output: str) -> List[Dict[str, str]]:
    interfaces: List[Dict[str, str]] = []
    for line in output.splitlines():
        fields = split_nmcli_terse(line)
        if len(fields) < 6 or fields[0] != "*":
            continue
        interfaces.append(
            {
                "name": fields[5] or fields[1] or "Wi-Fi",
                "ssid": fields[1],
                "channel": fields[2],
                "receive_rate_(mbps)": fields[3],
                "signal": fields[4],
                "device": fields[5],
                "source": "nmcli",
            }
        )
    return interfaces


def parse_macos_airport_profiler(output: str) -> List[Dict[str, str]]:
    current_name = ""
    current: Dict[str, str] = {}
    interfaces: List[Dict[str, str]] = []
    in_network = False
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if stripped == "Current Network Information:":
            in_network = True
            continue
        if not in_network or not stripped:
            continue
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            if current:
                interfaces.append(current)
                current = {}
            current_name = stripped[:-1]
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        normalized = re.sub(r"\s+", "_", key.strip().lower())
        if normalized == "phy_mode":
            normalized = "radio_type"
        elif normalized == "signal_/_noise":
            normalized = "signal_dbm"
            value = value.split("/", 1)[0]
        elif normalized == "transmit_rate":
            normalized = "transmit_rate_(mbps)"
        if normalized in {
            "radio_type",
            "channel",
            "signal_dbm",
            "transmit_rate_(mbps)",
        }:
            current[normalized] = value.strip()
            current.setdefault("name", current_name or "Wi-Fi")
            current.setdefault("source", "system_profiler")
    if current:
        interfaces.append(current)
    return interfaces


def wifi_link_records(quality: Mapping[str, Any]) -> List[Dict[str, Any]]:
    interfaces = quality.get("interfaces")
    if isinstance(interfaces, list):
        return [dict(item) for item in interfaces if isinstance(item, Mapping)]
    reports = quality.get("reports", {})
    if not isinstance(reports, Mapping):
        return []
    platform_name = str(quality.get("platform") or "")
    if platform_name == "Linux":
        terse = reports.get("nmcli_wifi_terse")
        if isinstance(terse, Mapping) and isinstance(terse.get("stdout"), str):
            return parse_linux_nmcli_wifi_terse(str(terse["stdout"]))
    if platform_name == "macOS":
        profiler = reports.get("airport_profiler")
        if isinstance(profiler, Mapping) and isinstance(profiler.get("stdout"), str):
            return parse_macos_airport_profiler(str(profiler["stdout"]))
    return []


def wifi_link_recommendations(quality: Mapping[str, Any]) -> List[Dict[str, Any]]:
    recommendations: List[Dict[str, Any]] = []
    for item in wifi_link_records(quality):
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "Wi-Fi")
        radio = str(item.get("radio_type") or "").lower()
        channel = first_number(item.get("channel"))
        signal = first_number(item.get("signal"))
        signal_dbm = first_number(item.get("signal_dbm"))
        if (
            channel is not None
            and 1 <= channel <= 14
            and int(channel)
            not in {
                1,
                6,
                11,
            }
        ):
            recommendations.append(
                {
                    "id": "two_four_ghz_overlap_channel",
                    "severity": "medium",
                    "interface": name,
                    "evidence": {
                        "radio_type": item.get("radio_type"),
                        "channel": int(channel),
                        "signal": item.get("signal") or item.get("signal_dbm"),
                        "source": item.get("source"),
                    },
                    "detail": (
                        f"{name} is on 2.4 GHz channel {int(channel)}, which overlaps "
                        "the standard 1/6/11 channel plan and can reduce throughput under contention."
                    ),
                    "action": (
                        "Change the router or access point 2.4 GHz channel to the least busy "
                        "of 1, 6, or 11, or use a 5 GHz SSID if the adapter/router path supports it."
                    ),
                    "mutation": "router-side advisory only",
                }
            )
        marginal_percent = signal is not None and signal < 70
        marginal_dbm = signal_dbm is not None and signal_dbm <= -67
        if ("802.11n" in radio or (channel is not None and channel <= 14)) and (
            marginal_percent or marginal_dbm
        ):
            signal_fact = (
                f"{signal:g}%"
                if signal is not None
                else f"{signal_dbm:g} dBm"
                if signal_dbm is not None
                else "marginal"
            )
            recommendations.append(
                {
                    "id": "marginal_two_four_ghz_signal",
                    "severity": "medium",
                    "interface": name,
                    "evidence": {
                        "radio_type": item.get("radio_type"),
                        "channel": item.get("channel"),
                        "signal": item.get("signal") or item.get("signal_dbm"),
                        "source": item.get("source"),
                    },
                    "detail": (
                        f"{name} signal is {signal_fact}; this is usable but marginal for "
                        "stable 18+ Mbps downloads on 2.4 GHz under load."
                    ),
                    "action": (
                        "Improve adapter placement, reduce obstruction, or test a short USB extension "
                        "to move the nano adapter away from the PC chassis."
                    ),
                    "mutation": "physical-placement advisory only",
                }
            )
    return recommendations
