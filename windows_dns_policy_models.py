from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Tuple


CONNECT_TIMEOUT_RE = re.compile(
    r"(?is)\b(?:UND_ERR_CONNECT_TIMEOUT|ConnectTimeoutError|ETIMEDOUT|EAI_AGAIN)\b"
)
RESET_RE = re.compile(r"(?is)\b(?:ECONNRESET|socket hang up)\b")
FETCH_FAILED_RE = re.compile(r"(?is)\bfetch failed\b")
INVALID_DNS_SERVER = "0.0.0.0"
DNS_POLICY_EVENT_IDS = (1014, 1023)


class PowerShellResult(Protocol):
    stdout: str
    stderr: str
    error: Optional[str]

    @property
    def ok(self) -> bool:
        ...


PowerShellRunner = Callable[[str, float], PowerShellResult]


@dataclass(frozen=True, slots=True)
class DnsServerEntry:
    interface_alias: str
    address_family: str
    servers: Tuple[str, ...]

    @property
    def has_invalid_server(self) -> bool:
        return INVALID_DNS_SERVER in self.servers

    def to_report(self) -> Dict[str, Any]:
        return {
            "interface_alias": self.interface_alias,
            "address_family": self.address_family,
            "servers": list(self.servers),
            "has_invalid_server": self.has_invalid_server,
        }


@dataclass(frozen=True, slots=True)
class DnsPolicyHealth:
    available: bool
    severity: str
    repair_needed: bool
    nrpt_effective_ok: bool
    nrpt_error: str
    findings: Tuple[str, ...]
    recommended_actions: Tuple[str, ...]
    event_counts: Mapping[int, int]
    dns_servers: Tuple[DnsServerEntry, ...]
    nrpt_rules: Tuple[Mapping[str, Any], ...]
    limitations: Tuple[str, ...]

    def to_report(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "severity": self.severity,
            "repair_needed": self.repair_needed,
            "nrpt_effective_ok": self.nrpt_effective_ok,
            "nrpt_error": self.nrpt_error,
            "findings": list(self.findings),
            "recommended_actions": list(self.recommended_actions),
            "event_counts": {str(key): value for key, value in self.event_counts.items()},
            "dns_servers": [entry.to_report() for entry in self.dns_servers],
            "nrpt_rules": list(self.nrpt_rules),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class RepairAction:
    name: str
    ok: bool
    detail: str
    interface_alias: str = ""
    original_servers: Tuple[str, ...] = ()
    applied_servers: Tuple[str, ...] = ()

    def to_report(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "interface_alias": self.interface_alias,
            "original_servers": list(self.original_servers),
            "applied_servers": list(self.applied_servers),
        }


@dataclass(frozen=True, slots=True)
class RepairResult:
    ok: bool
    reboot_recommended: bool
    actions: Tuple[RepairAction, ...]
    notes: Tuple[str, ...]

    def to_report(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "reboot_recommended": self.reboot_recommended,
            "actions": [action.to_report() for action in self.actions],
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class TransientFailureClassification:
    retryable: bool
    reason: str
    recommended_actions: Tuple[str, ...]


def classify_transient_network_failure(output: str) -> TransientFailureClassification:
    if CONNECT_TIMEOUT_RE.search(output):
        return TransientFailureClassification(
            True,
            "connect_timeout",
            ("run_dns_policy_health_check", "flush_dns_cache", "retry_with_backoff"),
        )
    if RESET_RE.search(output):
        return TransientFailureClassification(
            True,
            "connection_reset",
            ("run_dns_policy_health_check", "retry_with_backoff"),
        )
    if FETCH_FAILED_RE.search(output):
        return TransientFailureClassification(
            True,
            "fetch_failed",
            ("run_dns_policy_health_check", "retry_with_backoff"),
        )
    return TransientFailureClassification(False, "none", ())
