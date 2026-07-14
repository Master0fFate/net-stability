"""Pure router-side evidence classification and advisory recommendations."""

from __future__ import annotations

from importlib import import_module
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

_router_rules = import_module("modules.net_stability_router_rules")
_wifi_analysis = import_module("modules.net_stability_wifi_analysis")
first_number = _wifi_analysis.first_number
_router_finding = _router_rules.router_finding
_manual_router_optimization = _router_rules.manual_router_optimization
_add_router_optimization = _router_rules.add_router_optimization
_router_wifi_channel_optimization = _router_rules.router_wifi_channel_optimization
_router_wifi_placement_optimization = _router_rules.router_wifi_placement_optimization
_apply_router_wifi_rules = _router_rules.apply_router_wifi_rules
_apply_gateway_pressure_rule = _router_rules.apply_gateway_pressure_rule
_apply_wan_queue_rule = _router_rules.apply_wan_queue_rule
_apply_router_dns_rule = _router_rules.apply_router_dns_rule
_apply_throughput_rule = _router_rules.apply_throughput_rule


def bufferbloat_assessment(
    baseline: Mapping[str, Any],
    load: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    if load is None:
        return {
            "available": False,
            "severity": "unknown",
            "evidence": [],
            "recommendation": "Run benchmark or verify --loaded to measure loaded latency.",
        }
    base_public = baseline.get("public_ping", {})
    load_public = load.get("public_ping", {})
    gateway = load.get("gateway_ping", {})
    base_median = base_public.get("median_ms")
    load_p95 = load_public.get("p95_ms")
    if base_median is None or load_p95 is None or not load_public.get("available"):
        return {
            "available": False,
            "severity": "unknown",
            "evidence": ["public latency summary unavailable"],
            "recommendation": "Repeat with an ICMP-reachable public target or compare with HTTPS timings.",
        }

    base_value = float(base_median)
    load_value = float(load_p95)
    gateway_loss = float(gateway.get("loss_percent") or 0.0)
    ratio = round(load_value / max(base_value, 1.0), 2)
    delta = round(load_value - base_value, 3)
    if gateway_loss >= 10.0:
        severity = "local_link_or_router"
        recommendation = "Gateway degraded under load; inspect Wi-Fi signal, adapter placement, USB path, AP load, and router CPU before router SQM."
    elif load_value >= max(200.0, base_value * 4.0):
        severity = "high"
        recommendation = "Evaluate SQM/FQ-CoDel/CAKE at the WAN bottleneck; keep PC-side TCP folklore disabled."
    elif load_value >= max(100.0, base_value * 2.0):
        severity = "medium"
        recommendation = "Loaded latency rose materially; repeat with separate download/upload load before changing router policy."
    else:
        severity = "low"
        recommendation = "No strong bufferbloat signal in this short run."
    return {
        "available": True,
        "severity": severity,
        "idle_public_median_ms": base_value,
        "load_public_p95_ms": load_value,
        "latency_delta_ms": delta,
        "latency_ratio": ratio,
        "gateway_loss_percent": gateway_loss,
        "recommendation": recommendation,
    }


def _summary_number(
    summary: Mapping[str, Any],
    section: str,
    key: str,
) -> Optional[float]:
    metric = summary.get(section, {})
    if not isinstance(metric, Mapping):
        return None
    value = metric.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _router_metrics(
    baseline: Mapping[str, Any],
    load: Optional[Mapping[str, Any]],
    download_report: Optional[Mapping[str, Any]],
    min_download_mbps: float,
    load_capacity_mbps: Optional[float],
) -> Dict[str, Any]:
    limitations = [
        "Endpoint probes can identify router/AP symptoms, but cannot read router CPU, airtime, WAN negotiation, or firmware state without router-admin integration.",
        "ICMP can be deprioritized; DNS and HTTPS probes are included to avoid single-signal conclusions.",
    ]
    base_gateway_median = _summary_number(baseline, "gateway_ping", "median_ms")
    load_gateway_p95 = _summary_number(load or {}, "gateway_ping", "p95_ms")
    load_gateway_loss = (
        _summary_number(load or {}, "gateway_ping", "loss_percent") or 0.0
    )
    base_public_median = _summary_number(baseline, "public_ping", "median_ms")
    load_public_p95 = _summary_number(load or {}, "public_ping", "p95_ms")
    load_public_loss = _summary_number(load or {}, "public_ping", "loss_percent") or 0.0
    load_public_jitter = (
        _summary_number(load or {}, "public_ping", "jitter_avg_ms") or 0.0
    )
    dns_failure = max(
        _summary_number(baseline, "dns", "failure_percent") or 0.0,
        _summary_number(load or {}, "dns", "failure_percent") or 0.0,
    )
    registry_failure = max(
        _summary_number(baseline, "registry_https", "failure_percent") or 0.0,
        _summary_number(load or {}, "registry_https", "failure_percent") or 0.0,
    )
    throughput = None
    if isinstance(download_report, Mapping):
        throughput = first_number(download_report.get("throughput_mbps"))
    can_assess_download_target = (
        load_capacity_mbps is None or load_capacity_mbps >= min_download_mbps
    )
    if not can_assess_download_target:
        limitations.append(
            "Download byte cap is below the requested throughput target for this load duration; throughput findings are suppressed for this run."
        )
    gateway_latency_inflated = (
        base_gateway_median is not None
        and load_gateway_p95 is not None
        and load_gateway_p95 >= max(50.0, base_gateway_median * 6.0)
    )
    gateway_stable = (
        load is not None and load_gateway_loss < 5.0 and not gateway_latency_inflated
    )
    public_latency_inflated = (
        base_public_median is not None
        and load_public_p95 is not None
        and load_public_p95 >= max(100.0, base_public_median * 2.5)
    )
    return {
        "has_load": load is not None,
        "base_public_median": base_public_median,
        "load_public_p95": load_public_p95,
        "load_public_loss": load_public_loss,
        "load_public_jitter": load_public_jitter,
        "load_gateway_p95": load_gateway_p95,
        "load_gateway_loss": load_gateway_loss,
        "gateway_latency_inflated": gateway_latency_inflated,
        "gateway_stable": gateway_stable,
        "public_latency_inflated": public_latency_inflated,
        "dns_failure": dns_failure,
        "registry_failure": registry_failure,
        "throughput": throughput,
        "min_download_mbps": min_download_mbps,
        "load_capacity_mbps": load_capacity_mbps,
        "can_assess_download_target": can_assess_download_target,
        "limitations": limitations,
    }


def _router_verdict(findings: Sequence[Mapping[str, Any]]) -> Tuple[str, float]:
    severity_order = {"high": 3, "medium": 2, "low": 1}
    leading = max(
        findings, key=lambda item: severity_order.get(str(item["severity"]), 0)
    )
    verdict_map = {
        "router_queue": "router_wan_queue_likely",
        "router_wifi": "router_wifi_or_ap_likely",
        "router_or_ap_lan": "router_or_ap_lan_likely",
        "router_dns": "router_dns_possible",
        "router_or_isp_throughput": "router_or_isp_throughput_possible",
        "not_isolated": "router_fault_not_proven",
    }
    return (
        verdict_map.get(str(leading["layer"]), "router_fault_not_proven"),
        float(leading["confidence"]),
    )


def router_side_diagnosis(
    baseline: Mapping[str, Any],
    load: Optional[Mapping[str, Any]],
    wifi_link_quality: Mapping[str, Any],
    download_report: Optional[Mapping[str, Any]],
    min_download_mbps: float,
    load_capacity_mbps: Optional[float] = None,
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    optimizations: List[Dict[str, Any]] = []
    seen_optimizations: Set[str] = set()
    metrics = _router_metrics(
        baseline, load, download_report, min_download_mbps, load_capacity_mbps
    )
    _apply_router_wifi_rules(
        wifi_link_quality, findings, optimizations, seen_optimizations
    )
    _apply_gateway_pressure_rule(metrics, findings, optimizations, seen_optimizations)
    _apply_wan_queue_rule(metrics, findings, optimizations, seen_optimizations)
    _apply_router_dns_rule(metrics, findings, optimizations, seen_optimizations)
    _apply_throughput_rule(metrics, findings, optimizations, seen_optimizations)

    if not findings:
        findings.append(
            _router_finding(
                "router-fault-not-proven",
                "not_isolated",
                "low",
                0.42,
                ["no_router_threshold_crossed=true"],
                "The current evidence does not prove a router-side fault. Keep device-side settings stable and capture the failing workload if the symptom returns.",
            )
        )

    verdict, confidence = _router_verdict(findings)
    return {
        "available": True,
        "verdict": verdict,
        "confidence": confidence,
        "findings": findings,
        "optimizations": optimizations,
        "evidence_summary": {
            "gateway_loss_percent_under_load": metrics["load_gateway_loss"],
            "gateway_loaded_p95_ms": metrics["load_gateway_p95"],
            "public_loaded_p95_ms": metrics["load_public_p95"],
            "public_loaded_jitter_ms": metrics["load_public_jitter"],
            "dns_failure_percent": metrics["dns_failure"],
            "registry_failure_percent": metrics["registry_failure"],
            "download_load_mbps": metrics["throughput"],
            "min_download_mbps": min_download_mbps,
            "load_capacity_mbps": load_capacity_mbps,
        },
        "limitations": metrics["limitations"],
        "mutation": "none; report output only",
    }
