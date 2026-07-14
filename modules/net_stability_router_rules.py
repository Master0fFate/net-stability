"""Pure router finding and advisory recommendation rules."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Set


def router_finding(
    identifier: str,
    layer: str,
    severity: str,
    confidence: float,
    facts: Sequence[str],
    detail: str,
) -> Dict[str, Any]:
    return {
        "id": identifier,
        "layer": layer,
        "severity": severity,
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "facts": list(facts),
        "detail": detail,
    }


def manual_router_optimization(record: Mapping[str, Any]) -> Dict[str, Any]:
    result = dict(record)
    result.setdefault("automatic", False)
    result.setdefault("mutation", "router-admin manual only")
    return result


def add_router_optimization(
    optimizations: List[Dict[str, Any]],
    seen: Set[str],
    record: Mapping[str, Any],
) -> None:
    identifier = str(record.get("id") or "")
    if not identifier or identifier in seen:
        return
    seen.add(identifier)
    optimizations.append(manual_router_optimization(record))


def router_wifi_channel_optimization() -> Dict[str, Any]:
    return {
        "id": "router-wifi-channel-plan",
        "layer": "router_wifi",
        "title": "Use a clean 2.4 GHz channel plan on the router/AP",
        "actions": [
            "In the router/AP Wi-Fi settings, choose the least busy of channels 1, 6, or 11 for 2.4 GHz.",
            "Use 20 MHz channel width on crowded 2.4 GHz networks; wider 2.4 GHz channels often add interference instead of throughput.",
            "Move high-throughput clients to a 5 GHz or 6 GHz SSID when both router and client support it.",
        ],
        "evidence": ["router-wifi-overlap-channel"],
        "expected_metrics": [
            "higher sustained download throughput",
            "lower loaded jitter",
            "fewer Wi-Fi retries when router counters expose them",
        ],
        "verify_with": "Rerun router-diagnose and link-quality after the router/AP change.",
        "risk": "low; incorrect channel choice can worsen neighboring-network contention.",
    }


def router_wifi_placement_optimization() -> Dict[str, Any]:
    return {
        "id": "router-wifi-placement",
        "layer": "router_wifi",
        "title": "Improve AP/client placement before changing TCP settings",
        "actions": [
            "Raise or reposition the router/AP and keep it away from metal, dense walls, USB 3.0 noise, and crowded power strips.",
            "Test a short USB extension or a different client position, then compare link signal and loaded throughput.",
            "If the router has band steering, verify the client is not being held on weak 2.4 GHz when a stronger 5 GHz path exists.",
        ],
        "evidence": ["router-wifi-marginal-signal"],
        "expected_metrics": [
            "stronger signal/RSSI",
            "higher link rate",
            "more stable loaded throughput",
        ],
        "verify_with": "Compare link-quality and router-diagnose before and after placement changes.",
        "risk": "low; physical placement changes are reversible.",
    }


def apply_router_wifi_rules(
    wifi_link_quality: Mapping[str, Any],
    findings: List[Dict[str, Any]],
    optimizations: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    wifi_recommendations = wifi_link_quality.get("recommendations", [])
    if not isinstance(wifi_recommendations, list):
        return
    for recommendation in wifi_recommendations:
        if not isinstance(recommendation, Mapping):
            continue
        recommendation_id = recommendation.get("id")
        detail = str(recommendation.get("detail") or "")
        if recommendation_id == "two_four_ghz_overlap_channel":
            findings.append(
                router_finding(
                    "router-wifi-overlap-channel",
                    "router_wifi",
                    "medium",
                    0.78,
                    [detail],
                    "The associated AP is using an overlapping 2.4 GHz channel. This can reduce usable throughput when nearby airtime is busy.",
                )
            )
            add_router_optimization(
                optimizations, seen, router_wifi_channel_optimization()
            )
        elif recommendation_id == "marginal_two_four_ghz_signal":
            findings.append(
                router_finding(
                    "router-wifi-marginal-signal",
                    "router_wifi",
                    "medium",
                    0.72,
                    [detail],
                    "The Wi-Fi link is usable but close enough to the edge that load can expose rate shifts, retries, or AP airtime pressure.",
                )
            )
            add_router_optimization(
                optimizations, seen, router_wifi_placement_optimization()
            )


def apply_gateway_pressure_rule(
    metrics: Mapping[str, Any],
    findings: List[Dict[str, Any]],
    optimizations: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    if not metrics["has_load"]:
        return
    if metrics["load_gateway_loss"] < 10.0 and not metrics["gateway_latency_inflated"]:
        return
    facts = [f"loaded_gateway_loss_percent={metrics['load_gateway_loss']:g}"]
    if metrics["load_gateway_p95"] is not None:
        facts.append(f"loaded_gateway_p95_ms={metrics['load_gateway_p95']:g}")
    findings.append(
        router_finding(
            "gateway-degrades-under-load",
            "router_or_ap_lan",
            "high",
            0.8,
            facts,
            "The first hop degraded during local load. That points to Wi-Fi airtime, AP/router CPU, router LAN queueing, or adapter path stress before blaming the ISP path.",
        )
    )
    add_router_optimization(
        optimizations,
        seen,
        {
            "id": "router-ap-health-check",
            "layer": "router_or_ap_lan",
            "title": "Check router/AP load and local-link contention",
            "actions": [
                "Inspect router/AP CPU, memory, wireless client count, and error counters during the failing workload if the UI exposes them.",
                "Compare one wired/Ethernet run or a different Wi-Fi band to separate AP/router pressure from ISP/WAN pressure.",
                "Remove accidental per-device caps, parental controls, or guest-network limits only when the router UI shows they apply to this client.",
            ],
            "evidence": ["gateway-degrades-under-load"],
            "expected_metrics": [
                "gateway loss below 5%",
                "gateway p95 latency stays close to idle",
                "fewer disconnects under package-install load",
            ],
            "verify_with": "Rerun router-diagnose under the same load after each router/AP change.",
            "risk": "low to moderate; router policy changes affect all clients.",
        },
    )


def apply_wan_queue_rule(
    metrics: Mapping[str, Any],
    findings: List[Dict[str, Any]],
    optimizations: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    if not (
        metrics["has_load"]
        and metrics["gateway_stable"]
        and (
            metrics["public_latency_inflated"]
            or metrics["load_public_loss"] >= 5.0
            or metrics["load_public_jitter"] >= 15.0
        )
    ):
        return
    facts = [
        f"loaded_gateway_loss_percent={metrics['load_gateway_loss']:g}",
        f"loaded_public_loss_percent={metrics['load_public_loss']:g}",
        f"loaded_public_jitter_ms={metrics['load_public_jitter']:g}",
    ]
    if (
        metrics["base_public_median"] is not None
        and metrics["load_public_p95"] is not None
    ):
        facts.extend(
            [
                f"idle_public_median_ms={metrics['base_public_median']:g}",
                f"loaded_public_p95_ms={metrics['load_public_p95']:g}",
            ]
        )
    findings.append(
        router_finding(
            "wan-queue-pressure",
            "router_queue",
            "high",
            0.86,
            facts,
            "The gateway stayed clean while the remote path degraded under download pressure. That is the classic host-visible shape of router/WAN queue pressure.",
        )
    )
    add_router_optimization(
        optimizations,
        seen,
        {
            "id": "router-sqm-aqm",
            "layer": "router_queue",
            "title": "Enable SQM/AQM at the WAN bottleneck",
            "actions": [
                "Use SQM/AQM with FQ-CoDel or CAKE on the router interface that actually bottlenecks the ISP link.",
                "Set download and upload shaping slightly below measured line rate; start around 90-95% and refine with loaded-latency results.",
                "Do not stack random client TCP tweaks on top of router queue symptoms; verify the queue directly after each router change.",
            ],
            "evidence": ["wan-queue-pressure"],
            "expected_metrics": [
                "lower loaded public p95 latency",
                "lower jitter under download and upload load",
                "stable package-manager downloads while other traffic is active",
            ],
            "verify_with": "Rerun router-diagnose; loaded public p95/jitter should fall while gateway remains clean.",
            "risk": "moderate; rate limits set too low cap throughput, and SQM must run at the true bottleneck.",
        },
    )


def apply_router_dns_rule(
    metrics: Mapping[str, Any],
    findings: List[Dict[str, Any]],
    optimizations: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    if metrics["dns_failure"] <= 0.0 or metrics["registry_failure"] >= 50.0:
        return
    findings.append(
        router_finding(
            "router-dns-forwarder-suspect",
            "router_dns",
            "medium",
            0.64,
            [
                f"dns_failure_percent={metrics['dns_failure']:g}",
                f"https_failure_percent={metrics['registry_failure']:g}",
            ],
            "DNS failed while HTTPS was not equally broken. That can be router DNS proxy/cache behavior, ISP resolver behavior, VPN policy, or host resolver state.",
        )
    )
    add_router_optimization(
        optimizations,
        seen,
        {
            "id": "router-dns-forwarder-review",
            "layer": "router_dns",
            "title": "Review router DNS forwarding only if failures repeat",
            "actions": [
                "Check whether multiple devices see DNS failures through the same router before changing DNS globally.",
                "If failures repeat, configure router DHCP/WAN DNS to reliable recursive resolvers or bypass a flaky router DNS proxy.",
                "Keep VPN or enterprise DNS rules intact; do not delete policy rules just to chase raw download speed.",
            ],
            "evidence": ["router-dns-forwarder-suspect"],
            "expected_metrics": [
                "DNS failure rate returns to 0%",
                "DNS median and p95 stabilize",
                "HTTPS probes remain successful",
            ],
            "verify_with": "Rerun diagnose or router-diagnose and compare DNS failure percent.",
            "risk": "moderate; DNS changes can break split-DNS, parental controls, or VPN routing.",
        },
    )


def apply_throughput_rule(
    metrics: Mapping[str, Any],
    findings: List[Dict[str, Any]],
    optimizations: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    if not (
        metrics["throughput"] is not None
        and metrics["throughput"] < metrics["min_download_mbps"]
        and metrics["gateway_stable"]
        and metrics["load_public_loss"] < 5.0
        and metrics["can_assess_download_target"]
    ):
        return
    findings.append(
        router_finding(
            "throughput-below-target-with-clean-first-hop",
            "router_or_isp_throughput",
            "medium",
            0.58,
            [
                f"download_load_mbps={metrics['throughput']:g}",
                f"min_download_mbps={metrics['min_download_mbps']:g}",
            ],
            "Throughput missed the target while the first hop stayed clean. This is not enough to blame the router alone, but it is enough to inspect router rate limits, WAN negotiation, and ISP plan/path evidence.",
        )
    )
    add_router_optimization(
        optimizations,
        seen,
        {
            "id": "router-throughput-policy-review",
            "layer": "router_or_isp_throughput",
            "title": "Inspect router throughput caps and WAN link state",
            "actions": [
                "Check router QoS, guest-network, parental-control, and per-device rate-limit rules for this client.",
                "Inspect router WAN port/link speed and modem/router logs for renegotiation or error counters.",
                "Compare with one wired client or another device before changing endpoint TCP settings.",
            ],
            "evidence": ["throughput-below-target-with-clean-first-hop"],
            "expected_metrics": [
                "download load meets target",
                "WAN/link error counters stop increasing",
                "wired comparison matches expected ISP plan",
            ],
            "verify_with": "Rerun router-diagnose and an NDT7 speed test after router policy changes.",
            "risk": "low to moderate; router policy edits can affect other clients.",
        },
    )
