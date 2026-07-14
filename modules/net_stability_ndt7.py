from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

DEFAULT_LOCATE_URL = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
NDT7_SUBPROTOCOL = "net.measurementlab.ndt.v7"
UPLOAD_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class Ndt7Config:
    locate_url: str = DEFAULT_LOCATE_URL
    timeout_seconds: float = 14.0
    user_agent: str = "NetStability/unknown"
    run_download: bool = True
    run_upload: bool = True
    max_results: int = 4


def public_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _url_for_direction(urls: Mapping[str, Any], direction: str) -> Optional[str]:
    preferred_key = f"wss:///ndt/v7/{direction}"
    preferred = urls.get(preferred_key)
    if isinstance(preferred, str) and preferred.startswith("wss://"):
        return preferred
    for key, value in urls.items():
        if (
            isinstance(key, str)
            and isinstance(value, str)
            and key.startswith("wss:")
            and f"/{direction}" in key
            and value.startswith("wss://")
        ):
            return value
    return None


def extract_ndt7_targets(
    payload: Mapping[str, Any], max_results: int = 4
) -> List[Dict[str, Any]]:
    raw_results = payload.get("results")
    if raw_results is None:
        raw_results = payload.get("result")
    if not isinstance(raw_results, list):
        return []

    targets: List[Dict[str, Any]] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        urls = item.get("urls")
        if not isinstance(urls, dict):
            continue
        download_url = _url_for_direction(urls, "download")
        upload_url = _url_for_direction(urls, "upload")
        if not download_url and not upload_url:
            continue
        targets.append(
            {
                "machine": item.get("machine"),
                "location": item.get("location")
                if isinstance(item.get("location"), dict)
                else {},
                "download_url": download_url,
                "upload_url": upload_url,
            }
        )
        if len(targets) >= max_results:
            break
    return targets


def locate_ndt7_targets(config: Ndt7Config) -> Dict[str, Any]:
    request = urllib.request.Request(
        config.locate_url,
        headers={
            "Accept": "application/json",
            "User-Agent": config.user_agent,
        },
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=10.0) as response:
            status = int(getattr(response, "status", response.getcode()))
            body = response.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        return {
            "available": False,
            "status": exc.code,
            "duration_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "error": f"Locate API returned HTTP {exc.code}",
            "targets": [],
        }
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        return {
            "available": False,
            "status": None,
            "duration_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "error": str(exc),
            "targets": [],
        }

    duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
    if status == 204:
        return {
            "available": False,
            "status": status,
            "duration_ms": duration_ms,
            "error": "Locate API reported no NDT7 server capacity",
            "targets": [],
        }
    if status < 200 or status >= 300:
        return {
            "available": False,
            "status": status,
            "duration_ms": duration_ms,
            "error": f"Locate API returned HTTP {status}",
            "targets": [],
        }
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "status": status,
            "duration_ms": duration_ms,
            "error": f"Could not parse Locate API JSON: {exc}",
            "targets": [],
        }

    targets = extract_ndt7_targets(payload, config.max_results)
    return {
        "available": bool(targets),
        "status": status,
        "duration_ms": duration_ms,
        "error": None if targets else "Locate API did not return usable WSS NDT7 URLs",
        "targets": [
            {
                "machine": target.get("machine"),
                "location": target.get("location") or {},
                "download_url": public_url(target["download_url"])
                if target.get("download_url")
                else None,
                "upload_url": public_url(target["upload_url"])
                if target.get("upload_url")
                else None,
            }
            for target in targets
        ],
        "_private_targets": targets,
    }


def _safe_measurement(message: str) -> Optional[Dict[str, Any]]:
    try:
        parsed = json.loads(message)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    safe: Dict[str, Any] = {}
    for key in ("AppInfo", "TCPInfo", "BBRInfo", "Origin", "Test"):
        value = parsed.get(key)
        if value is not None:
            safe[key] = value
    return safe or None


async def _connect(url: str, config: Ndt7Config):
    from websockets.asyncio.client import connect

    return connect(
        url,
        subprotocols=[NDT7_SUBPROTOCOL],
        user_agent_header=config.user_agent,
        open_timeout=min(10.0, max(2.0, config.timeout_seconds)),
        close_timeout=2.0,
        max_size=None,
        ping_interval=20.0,
        ping_timeout=10.0,
    )


def _throughput_mbps(byte_count: int, duration_seconds: float) -> float:
    return round((byte_count * 8.0) / (max(duration_seconds, 0.001) * 1_000_000.0), 3)


async def _run_download(
    url: str, target: Mapping[str, Any], config: Ndt7Config
) -> Dict[str, Any]:
    started = time.perf_counter()
    bytes_received = 0
    binary_messages = 0
    measurements: List[Dict[str, Any]] = []
    error: Optional[str] = None
    try:
        async with await _connect(url, config) as websocket:
            deadline = time.monotonic() + config.timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    message = await asyncio.wait_for(
                        websocket.recv(), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    break
                if isinstance(message, bytes):
                    bytes_received += len(message)
                    binary_messages += 1
                elif isinstance(message, str):
                    measurement = _safe_measurement(message)
                    if measurement:
                        measurements = (measurements + [measurement])[-8:]
    except (
        Exception
    ) as exc:  # WebSocket/network boundary; reported as measurement evidence.
        error = str(exc) or exc.__class__.__name__

    duration_seconds = time.perf_counter() - started
    return {
        "direction": "download",
        "success": bytes_received > 0,
        "machine": target.get("machine"),
        "location": target.get("location") or {},
        "url": public_url(url),
        "bytes": bytes_received,
        "messages": binary_messages,
        "duration_ms": round(duration_seconds * 1000.0, 3),
        "throughput_mbps": _throughput_mbps(bytes_received, duration_seconds),
        "measurements": measurements,
        "error": None if bytes_received > 0 else error or "download produced no data",
    }


async def _run_upload(
    url: str, target: Mapping[str, Any], config: Ndt7Config
) -> Dict[str, Any]:
    started = time.perf_counter()
    bytes_sent = 0
    binary_messages = 0
    measurements: List[Dict[str, Any]] = []
    payload = b"\x8a" * UPLOAD_CHUNK_BYTES
    error: Optional[str] = None
    try:
        async with await _connect(url, config) as websocket:
            deadline = time.monotonic() + config.timeout_seconds
            while time.monotonic() < deadline:
                await websocket.send(payload)
                bytes_sent += len(payload)
                binary_messages += 1
                if binary_messages % 8 == 0:
                    try:
                        message = await asyncio.wait_for(
                            websocket.recv(), timeout=0.001
                        )
                    except asyncio.TimeoutError:
                        continue
                    if isinstance(message, str):
                        measurement = _safe_measurement(message)
                        if measurement:
                            measurements = (measurements + [measurement])[-8:]
    except (
        Exception
    ) as exc:  # WebSocket/network boundary; reported as measurement evidence.
        error = str(exc) or exc.__class__.__name__

    duration_seconds = time.perf_counter() - started
    return {
        "direction": "upload",
        "success": bytes_sent > 0,
        "machine": target.get("machine"),
        "location": target.get("location") or {},
        "url": public_url(url),
        "bytes": bytes_sent,
        "messages": binary_messages,
        "duration_ms": round(duration_seconds * 1000.0, 3),
        "throughput_mbps": _throughput_mbps(bytes_sent, duration_seconds),
        "measurements": measurements,
        "error": None if bytes_sent > 0 else error or "upload produced no data",
    }


async def _run_direction(
    direction: str, targets: Sequence[Mapping[str, Any]], config: Ndt7Config
) -> Dict[str, Any]:
    failures: List[Dict[str, Any]] = []
    key = f"{direction}_url"
    for target in targets:
        url = target.get(key)
        if not isinstance(url, str):
            continue
        result = await (
            _run_download(url, target, config)
            if direction == "download"
            else _run_upload(url, target, config)
        )
        if result.get("success"):
            result["attempts"] = failures + [dict(result)]
            return result
        failures.append(result)
    return {
        "direction": direction,
        "success": False,
        "throughput_mbps": 0.0,
        "bytes": 0,
        "duration_ms": 0.0,
        "attempts": failures,
        "error": "all located NDT7 servers failed or lacked this direction",
    }


async def _run_speedtest_async(config: Ndt7Config) -> Dict[str, Any]:
    locate = locate_ndt7_targets(config)
    private_targets = locate.pop("_private_targets", [])
    report: Dict[str, Any] = {
        "available": bool(private_targets),
        "protocol": "ndt7",
        "locate": locate,
        "timeout_seconds": config.timeout_seconds,
        "download": None,
        "upload": None,
        "notes": [
            "NDT7 measures application-level goodput to a nearby M-Lab server; it is not a guaranteed ISP line-rate certificate.",
            "Locate API URLs include access tokens, but reports store only public scheme, host, and path.",
        ],
    }
    if not private_targets:
        report["error"] = locate.get("error") or "no NDT7 targets available"
        return report
    if config.run_download:
        report["download"] = await _run_direction("download", private_targets, config)
    if config.run_upload:
        report["upload"] = await _run_direction("upload", private_targets, config)
    successful = [
        item
        for item in (report.get("download"), report.get("upload"))
        if isinstance(item, dict) and item.get("success")
    ]
    report["available"] = bool(successful)
    report["error"] = (
        None if successful else "NDT7 speed test did not complete successfully"
    )
    return report


def run_ndt7_speedtest(config: Ndt7Config) -> Dict[str, Any]:
    try:
        import websockets  # noqa: F401
    except ImportError:
        return {
            "available": False,
            "protocol": "ndt7",
            "locate": None,
            "download": None,
            "upload": None,
            "error": "Python package 'websockets' is required for M-Lab NDT7 speed tests",
        }
    return asyncio.run(_run_speedtest_async(config))
