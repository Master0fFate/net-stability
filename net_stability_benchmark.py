from __future__ import annotations

import http.client
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Final, List, Optional, Sequence

DEFAULT_DOWNLOAD_URL: Final = "https://speed.cloudflare.com/__down?bytes=67108864"
_CHUNK_SIZE: Final = 64 * 1024


@dataclass(frozen=True, slots=True)
class DownloadLoadConfig:
    url: str
    parallel: int
    bytes_per_worker: int
    timeout_seconds: float


def jitter_metrics(latencies: Sequence[float]) -> Dict[str, Optional[float]]:
    deltas = [
        abs(current - previous)
        for previous, current in zip(latencies, latencies[1:])
    ]
    if not deltas:
        return {"jitter_avg_ms": None, "jitter_max_ms": None}
    return {
        "jitter_avg_ms": round(sum(deltas) / len(deltas), 3),
        "jitter_max_ms": round(max(deltas), 3),
    }


def download_worker(
    config: DownloadLoadConfig,
    stop_event: threading.Event,
) -> Dict[str, Any]:
    parsed = urllib.parse.urlsplit(config.url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {
            "success": False,
            "bytes_read": 0,
            "duration_ms": 0.0,
            "error": "download URL must be an HTTPS URL with a hostname",
        }

    started = time.perf_counter()
    bytes_read = 0
    requests = 0
    error: Optional[str] = None
    context = ssl.create_default_context()
    port = parsed.port or 443
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))

    while not stop_event.is_set() and bytes_read < config.bytes_per_worker:
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            port,
            timeout=min(10.0, max(2.0, config.timeout_seconds)),
            context=context,
        )
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "User-Agent": "NetStability/1.0 benchmark",
                    "Accept": "application/octet-stream,*/*",
                    "Cache-Control": "no-cache",
                },
            )
            response = connection.getresponse()
            if response.status >= 400:
                error = f"HTTP {response.status}"
                break
            requests += 1
            while not stop_event.is_set() and bytes_read < config.bytes_per_worker:
                chunk = response.read(min(_CHUNK_SIZE, config.bytes_per_worker - bytes_read))
                if not chunk:
                    break
                bytes_read += len(chunk)
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
            error = str(exc)
            break
        finally:
            connection.close()

    duration_ms = (time.perf_counter() - started) * 1000.0
    return {
        "success": error is None and bytes_read > 0,
        "bytes_read": bytes_read,
        "duration_ms": round(duration_ms, 3),
        "requests": requests,
        "error": error,
    }


def summarize_download_results(
    url: str,
    parallel: int,
    duration_ms: float,
    workers: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    bytes_read = sum(int(worker.get("bytes_read") or 0) for worker in workers)
    successes = sum(1 for worker in workers if worker.get("success"))
    failures = len(workers) - successes
    seconds = max(duration_ms / 1000.0, 0.001)
    return {
        "url": url,
        "parallel": parallel,
        "bytes_read": bytes_read,
        "successes": successes,
        "failures": failures,
        "duration_ms": round(duration_ms, 3),
        "throughput_mbps": round((bytes_read * 8.0) / (seconds * 1_000_000.0), 3),
        "workers": list(workers),
    }
