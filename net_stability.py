#!/usr/bin/env python3
"""
Net Stability: conservative, reversible network reliability tuning and diagnostics.

Primary use case: weak or unstable Wi-Fi links where bursty tools such as npm
trigger disconnects, extreme latency, or repeated fetch failures.

Design principles
-----------------
* Standard-library Python only (Python 3.9+).
* Back up every setting this program changes before changing it.
* Avoid folklore tweaks: no MTU guessing, DNS replacement, Nagle hacks,
  TCP auto-tuning changes, QoS-reservation edits, global USB selective-suspend
  changes, or blanket NIC-offload disabling.
* Keep OS changes narrow:
    Windows: AC Wi-Fi power policy + supported per-adapter NDIS power controls.
    Linux: NetworkManager Wi-Fi powersave for active Wi-Fi profiles.
    macOS: diagnostics only; no undocumented system Wi-Fi knobs.
* Make npm more tolerant of a weak link by reducing per-origin concurrency,
  increasing retry tolerance, and preferring already-cached packages.

Backups are stored in:
  Windows: %LOCALAPPDATA%\\NetStability
  macOS:   ~/Library/Application Support/NetStability
  Linux:   $XDG_STATE_HOME/netstability or ~/.local/state/netstability

Examples
--------
  python net_stability.py diagnose
  python net_stability.py watch -- npm install
  python net_stability.py apply
  python net_stability.py restore latest
  python net_stability.py list-backups

Windows system tuning requires an Administrator terminal. On Linux, run the
normal command as your user first. If NetworkManager authorization is denied,
run a separate system-only operation with sudo; do not run npm tuning as root:

  python net_stability.py apply --npm-only
  sudo python net_stability.py apply --system-only
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import ctypes
import datetime as _dt
import hashlib
import http.client
import json
import locale
import math
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import ssl
import stat
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


APP_DISPLAY_NAME = "Net Stability"
APP_DIR_WINDOWS = "NetStability"
APP_DIR_UNIX = "netstability"
VERSION = "1.0.0"
SCHEMA_VERSION = 1

# Stable Windows power-setting GUIDs. Aliases are attempted first, and these
# GUIDs are the fallback for systems/locales where aliases are unavailable.
WINDOWS_WIFI_SUBGROUP_GUID = "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1"
WINDOWS_WIFI_POWER_SETTING_GUID = "12bbebe6-58d6-4636-95bb-3217ef867c1a"

DEFAULT_REGISTRY_HOST = "registry.npmjs.org"
DEFAULT_PUBLIC_PING_TARGET = "1.1.1.1"
WINDOWS_TCP_AUTOTUNING_NORMAL = "normal"
WINDOWS_TCP_AUTOTUNING_REPAIR_VALUES = {"disabled", "highlyrestricted", "restricted", "experimental"}

NPM_PROFILE_BASE: Dict[str, str] = {
    "fetch-retries": "5",
    "fetch-retry-factor": "2",
    "fetch-retry-mintimeout": "20000",
    "fetch-retry-maxtimeout": "120000",
    "fetch-timeout": "600000",
    "prefer-offline": "true",
}

CONTROL_LAYERS: Tuple[Dict[str, str], ...] = (
    {
        "id": "application",
        "label": "Application",
        "client_scope": "App-specific concurrency, retry, timeout, cache, and watched-command diagnostics.",
    },
    {
        "id": "host_transport",
        "label": "Host transport",
        "client_scope": "Read-only TCP/IP, DNS, route, proxy, dual-stack, and PMTU diagnostics.",
    },
    {
        "id": "adapter_usb",
        "label": "Adapter/USB",
        "client_scope": "Adapter inventory, power stability trials, and physical placement experiments.",
    },
    {
        "id": "wifi_link",
        "label": "Wi-Fi radio/link",
        "client_scope": "Signal, link-rate, association, retry, and placement/band observation.",
    },
    {
        "id": "router_queue",
        "label": "AP/router queue",
        "client_scope": "Loaded-latency diagnosis and SQM/AQM advice; router mutation is outside normal mode.",
    },
    {
        "id": "isp_path",
        "label": "ISP/WAN/path",
        "client_scope": "Remote-path evidence, target diversity, and family/path diagnostics.",
    },
)

EVIDENCE_POLICY: Tuple[Dict[str, str], ...] = (
    {
        "id": "F01",
        "feature": "Capability, topology, and baseline inventory",
        "priority": "P0",
        "risk": "read-only",
        "evidence_grade": "A/C",
        "layer": "host_transport",
    },
    {
        "id": "F02",
        "feature": "Longitudinal Wi-Fi telemetry",
        "priority": "P0",
        "risk": "read-only",
        "evidence_grade": "A/B/C",
        "layer": "wifi_link",
    },
    {
        "id": "F03",
        "feature": "Working-condition responsiveness tests",
        "priority": "P0",
        "risk": "read-only or opt-in traffic",
        "evidence_grade": "A/B",
        "layer": "router_queue",
    },
    {
        "id": "F04",
        "feature": "Multi-layer root-cause classifier",
        "priority": "P0",
        "risk": "read-only",
        "evidence_grade": "A/B",
        "layer": "isp_path",
    },
    {
        "id": "F15",
        "feature": "Benchmark-gated optimization engine",
        "priority": "P0",
        "risk": "governs mutations",
        "evidence_grade": "A/B",
        "layer": "application",
    },
    {
        "id": "F16",
        "feature": "Privacy, provenance, and reproducible reporting",
        "priority": "P0",
        "risk": "read-only",
        "evidence_grade": "A/C",
        "layer": "host_transport",
    },
)

ANTI_FOLKLORE_DENYLIST: Tuple[str, ...] = (
    # Overridden: paper-backed MTU=1500 is applied when safe
    # "fixed MTU values such as 1400 or 1472",
    "global IPv6 disable",
    # Overridden: paper-backed DNS replacement to 1.1.1.1
    # "DNS replacement as a speed boost",
    "TCP ACK/Nagle registry recipes",
    "TCP receive-window autotuning disable",
    # Overridden: paper-backed selective LSO disable when it causes latency
    # "blanket NIC offload disable",
    "RSS or VMQ tuning on Wi-Fi",
    # Overridden: paper-backed QoS reservable bandwidth = 0%
    # "NetworkThrottlingIndex or SystemResponsiveness gaming tweaks",
    "forced 5 GHz or maximum channel width",
    "global USB selective suspend disable",
    "Wi-Fi retry-limit reduction",
    # Overridden: paper-backed BBR on Linux and ECN on Windows
    # "blind CUBIC, BBR, ECN, L4S, or DSCP changes",
    "firewall or antivirus disable",
    "automatic random driver installation",
)

MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOKEN_VALUE_RE = re.compile(
    r"(?i)\b(?:bearer\s+[A-Za-z0-9._~+/=-]{16,}|npm_[A-Za-z0-9]{20,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|token[_-]like[_-][A-Za-z0-9_=-]{16,}|"
    r"(?:token|secret|password|passwd|api[_-]?key|auth)[=:]\S+)\b"
)
SECRET_ARG_RE = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|auth)")
GUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
PING_TIME_RE = re.compile(r"(?i)(?:time|temps|zeit|tiempo)[=<]\s*([0-9]+(?:[.,][0-9]+)?)\s*ms")
PING_LT_ONE_RE = re.compile(r"(?i)(?:time|temps|zeit|tiempo)<\s*1\s*ms")


class NetStabilityError(RuntimeError):
    """Expected, user-facing error."""


@dataclass
class CommandResult:
    args: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0

    def to_report(self, limit: int = 100_000) -> Dict[str, Any]:
        return {
            "args": self.args,
            "returncode": self.returncode,
            "duration_ms": round(self.duration_ms, 3),
            "stdout": _truncate(self.stdout, limit),
            "stderr": _truncate(self.stderr, limit),
            "error": self.error,
        }


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n...[truncated {len(value) - limit} characters]"


def _decode_bytes(data: bytes, preferred: Optional[str] = None) -> str:
    encodings: List[str] = []
    if preferred:
        encodings.append(preferred)
    encodings.extend(
        [
            "utf-8",
            locale.getpreferredencoding(False) or "utf-8",
            "cp1252",
            "cp437",
        ]
    )
    seen = set()
    for encoding in encodings:
        if encoding.lower() in seen:
            continue
        seen.add(encoding.lower())
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def run_command(
    args: Sequence[str],
    *,
    timeout: float = 20.0,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[Path] = None,
    preferred_encoding: Optional[str] = None,
) -> CommandResult:
    command = [str(item) for item in args]
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=dict(env) if env is not None else None,
            cwd=str(cwd) if cwd is not None else None,
            check=False,
        )
        duration = (time.perf_counter() - start) * 1000.0
        return CommandResult(
            command,
            completed.returncode,
            _decode_bytes(completed.stdout, preferred_encoding),
            _decode_bytes(completed.stderr, preferred_encoding),
            duration,
        )
    except FileNotFoundError as exc:
        duration = (time.perf_counter() - start) * 1000.0
        return CommandResult(command, 127, "", "", duration, f"command not found: {exc.filename}")
    except subprocess.TimeoutExpired as exc:
        duration = (time.perf_counter() - start) * 1000.0
        stdout = _decode_bytes(exc.stdout or b"", preferred_encoding)
        stderr = _decode_bytes(exc.stderr or b"", preferred_encoding)
        return CommandResult(command, 124, stdout, stderr, duration, f"timed out after {timeout:g}s")
    except OSError as exc:
        duration = (time.perf_counter() - start) * 1000.0
        return CommandResult(command, 126, "", "", duration, str(exc))


def powershell_executable() -> Optional[str]:
    return shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")


def run_powershell(script: str, *, timeout: float = 30.0) -> CommandResult:
    executable = powershell_executable()
    if not executable:
        return CommandResult(["powershell"], 127, "", "", 0.0, "PowerShell was not found")
    prefix = (
        "$ProgressPreference='SilentlyContinue';"
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
    )
    return run_command(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + script],
        timeout=timeout,
        preferred_encoding="utf-8",
    )


def utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def snapshot_id() -> str:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def original_user_identity() -> Tuple[Path, Optional[int], Optional[int]]:
    """Return target home/uid/gid, preserving the invoking user under sudo."""
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            try:
                import pwd  # POSIX only

                entry = pwd.getpwnam(sudo_user)
                return Path(entry.pw_dir), entry.pw_uid, entry.pw_gid
            except (ImportError, KeyError, OSError):
                pass
    return Path.home(), None, None


TARGET_HOME, TARGET_UID, TARGET_GID = original_user_identity()


def _fix_owner(path: Path) -> None:
    if os.name == "nt" or TARGET_UID is None or TARGET_GID is None:
        return
    with contextlib.suppress(OSError):
        os.chown(path, TARGET_UID, TARGET_GID)


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            path.chmod(0o700)
    _fix_owner(path)
    parent = path.parent
    if parent.exists() and TARGET_UID is not None:
        _fix_owner(parent)
    return path


def set_private_file(path: Path, mode: int = 0o600) -> None:
    if os.name != "nt":
        with contextlib.suppress(OSError):
            path.chmod(mode)
    _fix_owner(path)


def state_root() -> Path:
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_DIR_WINDOWS
        return TARGET_HOME / "AppData" / "Local" / APP_DIR_WINDOWS
    if system == "Darwin":
        return TARGET_HOME / "Library" / "Application Support" / APP_DIR_WINDOWS

    # XDG_STATE_HOME is intentionally ignored under sudo when it belongs to root.
    xdg = os.environ.get("XDG_STATE_HOME") if TARGET_UID is None else None
    if xdg and Path(xdg).is_absolute():
        return Path(xdg) / APP_DIR_UNIX
    return TARGET_HOME / ".local" / "state" / APP_DIR_UNIX


def backups_root() -> Path:
    return ensure_private_dir(ensure_private_dir(state_root()) / "backups")


def reports_root() -> Path:
    return ensure_private_dir(ensure_private_dir(state_root()) / "reports")


def atomic_write_bytes(
    path: Path,
    data: bytes,
    mode: int = 0o600,
    *,
    private_parent: bool = True,
) -> None:
    if private_parent:
        ensure_private_dir(path.parent)
    else:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        set_private_file(temporary, mode)
        os.replace(temporary, path)
        set_private_file(path, mode)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def atomic_write_json(
    path: Path, data: Mapping[str, Any], *, private_parent: bool = True
) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    atomic_write_bytes(path, payload, private_parent=private_parent)


def load_json(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise NetStabilityError(f"Could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise NetStabilityError(f"Invalid manifest format in {path}")
    return value


def sha256_path(path: Path) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def is_windows_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def is_sudo_root() -> bool:
    return (
        os.name != "nt"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and bool(os.environ.get("SUDO_USER"))
        and os.environ.get("SUDO_USER") != "root"
    )


def confirm(message: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise NetStabilityError("Confirmation is required in a non-interactive terminal; add --yes")
    answer = input(f"{message} [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def print_command_failure(label: str, result: CommandResult) -> None:
    detail = result.error or result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
    print(f"  ! {label}: {_truncate(detail, 500)}", file=sys.stderr)


def record_apply_issue(
    manifest: Dict[str, Any],
    manifest_path: Path,
    severity: str,
    scope: str,
    message: str,
) -> None:
    manifest.setdefault("issues", []).append(
        {"utc": utc_now_iso(), "severity": severity, "scope": scope, "message": message}
    )
    atomic_write_json(manifest_path, manifest)


def parse_json_output(result: CommandResult, label: str) -> Any:
    if not result.ok:
        raise NetStabilityError(f"{label} failed: {result.error or result.stderr.strip() or result.stdout.strip()}")
    text = result.stdout.strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise NetStabilityError(f"{label} returned invalid JSON: {_truncate(text, 500)}") from exc


def ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# npm backup and tuning
# ---------------------------------------------------------------------------


def npm_executable() -> Optional[str]:
    return shutil.which("npm") or shutil.which("npm.cmd")


def npm_environment() -> Dict[str, str]:
    env = dict(os.environ)
    # In ordinary execution this is unchanged. It prevents accidental root-home
    # npm state if a caller manually provides a target home.
    env["HOME"] = str(TARGET_HOME)
    if platform.system() == "Windows":
        env.setdefault("USERPROFILE", str(TARGET_HOME))
    return env


def npm_user_config_path(npm: str) -> Path:
    result = run_command([npm, "config", "get", "userconfig"], timeout=15, env=npm_environment())
    if result.ok:
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if lines:
            candidate = lines[-1]
            if candidate.lower() not in {"null", "undefined", "none"}:
                candidate = os.path.expandvars(candidate)
                if candidate.startswith("~"):
                    candidate = str(TARGET_HOME) + candidate[1:]
                path = Path(candidate)
                if not path.is_absolute():
                    path = TARGET_HOME / path
                return path
    return TARGET_HOME / ".npmrc"


def capture_npm_state(snapshot_dir: Path) -> Dict[str, Any]:
    npm = npm_executable()
    if not npm:
        return {"available": False, "reason": "npm was not found on PATH"}

    path = npm_user_config_path(npm)
    existed = os.path.lexists(path)
    was_symlink = path.is_symlink() if existed else False
    link_target: Optional[str] = None
    resolved_path: Optional[str] = None
    mode: Optional[int] = None
    backup_name: Optional[str] = None

    if was_symlink:
        with contextlib.suppress(OSError):
            link_target = os.readlink(path)
        with contextlib.suppress(OSError):
            resolved_path = str(path.resolve(strict=False))

    if existed:
        try:
            target_stat = path.stat()
            mode = stat.S_IMODE(target_stat.st_mode)
            payload = path.read_bytes()
        except OSError as exc:
            raise NetStabilityError(f"Cannot back up npm user config {path}: {exc}") from exc
        backup_name = "npmrc.before"
        atomic_write_bytes(snapshot_dir / backup_name, payload, mode=0o600)

    return {
        "available": True,
        "npm_executable": npm,
        "path": str(path),
        "existed": existed,
        "was_symlink": was_symlink,
        "link_target": link_target,
        "resolved_path": resolved_path,
        "mode": mode,
        "backup_file": backup_name,
        "pre_sha256": sha256_path(path) if existed else None,
    }


def npm_set_value(npm: str, config_path: Path, key: str, value: str) -> CommandResult:
    env = npm_environment()
    primary = run_command(
        [npm, "config", "set", key, value, "--location=user"],
        timeout=20,
        env=env,
    )
    if primary.ok:
        return primary
    # Compatibility path for older npm releases. npm config set defaults to
    # user location, and --userconfig pins the exact file we backed up.
    fallback = run_command(
        [npm, "config", "set", key, value, f"--userconfig={config_path}"],
        timeout=20,
        env=env,
    )
    if fallback.ok:
        return fallback
    combined = CommandResult(
        fallback.args,
        fallback.returncode,
        fallback.stdout,
        (primary.stderr + "\n" + fallback.stderr).strip(),
        primary.duration_ms + fallback.duration_ms,
        fallback.error or primary.error,
    )
    return combined


def apply_npm_profile(
    manifest: Dict[str, Any],
    manifest_path: Path,
    maxsockets: int,
) -> List[Dict[str, Any]]:
    state = manifest.get("state", {}).get("npm", {})
    if not state.get("available"):
        message = str(state.get("reason") or "npm was not found; npm profile skipped")
        print(f"  - {message}")
        record_apply_issue(manifest, manifest_path, "error", "npm", message)
        return []

    npm = str(state["npm_executable"])
    config_path = Path(str(state["path"]))
    profile = {"maxsockets": str(maxsockets), **NPM_PROFILE_BASE}
    results: List[Dict[str, Any]] = []

    config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for key, value in profile.items():
        result = npm_set_value(npm, config_path, key, value)
        record = {
            "type": "npm_config",
            "key": key,
            "value": value,
            "ok": result.ok,
            "error": result.error or (result.stderr.strip() if not result.ok else None),
        }
        results.append(record)
        if result.ok:
            print(f"  + npm {key}={value}")
        else:
            print_command_failure(f"npm {key}", result)
            record_apply_issue(
                manifest, manifest_path, "error", "npm",
                f"Failed to set npm {key}: {record.get('error') or 'unknown error'}",
            )
        manifest.setdefault("applied", {}).setdefault("npm", []).append(record)
        atomic_write_json(manifest_path, manifest)

    state["post_sha256"] = sha256_path(config_path)
    state["profile"] = profile
    atomic_write_json(manifest_path, manifest)
    return results


def _archive_current_file(path: Path, snapshot_dir: Path, label: str) -> Optional[str]:
    if not os.path.lexists(path):
        return None
    timestamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"{label}.{timestamp}.{secrets.token_hex(2)}"
    destination = snapshot_dir / name
    try:
        if path.is_symlink():
            target = os.readlink(path)
            if path.exists() and path.is_file():
                atomic_write_bytes(destination, path.read_bytes())
            else:
                atomic_write_bytes(destination, f"Dangling symlink: {target}\n".encode("utf-8"))
            atomic_write_bytes(
                snapshot_dir / f"{name}.symlink.txt",
                f"{target}\n".encode("utf-8"),
            )
        elif path.is_file():
            atomic_write_bytes(destination, path.read_bytes())
        else:
            atomic_write_bytes(destination, f"Non-regular path: {path}\n".encode("utf-8"))
        return name
    except OSError:
        return None


def restore_npm_state(manifest: Dict[str, Any], snapshot_dir: Path) -> Dict[str, Any]:
    state = manifest.get("state", {}).get("npm", {})
    if not state.get("available"):
        return {"ok": True, "skipped": "npm was unavailable when the snapshot was created"}

    path = Path(str(state["path"]))
    existed = bool(state.get("existed"))
    current_hash = sha256_path(path) if os.path.lexists(path) else None
    post_hash = state.get("post_sha256")
    conflict_backup = None
    if current_hash != post_hash and os.path.lexists(path):
        conflict_backup = _archive_current_file(path, snapshot_dir, "npmrc.before-restore")

    try:
        if existed:
            backup_name = state.get("backup_file")
            if not backup_name:
                raise NetStabilityError("Snapshot says .npmrc existed, but no backup file is recorded")
            backup_path = snapshot_dir / str(backup_name)
            if not backup_path.is_file():
                raise NetStabilityError(f"npm backup is missing: {backup_path}")
            payload = backup_path.read_bytes()

            if state.get("was_symlink") and state.get("resolved_path"):
                destination = Path(str(state["resolved_path"]))
                atomic_write_bytes(
                    destination, payload, mode=int(state.get("mode") or 0o600), private_parent=False
                )
                desired_link = state.get("link_target")
                if desired_link and (not path.is_symlink() or os.readlink(path) != desired_link):
                    _archive_current_file(path, snapshot_dir, "npmrc.link-before-restore")
                    with contextlib.suppress(FileNotFoundError):
                        path.unlink()
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    os.symlink(str(desired_link), path)
            else:
                atomic_write_bytes(
                    path, payload, mode=int(state.get("mode") or 0o600), private_parent=False
                )
        else:
            if os.path.lexists(path):
                if path.is_dir() and not path.is_symlink():
                    raise NetStabilityError(f"Refusing to delete directory at former npm config path: {path}")
                path.unlink()
        print(f"  + restored npm user config: {path}")
        return {"ok": True, "path": str(path), "conflict_backup": conflict_backup}
    except (OSError, NetStabilityError) as exc:
        print(f"  ! npm restore failed: {exc}", file=sys.stderr)
        return {"ok": False, "path": str(path), "error": str(exc), "conflict_backup": conflict_backup}


# ---------------------------------------------------------------------------
# Windows system state and tuning
# ---------------------------------------------------------------------------


def windows_power_state() -> Dict[str, Any]:
    active = run_command(["powercfg", "/getactivescheme"], timeout=10)
    if not active.ok:
        return {"available": False, "error": active.error or active.stderr.strip() or active.stdout.strip()}
    match = GUID_RE.search(active.stdout)
    if not match:
        return {"available": False, "error": f"Could not parse active power scheme: {active.stdout.strip()}"}
    scheme = match.group(0)

    query = run_command(["powercfg", "/query", scheme, "SUB_WIFI"], timeout=10)
    if not query.ok:
        query = run_command(["powercfg", "/query", scheme, WINDOWS_WIFI_SUBGROUP_GUID], timeout=10)
    if not query.ok:
        return {
            "available": False,
            "scheme_guid": scheme,
            "error": query.error or query.stderr.strip() or query.stdout.strip(),
        }

    ac_match = re.search(r"(?i)Current\s+AC\s+Power\s+Setting\s+Index\s*:\s*0x([0-9a-f]+)", query.stdout)
    dc_match = re.search(r"(?i)Current\s+DC\s+Power\s+Setting\s+Index\s*:\s*0x([0-9a-f]+)", query.stdout)
    ac_value: Optional[int] = int(ac_match.group(1), 16) if ac_match else None
    dc_value: Optional[int] = int(dc_match.group(1), 16) if dc_match else None

    # Locale-independent fallback: the Wi-Fi subgroup normally has one setting,
    # and the final two 0x values are its current AC/DC indexes.
    if ac_value is None or dc_value is None:
        hex_values = re.findall(r"(?i)0x([0-9a-f]{1,8})", query.stdout)
        if len(hex_values) >= 2:
            ac_value = int(hex_values[-2], 16)
            dc_value = int(hex_values[-1], 16)

    if ac_value is None or dc_value is None:
        return {
            "available": False,
            "scheme_guid": scheme,
            "error": "Could not parse AC/DC Wi-Fi power indexes",
            "query_excerpt": _truncate(query.stdout, 2000),
        }
    return {
        "available": True,
        "scheme_guid": scheme,
        "ac_value": ac_value,
        "dc_value": dc_value,
    }


def windows_wifi_adapters_state() -> Dict[str, Any]:
    script = r"""
$items = @()
$adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceType -eq 71 -or
    $_.NdisPhysicalMedium -eq 1 -or
    $_.NdisPhysicalMedium -eq 9 -or
    $_.InterfaceDescription -match '(?i)wireless|wi-?fi|802\.11'
})
foreach ($a in $adapters) {
    $pm = $null
    try { $pm = Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction Stop } catch { }
    $items += [pscustomobject]@{
        Name = [string]$a.Name
        InterfaceDescription = [string]$a.InterfaceDescription
        InterfaceGuid = [string]$a.InterfaceGuid
        Status = [string]$a.Status
        LinkSpeed = [string]$a.LinkSpeed
        DriverInformation = [string]$a.DriverInformation
        DriverFileName = [string]$a.DriverFileName
        DriverVersion = [string]$a.DriverVersionString
        PnPDeviceID = [string]$a.PnPDeviceID
        SelectiveSuspend = $(if ($null -ne $pm) { [string]$pm.SelectiveSuspend } else { $null })
        DeviceSleepOnDisconnect = $(if ($null -ne $pm) { [string]$pm.DeviceSleepOnDisconnect } else { $null })
    }
}
ConvertTo-Json -InputObject @($items) -Depth 5 -Compress
"""
    result = run_powershell(script, timeout=30)
    if not result.ok:
        return {"available": False, "error": result.error or result.stderr.strip() or result.stdout.strip(), "adapters": []}
    try:
        parsed = json.loads(result.stdout.strip() or "[]")
    except json.JSONDecodeError:
        return {"available": False, "error": f"Invalid PowerShell JSON: {_truncate(result.stdout, 1000)}", "adapters": []}
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        parsed = []
    return {"available": True, "adapters": parsed}


def parse_windows_tcp_global_state(result: CommandResult) -> Dict[str, Any]:
    if not result.ok:
        return {
            "available": False,
            "error": result.error or result.stderr.strip() or result.stdout.strip(),
        }
    state: Dict[str, Any] = {"available": True, "raw": result.stdout}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        normalized_key = " ".join(key.strip().lower().split())
        normalized_value = " ".join(value.strip().lower().split())
        if normalized_key == "receive window auto-tuning level":
            state["receive_window_autotuning"] = normalized_value
    return state


def windows_tcp_global_state() -> Dict[str, Any]:
    result = run_command(["netsh", "interface", "tcp", "show", "global"], timeout=10)
    return parse_windows_tcp_global_state(result)


def windows_tcp_autotuning_needs_repair(state: Mapping[str, Any]) -> bool:
    level = str(state.get("receive_window_autotuning") or "").strip().lower()
    return level in WINDOWS_TCP_AUTOTUNING_REPAIR_VALUES


def windows_set_tcp_autotuning(level: str) -> CommandResult:
    return run_command(
        ["netsh", "interface", "tcp", "set", "global", f"autotuninglevel={level}"],
        timeout=10,
    )


def capture_windows_state() -> Dict[str, Any]:
    return {
        "tcp_global": windows_tcp_global_state(),
        "power": windows_power_state(),
        "wifi_adapters": windows_wifi_adapters_state(),
    }


def windows_set_power_value(scheme: str, ac: Optional[int], dc: Optional[int]) -> List[CommandResult]:
    results: List[CommandResult] = []
    subgroup = WINDOWS_WIFI_SUBGROUP_GUID
    setting = WINDOWS_WIFI_POWER_SETTING_GUID
    if ac is not None:
        results.append(
            run_command(["powercfg", "/setacvalueindex", scheme, subgroup, setting, str(ac)], timeout=10)
        )
    if dc is not None:
        results.append(
            run_command(["powercfg", "/setdcvalueindex", scheme, subgroup, setting, str(dc)], timeout=10)
        )
    results.append(run_command(["powercfg", "/setactive", scheme], timeout=10))
    return results


def _valid_pm_value(value: Any) -> Optional[str]:
    text = str(value or "").strip().lower()
    if text == "enabled":
        return "Enabled"
    if text == "disabled":
        return "Disabled"
    return None


def windows_adapter_target_script(adapter: Mapping[str, Any]) -> str:
    guid = str(adapter.get("InterfaceGuid") or "").strip("{}")
    name = str(adapter.get("Name") or "")
    parts = ["$target = $null;"]
    if guid and GUID_RE.fullmatch(guid):
        parts.append(
            "$target = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
            f"Where-Object {{ ([string]$_.InterfaceGuid).Trim([char[]]'{{}}') -ieq {ps_single_quote(guid)} }} | Select-Object -First 1;"
        )
    if name:
        parts.append(
            f"if ($null -eq $target) {{ $target = Get-NetAdapter -Name {ps_single_quote(name)} -IncludeHidden -ErrorAction SilentlyContinue | Select-Object -First 1; }}"
        )
    parts.append("if ($null -eq $target) { throw 'Network adapter not found' }; ")
    return "".join(parts)


def windows_set_adapter_properties(
    adapter: Mapping[str, Any],
    properties: Mapping[str, str],
    restart: bool,
) -> CommandResult:
    if not properties:
        return CommandResult([], 0, "", "", 0.0)
    target_script = windows_adapter_target_script(adapter)
    assignments = "".join(
        f"$params[{ps_single_quote(key)}]={ps_single_quote(value)};" for key, value in properties.items()
    )
    restart_script = (
        "Restart-NetAdapter -Name $target.Name -Confirm:$false -ErrorAction Stop;" if restart else ""
    )
    script = (
        "$ErrorActionPreference='Stop';"
        + target_script
        + "$params=@{Name=$target.Name;NoRestart=$true;Confirm=$false;ErrorAction='Stop'};"
        + assignments
        + "Set-NetAdapterPowerManagement @params;"
        + restart_script
        + "[pscustomobject]@{Name=[string]$target.Name;Changed=$true}|ConvertTo-Json -Compress;"
    )
    return run_powershell(script, timeout=45)


def apply_windows_system(
    manifest: Dict[str, Any],
    manifest_path: Path,
    *,
    include_battery: bool,
    restart: bool,
) -> None:
    state = manifest.get("state", {}).get("system", {})
    tcp_global = state.get("tcp_global", {})
    if isinstance(tcp_global, dict) and windows_tcp_autotuning_needs_repair(tcp_global):
        original_level = str(tcp_global.get("receive_window_autotuning") or "").strip().lower()
        result = windows_set_tcp_autotuning(WINDOWS_TCP_AUTOTUNING_NORMAL)
        if result.ok:
            record = {
                "type": "windows_tcp_autotuning",
                "original_level": original_level,
                "applied": WINDOWS_TCP_AUTOTUNING_NORMAL,
            }
            manifest.setdefault("applied", {}).setdefault("system", []).append(record)
            atomic_write_json(manifest_path, manifest)
            print("  + Windows TCP receive-window auto-tuning: normal")
        else:
            print_command_failure("Windows TCP receive-window auto-tuning", result)
            record_apply_issue(
                manifest, manifest_path, "error", "windows",
                "Windows TCP receive-window auto-tuning repair failed: "
                f"{result.error or result.stderr.strip() or result.stdout.strip()}",
            )

    power = state.get("power", {})
    if power.get("available"):
        scheme = str(power["scheme_guid"])
        results = windows_set_power_value(scheme, 0, 0 if include_battery else None)
        if all(result.ok for result in results):
            record = {
                "type": "windows_wifi_power",
                "scheme_guid": scheme,
                "ac_value": 0,
                "dc_value": 0 if include_battery else None,
            }
            manifest.setdefault("applied", {}).setdefault("system", []).append(record)
            atomic_write_json(manifest_path, manifest)
            print("  + Windows Wi-Fi power policy: Maximum Performance on AC" + (" and battery" if include_battery else ""))
        else:
            for result in results:
                if not result.ok:
                    print_command_failure("Windows Wi-Fi power policy", result)
                    record_apply_issue(
                        manifest, manifest_path, "error", "windows",
                        f"Windows Wi-Fi power policy failed: {result.error or result.stderr.strip() or result.stdout.strip()}",
                    )
    else:
        message = f"Windows Wi-Fi power policy skipped: {power.get('error', 'setting unavailable')}"
        print(f"  - {message}")
        record_apply_issue(manifest, manifest_path, "warning", "windows", message)

    adapters_state = state.get("wifi_adapters", {})
    adapters = adapters_state.get("adapters", []) if isinstance(adapters_state, dict) else []
    if not adapters:
        print("  - no configurable physical Wi-Fi adapter power properties found")
        return

    for adapter in adapters:
        desired: Dict[str, str] = {}
        original: Dict[str, str] = {}
        for prop in ("SelectiveSuspend", "DeviceSleepOnDisconnect"):
            current = _valid_pm_value(adapter.get(prop))
            if current:
                original[prop] = current
            if current == "Enabled":
                desired[prop] = "Disabled"
        if not desired:
            continue
        result = windows_set_adapter_properties(adapter, desired, restart)
        if result.ok:
            record = {
                "type": "windows_adapter_power",
                "adapter": {
                    "Name": adapter.get("Name"),
                    "InterfaceGuid": adapter.get("InterfaceGuid"),
                    "InterfaceDescription": adapter.get("InterfaceDescription"),
                },
                "original": {key: original[key] for key in desired},
                "applied": desired,
                "restarted": restart,
            }
            manifest.setdefault("applied", {}).setdefault("system", []).append(record)
            atomic_write_json(manifest_path, manifest)
            description = adapter.get("InterfaceDescription") or adapter.get("Name")
            suffix = "; adapter restarted" if restart else "; takes effect after reconnect/restart"
            print(f"  + disabled supported NDIS idle/disconnect power controls on {description}{suffix}")
        else:
            print_command_failure(f"adapter power settings for {adapter.get('Name')}", result)
            record_apply_issue(
                manifest, manifest_path, "error", "windows",
                f"Adapter power settings failed for {adapter.get('Name')}: "
                f"{result.error or result.stderr.strip() or result.stdout.strip()}",
            )


def restore_windows_system(manifest: Dict[str, Any], restart: bool) -> List[Dict[str, Any]]:
    state = manifest.get("state", {}).get("system", {})
    applied = manifest.get("applied", {}).get("system", [])
    results: List[Dict[str, Any]] = []

    for item in applied:
        if item.get("type") != "windows_tcp_autotuning":
            continue
        original_level = str(item.get("original_level") or "").strip().lower()
        if original_level not in WINDOWS_TCP_AUTOTUNING_REPAIR_VALUES | {WINDOWS_TCP_AUTOTUNING_NORMAL}:
            continue
        command = windows_set_tcp_autotuning(original_level)
        record = {"type": "windows_tcp_autotuning", "ok": command.ok}
        if command.ok:
            print(f"  + restored Windows TCP receive-window auto-tuning: {original_level}")
        else:
            record["error"] = command.error or command.stderr.strip()
            print_command_failure("restore Windows TCP receive-window auto-tuning", command)
        results.append(record)

    if any(item.get("type") == "windows_wifi_power" for item in applied):
        power = state.get("power", {})
        if power.get("available"):
            commands = windows_set_power_value(
                str(power["scheme_guid"]),
                int(power["ac_value"]),
                int(power["dc_value"]),
            )
            ok = all(command.ok for command in commands)
            result_record = {"type": "windows_wifi_power", "ok": ok}
            if not ok:
                result_record["errors"] = [
                    command.error or command.stderr.strip() for command in commands if not command.ok
                ]
                for command in commands:
                    if not command.ok:
                        print_command_failure("restore Windows Wi-Fi power policy", command)
            else:
                print("  + restored Windows Wi-Fi power policy")
            results.append(result_record)

    for item in applied:
        if item.get("type") != "windows_adapter_power":
            continue
        adapter = item.get("adapter", {})
        original = {
            key: value
            for key, value in (item.get("original", {}) or {}).items()
            if key in {"SelectiveSuspend", "DeviceSleepOnDisconnect"} and _valid_pm_value(value)
        }
        command = windows_set_adapter_properties(adapter, original, restart)
        record = {"type": "windows_adapter_power", "adapter": adapter, "ok": command.ok}
        if command.ok:
            print(f"  + restored adapter power settings: {adapter.get('Name') or adapter.get('InterfaceDescription')}")
        else:
            record["error"] = command.error or command.stderr.strip()
            print_command_failure(f"restore adapter {adapter.get('Name')}", command)
        results.append(record)
    return results


# ---------------------------------------------------------------------------
# Windows extended tuning (MTU, ECN, Delivery Optimization, QoS, LSO, TCP retrans)
# ---------------------------------------------------------------------------

WINDOWS_DELIVERY_OPTIMIZATION_PATH = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
WINDOWS_QOS_PATH = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
WINDOWS_TCPIP_PARAMS_PATH = r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

DEFAULT_DNS_SERVERS = ("1.1.1.1", "1.0.0.1")


def _read_registry_dword(reg_path: str, value_name: str) -> Optional[int]:
    script = (
        f"$p={ps_single_quote(reg_path)};"
        f"$v={ps_single_quote(value_name)};"
        "try { $r=Get-ItemProperty -Path $p -Name $v -ErrorAction Stop; [int]$r.$v } catch { $null };"
    )
    result = run_powershell(script, timeout=10)
    if not result.ok or not result.stdout.strip():
        return None
    try:
        return int(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


def _set_registry_dword(reg_path: str, value_name: str, value: int) -> CommandResult:
    script = (
        f"$p={ps_single_quote(reg_path)};"
        f"$v={ps_single_quote(value_name)};"
        f"$d=$p -replace '^HKLM:\\\\','';"
        "try { "
        "  if (-not (Test-Path $p)) { "
        "    $parent=Split-Path $p -Parent; $leaf=Split-Path $p -Leaf; "
        "    New-Item -Path $parent -Name $leaf -Force -ErrorAction Stop | Out-Null "
        "  }; "
        f"  Set-ItemProperty -Path $p -Name $v -Value {value} -Type DWord -ErrorAction Stop; "
        "  $true "
        "} catch { $false };"
    )
    return run_powershell(script, timeout=10)


def windows_mtu_state() -> Dict[str, Any]:
    result = run_command(["netsh", "interface", "ipv4", "show", "subinterface"], timeout=10)
    if not result.ok:
        return {"available": False, "error": result.error or result.stderr.strip(), "interfaces": []}
    interfaces: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0].isdigit():
            mtu_val = int(parts[0])
            ifname = " ".join(parts[2:])
            if ifname and ifname not in ("Loopback", "Loopback Pseudo-Interface 1"):
                interfaces.append({"name": ifname, "mtu": mtu_val})
    return {"available": True, "interfaces": interfaces}


def windows_set_mtu(interface_name: str, mtu: int = 1500) -> CommandResult:
    return run_command(
        ["netsh", "interface", "ipv4", "set", "subinterface", interface_name, f"mtu={mtu}", "store=persistent"],
        timeout=10,
    )


def windows_ecn_state() -> Dict[str, Any]:
    result = run_powershell(
        "Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue "
        "| Select-Object EcnCapability | ConvertTo-Json -Compress",
        timeout=10,
    )
    if not result.ok or not result.stdout.strip():
        return {"available": False, "error": "Could not query ECN state"}
    try:
        parsed = json.loads(result.stdout.strip())
        ecn = parsed.get("EcnCapability") if isinstance(parsed, dict) else None
        return {"available": True, "ecn": str(ecn) if ecn is not None else None}
    except (json.JSONDecodeError, TypeError):
        return {"available": False, "error": "Could not parse ECN state"}


def windows_enable_ecn() -> CommandResult:
    return run_powershell(
        "Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Enabled -ErrorAction Stop; $true",
        timeout=10,
    )


def windows_restore_ecn() -> CommandResult:
    return run_powershell(
        "Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled -ErrorAction Stop; $true",
        timeout=10,
    )


def windows_delivery_optimization_state() -> Dict[str, Any]:
    value = _read_registry_dword(WINDOWS_DELIVERY_OPTIMIZATION_PATH, "DODownloadMode")
    return {"available": True if value is not None else False, "value": value}


def windows_disable_delivery_optimization() -> CommandResult:
    return _set_registry_dword(WINDOWS_DELIVERY_OPTIMIZATION_PATH, "DODownloadMode", 0)


def windows_restore_delivery_optimization(original_value: int) -> CommandResult:
    return _set_registry_dword(WINDOWS_DELIVERY_OPTIMIZATION_PATH, "DODownloadMode", original_value)


def windows_qos_state() -> Dict[str, Any]:
    value = _read_registry_dword(WINDOWS_QOS_PATH, "NonBestEffortLimit")
    return {"available": value is not None, "value": value}


def windows_set_qos_reserve(value: int = 0) -> CommandResult:
    return _set_registry_dword(WINDOWS_QOS_PATH, "NonBestEffortLimit", value)


def windows_lso_state() -> Dict[str, Any]:
    script = (
        "Get-NetAdapterLso -ErrorAction SilentlyContinue "
        "| Select-Object Name,IPv4Enabled,IPv6Enabled "
        "| ConvertTo-Json -Compress"
    )
    result = run_powershell(script, timeout=15)
    if not result.ok or not result.stdout.strip():
        return {"available": False, "adapters": []}
    try:
        parsed = json.loads(result.stdout.strip())
        if isinstance(parsed, dict):
            parsed = [parsed]
        adapters = [
            {
                "name": a.get("Name"),
                "ipv4_enabled": bool(a.get("IPv4Enabled")),
                "ipv6_enabled": bool(a.get("IPv6Enabled")),
            }
            for a in parsed if isinstance(a, dict)
        ]
        return {"available": True, "adapters": adapters}
    except (json.JSONDecodeError, TypeError):
        return {"available": False, "adapters": []}


def windows_disable_lso(adapter_name: str) -> CommandResult:
    return run_powershell(
        f"Disable-NetAdapterLso -Name {ps_single_quote(adapter_name)} -Confirm:$false -ErrorAction Stop; $true",
        timeout=15,
    )


def windows_enable_lso(adapter_name: str) -> CommandResult:
    return run_powershell(
        f"Enable-NetAdapterLso -Name {ps_single_quote(adapter_name)} -Confirm:$false -ErrorAction Stop; $true",
        timeout=15,
    )


def windows_tcp_retrans_state() -> Dict[str, Any]:
    data = _read_registry_dword(WINDOWS_TCPIP_PARAMS_PATH, "TcpMaxDataRetransmissions")
    connect = _read_registry_dword(WINDOWS_TCPIP_PARAMS_PATH, "TcpMaxConnectRetransmissions")
    return {
        "available": True,
        "TcpMaxDataRetransmissions": data,
        "TcpMaxConnectRetransmissions": connect,
    }


def windows_set_tcp_retransmissions(data: int = 5, connect: int = 3) -> List[CommandResult]:
    results: List[CommandResult] = []
    r1 = _set_registry_dword(WINDOWS_TCPIP_PARAMS_PATH, "TcpMaxDataRetransmissions", data)
    results.append(r1)
    r2 = _set_registry_dword(WINDOWS_TCPIP_PARAMS_PATH, "TcpMaxConnectRetransmissions", connect)
    results.append(r2)
    return results


def windows_reset_network_stack() -> List[CommandResult]:
    results: List[CommandResult] = []
    results.append(run_command(["netsh", "int", "ip", "reset", "reset.log"], timeout=30))
    results.append(run_command(["netsh", "winsock", "reset"], timeout=30))
    dns_reset = run_command(["ipconfig", "/flushdns"], timeout=10)
    if not dns_reset.ok:
        dns_reset = run_powershell("Clear-DnsClientCache -ErrorAction SilentlyContinue; $true", timeout=10)
    results.append(dns_reset)
    return results


def windows_parse_subinterface_output(output: str) -> List[Dict[str, Any]]:
    interfaces: List[Dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0].isdigit():
            mtu_val = int(parts[0])
            ifname = " ".join(parts[2:])
            if ifname and ifname not in ("Loopback", "Loopback Pseudo-Interface 1"):
                interfaces.append({"name": ifname, "mtu": mtu_val})
    return interfaces


# ---------------------------------------------------------------------------
# macOS tuning (DNS, TCP buffers, sysctl persistence, reset network config)
# ---------------------------------------------------------------------------


def macos_dns_state() -> Dict[str, Any]:
    result = run_command(["networksetup", "-getdnsservers", "Wi-Fi"], timeout=10)
    if not result.ok:
        result = run_command(["scutil", "--dns"], timeout=10)
        if result.ok:
            servers = re.findall(r"(?m)^\s+nameserver\s+\[[^\]]+\]\s*:\s*(\S+)", result.stdout)
            return {"available": True, "servers": servers[:4], "service": "Wi-Fi"}
        return {"available": False, "error": "Could not query DNS", "servers": []}
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith("There aren't any")]
    return {
        "available": True,
        "servers": [l for l in lines if l and not l.startswith("networksetup")],
        "service": "Wi-Fi",
    }


def macos_set_dns(servers: Optional[Tuple[str, ...]] = None) -> CommandResult:
    targets = list(servers or DEFAULT_DNS_SERVERS)
    # Try Wi-Fi first, fall back to any active service
    result = run_command(["networksetup", "-setdnsservers", "Wi-Fi"] + targets, timeout=10)
    if result.ok:
        return result
    # Fallback: detect active service
    detect = run_command(["networksetup", "-listallnetworkservices"], timeout=10)
    if detect.ok:
        for line in detect.stdout.splitlines():
            name = line.strip()
            if name and name != "An asterisk (*) denotes that a network service is disabled.":
                result = run_command(["networksetup", "-setdnsservers", name] + targets, timeout=10)
                if result.ok:
                    return result
    return result


def macos_clear_dns(service: str = "Wi-Fi") -> CommandResult:
    return run_command(["networksetup", "-setdnsservers", service, "Empty"], timeout=10)


def macos_tcp_buffer_state() -> Dict[str, Any]:
    result = run_command(["sysctl", "-n", "net.inet.tcp.sendspace"], timeout=5)
    sendspace = int(result.stdout.strip()) if result.ok and result.stdout.strip().isdigit() else None
    result = run_command(["sysctl", "-n", "net.inet.tcp.recvspace"], timeout=5)
    recvspace = int(result.stdout.strip()) if result.ok and result.stdout.strip().isdigit() else None
    return {"available": True, "sendspace": sendspace, "recvspace": recvspace}


def macos_set_tcp_buffers(sendspace: int = 131072, recvspace: int = 131072) -> List[CommandResult]:
    results: List[CommandResult] = []
    r1 = run_command(["sysctl", "-w", f"net.inet.tcp.sendspace={sendspace}"], timeout=5)
    results.append(r1)
    r2 = run_command(["sysctl", "-w", f"net.inet.tcp.recvspace={recvspace}"], timeout=5)
    results.append(r2)
    return results


def macos_sysctl_conf_path() -> Path:
    return Path("/etc/sysctl.conf")


def macos_write_sysctl_conf(sendspace: int = 131072, recvspace: int = 131072) -> CommandResult:
    content = (
        "# Net Stability - network buffer tuning\n"
        f"net.inet.tcp.sendspace={sendspace}\n"
        f"net.inet.tcp.recvspace={recvspace}\n"
    )
    try:
        path = macos_sysctl_conf_path()
        path.write_text(content, encoding="utf-8")
        return CommandResult(["write", str(path)], 0, "", "", 0.0)
    except OSError as exc:
        return CommandResult(["write", str(path)], 1, "", str(exc), 0.0)


def macos_reset_network_config() -> List[CommandResult]:
    results: List[CommandResult] = []
    config_dir = Path("/Library/Preferences/SystemConfiguration")
    if config_dir.is_dir():
        targets = [
            "com.apple.airport.preferences.plist",
            "com.apple.network.identification.plist",
            "NetworkInterfaces.plist",
            "preferences.plist",
        ]
        for name in targets:
            path = config_dir / name
            if path.is_file():
                backup = path.with_name(f"{name}.netstability-bak")
                try:
                    shutil.copy2(path, backup)
                    path.unlink()
                    results.append(CommandResult(["mv", str(path), str(backup)], 0, "", "", 0.0))
                except OSError as exc:
                    results.append(CommandResult(["mv", str(path), str(backup)], 1, "", str(exc), 0.0))
    route_result = run_command(["/usr/sbin/route", "-n", "flush"], timeout=10)
    results.append(route_result)
    dns_result = run_command(["dscacheutil", "-flushcache"], timeout=5)
    results.append(dns_result)
    mDNS_result = run_command(["killall", "-HUP", "mDNSResponder"], timeout=5)
    results.append(mDNS_result)
    return results


# ---------------------------------------------------------------------------
# Linux extended tuning (sysctl, BBR, ring buffers, IRQ balance, DNS)
# ---------------------------------------------------------------------------


LINUX_SYSCTL_CONF_PATH = Path("/etc/sysctl.d/99-net-optimizer.conf")

LINUX_SYSCTL_TUNING: Dict[str, str] = {
    "net.core.rmem_default": "262144",
    "net.core.wmem_default": "262144",
    "net.core.rmem_max": "4194304",
    "net.core.wmem_max": "4194304",
    "net.ipv4.tcp_rmem": "4096 87380 4194304",
    "net.ipv4.tcp_wmem": "4096 65536 4194304",
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_sack": "1",
    "net.ipv4.tcp_timestamps": "1",
    "net.ipv4.tcp_fastopen": "3",
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.core.default_qdisc": "fq_codel",
}


def linux_current_sysctl_values(keys: Sequence[str]) -> Dict[str, Optional[str]]:
    values: Dict[str, Optional[str]] = {}
    for key in keys:
        result = run_command(["sysctl", "-n", key], timeout=5)
        if result.ok and result.stdout.strip():
            values[key] = result.stdout.strip().splitlines()[0]
        else:
            values[key] = None
    return values


def linux_write_sysctl_conf(values: Optional[Mapping[str, str]] = None) -> CommandResult:
    entries = dict(values or LINUX_SYSCTL_TUNING)
    content = "# Net Stability - network optimization tuning\n# Applied: " + utc_now_iso() + "\n"
    for key, value in entries.items():
        content += f"{key} = {value}\n"
    try:
        LINUX_SYSCTL_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
        old = b""
        if LINUX_SYSCTL_CONF_PATH.is_file():
            old = LINUX_SYSCTL_CONF_PATH.read_bytes()
        LINUX_SYSCTL_CONF_PATH.write_text(content, encoding="utf-8")
        return CommandResult(["write", str(LINUX_SYSCTL_CONF_PATH)], 0, "", "", 0.0)
    except OSError as exc:
        return CommandResult(["write", str(LINUX_SYSCTL_CONF_PATH)], 1, "", str(exc), 0.0)


def linux_apply_sysctl() -> CommandResult:
    return run_command(["sysctl", "-p", str(LINUX_SYSCTL_CONF_PATH)], timeout=15)


def linux_restore_sysctl_conf(original: Mapping[str, Optional[str]]) -> CommandResult:
    entries = {k: v for k, v in original.items() if v is not None}
    if not entries:
        return CommandResult(["rm", str(LINUX_SYSCTL_CONF_PATH)], 0, "", "", 0.0)
    content = "# Net Stability - restored original values\n# Restored: " + utc_now_iso() + "\n"
    for key, value in entries.items():
        content += f"{key} = {value}\n"
    try:
        LINUX_SYSCTL_CONF_PATH.write_text(content, encoding="utf-8")
        return CommandResult(["write", str(LINUX_SYSCTL_CONF_PATH)], 0, "", "", 0.0)
    except OSError as exc:
        return CommandResult(["write", str(LINUX_SYSCTL_CONF_PATH)], 1, "", str(exc), 0.0)


def linux_nic_ring_buffer_state() -> Dict[str, Any]:
    ethtool = shutil.which("ethtool")
    if not ethtool:
        return {"available": False, "error": "ethtool not found", "interfaces": []}
    ip = shutil.which("ip") or "/sbin/ip"
    result = run_command([ip, "-brief", "link", "show"], timeout=10)
    if not result.ok:
        return {"available": False, "error": "Could not list interfaces", "interfaces": []}
    interfaces: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        ifname = parts[0]
        if ifname == "lo" or ":" in ifname:
            continue
        ring = run_command([ethtool, "-g", ifname], timeout=10)
        interfaces.append({"name": ifname, "ring": ring.stdout if ring.ok else None})
    return {"available": True, "ethtool": ethtool, "interfaces": interfaces}


def linux_set_nic_ring_buffer(interface: str, rx: int = 4096, tx: int = 4096) -> CommandResult:
    ethtool = shutil.which("ethtool")
    if not ethtool:
        return CommandResult(["ethtool"], 127, "", "", 0.0, "ethtool was not found")
    return run_command([ethtool, "-G", interface, "rx", str(rx), "tx", str(tx)], timeout=10)


def linux_irqbalance_state() -> Dict[str, Any]:
    result = run_command(["systemctl", "is-enabled", "irqbalance"], timeout=10)
    is_active = run_command(["systemctl", "is-active", "irqbalance"], timeout=10)
    return {
        "available": result.ok or is_active.ok,
        "enabled": result.stdout.strip() if result.ok else "unknown",
        "active": is_active.stdout.strip() if is_active.ok else "unknown",
    }


def linux_enable_irqbalance() -> CommandResult:
    return run_command(["systemctl", "enable", "--now", "irqbalance"], timeout=30)


def linux_disable_irqbalance() -> CommandResult:
    return run_command(["systemctl", "disable", "--now", "irqbalance"], timeout=30)


def linux_dns_state() -> Dict[str, Any]:
    resolv = Path("/etc/resolv.conf")
    if resolv.is_file():
        try:
            text = resolv.read_text(encoding="utf-8")
            servers = re.findall(r"(?m)^nameserver\s+(\S+)", text)
            return {"available": True, "servers": servers[:4], "path": str(resolv)}
        except OSError:
            pass
    result = run_command(["resolvectl", "dns"], timeout=10)
    if result.ok:
        return {"available": True, "resolvectl": result.stdout.strip(), "servers": []}
    return {"available": False, "servers": [], "error": "Could not query DNS"}


def linux_set_dns(servers: Optional[Tuple[str, ...]] = None) -> CommandResult:
    targets = list(servers or DEFAULT_DNS_SERVERS)
    resolvectl = shutil.which("resolvectl")
    if resolvectl:
        for server in targets:
            result = run_command([resolvectl, "dns", "global", server], timeout=10)
            if not result.ok:
                return run_command([resolvectl, "dns", server], timeout=10)
        return run_command([resolvectl, "dns", "global", targets[0]], timeout=10)
    resolv = Path("/etc/resolv.conf")
    try:
        content = "\n".join(f"nameserver {s}" for s in targets) + "\n"
        resolv.write_text(content, encoding="utf-8")
        return CommandResult(["write", str(resolv)], 0, "", "", 0.0)
    except OSError as exc:
        return CommandResult(["write", str(resolv)], 1, "", str(exc), 0.0)


def linux_reset_network() -> List[CommandResult]:
    results: List[CommandResult] = []
    if shutil.which("systemctl"):
        results.append(run_command(["systemctl", "restart", "NetworkManager"], timeout=30))
    if shutil.which("resolvectl"):
        results.append(run_command(["resolvectl", "flush-caches"], timeout=5))
    return results


# ---------------------------------------------------------------------------
# Linux NetworkManager state and tuning
# ---------------------------------------------------------------------------


def capture_linux_state() -> Dict[str, Any]:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return {"networkmanager": {"available": False, "error": "nmcli was not found"}}
    active = run_command(
        [nmcli, "-t", "-f", "UUID,TYPE,DEVICE", "connection", "show", "--active"],
        timeout=15,
    )
    if not active.ok:
        return {
            "networkmanager": {
                "available": False,
                "error": active.error or active.stderr.strip() or active.stdout.strip(),
            }
        }

    connections: List[Dict[str, Any]] = []
    for line in active.stdout.splitlines():
        fields = line.strip().split(":", 2)
        if len(fields) != 3:
            continue
        uuid, connection_type, device = fields
        if connection_type not in {"802-11-wireless", "wifi", "wireless"}:
            continue
        name_result = run_command([nmcli, "-g", "connection.id", "connection", "show", "uuid", uuid], timeout=10)
        power_result = run_command(
            [nmcli, "-g", "802-11-wireless.powersave", "connection", "show", "uuid", uuid],
            timeout=10,
        )
        name = name_result.stdout.strip().splitlines()[0] if name_result.ok and name_result.stdout.strip() else uuid
        powersave = power_result.stdout.strip().splitlines()[0] if power_result.ok and power_result.stdout.strip() else ""
        connections.append(
            {
                "uuid": uuid,
                "name": name,
                "device": device,
                "powersave": powersave,
            }
        )
    return {"networkmanager": {"available": True, "nmcli": nmcli, "connections": connections}}


def apply_linux_system(
    manifest: Dict[str, Any],
    manifest_path: Path,
    *,
    restart: bool,
) -> None:
    nm_state = manifest.get("state", {}).get("system", {}).get("networkmanager", {})
    if not nm_state.get("available"):
        message = f"Linux Wi-Fi power setting skipped: {nm_state.get('error', 'NetworkManager unavailable')}"
        print(f"  - {message}")
        record_apply_issue(manifest, manifest_path, "error", "linux", message)
        return
    nmcli = str(nm_state.get("nmcli") or shutil.which("nmcli") or "nmcli")
    connections = nm_state.get("connections", [])
    if not connections:
        message = "No active NetworkManager Wi-Fi profile found"
        print(f"  - {message.lower()}")
        record_apply_issue(manifest, manifest_path, "warning", "linux", message)
        return

    for connection in connections:
        if str(connection.get("powersave", "")).strip() == "2":
            continue
        uuid = str(connection["uuid"])
        result = run_command(
            [nmcli, "connection", "modify", "uuid", uuid, "802-11-wireless.powersave", "2"],
            timeout=20,
        )
        if not result.ok:
            print_command_failure(f"NetworkManager profile {connection.get('name')}", result)
            record_apply_issue(
                manifest, manifest_path, "error", "linux",
                f"Failed to modify NetworkManager profile {connection.get('name')}: "
                f"{result.error or result.stderr.strip() or result.stdout.strip()}",
            )
            continue

        reapplied = None
        if restart and connection.get("device"):
            reapply = run_command([nmcli, "device", "reapply", str(connection["device"])], timeout=20)
            if reapply.ok:
                reapplied = "reapply"
            else:
                reconnect = run_command(
                    [nmcli, "connection", "up", "uuid", uuid, "ifname", str(connection["device"])],
                    timeout=45,
                )
                if reconnect.ok:
                    reapplied = "reconnect"
                else:
                    reapplied = "pending_reconnect"
                    print_command_failure("NetworkManager reapply", reapply)
                    print_command_failure("NetworkManager reconnect", reconnect)
                    record_apply_issue(
                        manifest, manifest_path, "warning", "linux",
                        f"Profile {connection.get('name')} was changed but could not be reactivated automatically",
                    )

        record = {
            "type": "linux_nm_powersave",
            "connection": connection,
            "applied": "2",
            "activation": reapplied,
        }
        manifest.setdefault("applied", {}).setdefault("system", []).append(record)
        atomic_write_json(manifest_path, manifest)
        suffix = "" if restart else " (takes effect after reconnect)"
        print(f"  + disabled NetworkManager Wi-Fi powersave for {connection.get('name')}{suffix}")


def restore_linux_system(manifest: Dict[str, Any], restart: bool) -> List[Dict[str, Any]]:
    nm_state = manifest.get("state", {}).get("system", {}).get("networkmanager", {})
    nmcli = str(nm_state.get("nmcli") or shutil.which("nmcli") or "nmcli")
    results: List[Dict[str, Any]] = []
    for item in manifest.get("applied", {}).get("system", []):
        if item.get("type") != "linux_nm_powersave":
            continue
        connection = item.get("connection", {})
        uuid = str(connection.get("uuid") or "")
        original = str(connection.get("powersave") or "")
        value = original if original in {"0", "1", "2", "3"} else ""
        command = run_command(
            [nmcli, "connection", "modify", "uuid", uuid, "802-11-wireless.powersave", value],
            timeout=20,
        )
        record: Dict[str, Any] = {"type": "linux_nm_powersave", "uuid": uuid, "ok": command.ok}
        if not command.ok:
            record["error"] = command.error or command.stderr.strip()
            print_command_failure(f"restore NetworkManager profile {connection.get('name')}", command)
            results.append(record)
            continue

        if restart and connection.get("device"):
            reapply = run_command([nmcli, "device", "reapply", str(connection["device"])], timeout=20)
            if not reapply.ok:
                reconnect = run_command(
                    [nmcli, "connection", "up", "uuid", uuid, "ifname", str(connection["device"])],
                    timeout=45,
                )
                record["activation_ok"] = reconnect.ok
            else:
                record["activation_ok"] = True
        print(f"  + restored NetworkManager Wi-Fi powersave for {connection.get('name')}")
        results.append(record)
    return results


# ---------------------------------------------------------------------------
# Cross-platform snapshots/apply/restore
# ---------------------------------------------------------------------------


def capture_system_state() -> Dict[str, Any]:
    system = platform.system()
    state: Dict[str, Any] = {}
    if system == "Windows":
        state = capture_windows_state()
        state["mtu"] = windows_mtu_state()
        state["ecn"] = windows_ecn_state()
        state["delivery_optimization"] = windows_delivery_optimization_state()
        state["qos"] = windows_qos_state()
        state["lso"] = windows_lso_state()
        state["tcp_retrans"] = windows_tcp_retrans_state()
    elif system == "Linux":
        state = capture_linux_state()
        state["sysctl_current"] = linux_current_sysctl_values(list(LINUX_SYSCTL_TUNING.keys()))
        state["ring_buffers"] = linux_nic_ring_buffer_state()
        state["irqbalance"] = linux_irqbalance_state()
        state["dns"] = linux_dns_state()
    elif system == "Darwin":
        state = {
            "supported_changes": ["dns", "tcp_buffers"],
            "note": "macOS: DNS and TCP buffer tuning available.",
        }
        state["dns"] = macos_dns_state()
        state["tcp_buffers"] = macos_tcp_buffer_state()
    else:
        return {"supported_changes": [], "note": f"No system tuning implemented for {system}."}
    return state


# ---------------------------------------------------------------------------
# Extended OS tuning: apply and restore
# ---------------------------------------------------------------------------


def _record_applied(manifest: Dict[str, Any], manifest_path: Path, record: Dict[str, Any]) -> None:
    manifest.setdefault("applied", {}).setdefault("system", []).append(record)
    atomic_write_json(manifest_path, manifest)


def apply_windows_extended_tuning(
    manifest: Dict[str, Any],
    manifest_path: Path,
) -> None:
    state = manifest.get("state", {}).get("system", {})
    """Apply MTU=1500 on Wi-Fi interfaces."""
    mtu_state = state.get("mtu", {})
    if mtu_state.get("available"):
        wifi_interfaces = [i for i in mtu_state.get("interfaces", []) if i.get("mtu", 0) != 1500]
        for iface in wifi_interfaces:
            name = iface.get("name", "")
            if not name or "Loopback" in name:
                continue
            result = windows_set_mtu(name, 1500)
            if result.ok:
                print(f"  + MTU set to 1500 on {name}")
                _record_applied(manifest, manifest_path, {
                    "type": "mtu", "scope": "windows", "interface": name,
                    "original_mtu": iface.get("mtu"), "applied": 1500,
                })
            else:
                print_command_failure(f"MTU set on {name}", result)

    """Enable ECN."""
    ecn_state = state.get("ecn", {})
    if ecn_state.get("available") and str(ecn_state.get("ecn") or "").lower() != "enabled":
        result = windows_enable_ecn()
        if result.ok:
            print("  + ECN enabled")
            _record_applied(manifest, manifest_path, {
                "type": "ecn", "scope": "windows", "applied": "Enabled",
            })
        else:
            print_command_failure("ECN enable", result)

    """Disable Delivery Optimization P2P."""
    do_state = state.get("delivery_optimization", {})
    if do_state.get("available") and do_state.get("value") != 0:
        result = windows_disable_delivery_optimization()
        if result.ok:
            print("  + Delivery Optimization P2P disabled")
            _record_applied(manifest, manifest_path, {
                "type": "delivery_optimization", "scope": "windows",
                "original_value": do_state.get("value"), "applied": 0,
            })
        else:
            print_command_failure("Delivery Optimization disable", result)

    """Set QoS reservable bandwidth to 0%."""
    qos_state = state.get("qos", {})
    if qos_state.get("available") and qos_state.get("value") != 0:
        result = windows_set_qos_reserve(0)
        if result.ok:
            print("  + QoS reservable bandwidth set to 0%")
            _record_applied(manifest, manifest_path, {
                "type": "qos", "scope": "windows",
                "original_value": qos_state.get("value"), "applied": 0,
            })
        else:
            print_command_failure("QoS reservable bandwidth", result)

    """Disable LSO on Wi-Fi adapters where it's enabled."""
    lso_state = state.get("lso", {})
    if lso_state.get("available"):
        for adapter in lso_state.get("adapters", []):
            name = adapter.get("name", "")
            if not name:
                continue
            if adapter.get("ipv4_enabled") or adapter.get("ipv6_enabled"):
                result = windows_disable_lso(name)
                if result.ok:
                    print(f"  + LSO disabled on {name}")
                    _record_applied(manifest, manifest_path, {
                        "type": "lso", "scope": "windows", "adapter": name,
                        "original_ipv4": adapter.get("ipv4_enabled"),
                        "original_ipv6": adapter.get("ipv6_enabled"),
                        "applied": "disabled",
                    })
                else:
                    print_command_failure(f"LSO disable on {name}", result)

    """Set TCP retransmission registry values."""
    retrans_state = state.get("tcp_retrans", {})
    if retrans_state.get("available"):
        orig_data = retrans_state.get("TcpMaxDataRetransmissions")
        orig_connect = retrans_state.get("TcpMaxConnectRetransmissions")
        needs_data = orig_data is None or orig_data != 5
        needs_connect = orig_connect is None or orig_connect != 3
        if needs_data or needs_connect:
            results = windows_set_tcp_retransmissions(5, 3)
            ok = all(r.ok for r in results)
            if ok:
                print("  + TCP retransmission settings: data=5, connect=3")
                _record_applied(manifest, manifest_path, {
                    "type": "tcp_retrans", "scope": "windows",
                    "original_data": orig_data, "original_connect": orig_connect,
                    "applied_data": 5, "applied_connect": 3,
                })
            else:
                for i, r in enumerate(results):
                    if not r.ok:
                        label = "TcpMaxDataRetransmissions" if i == 0 else "TcpMaxConnectRetransmissions"
                        print_command_failure(label, r)


def restore_windows_extended_tuning(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    applied = manifest.get("applied", {}).get("system", [])
    results: List[Dict[str, Any]] = []
    for item in applied:
        if item.get("type") == "mtu":
            name = item.get("interface", "")
            orig = item.get("original_mtu")
            if name and orig:
                r = windows_set_mtu(name, orig)
                results.append({"type": "mtu", "ok": r.ok})
                if r.ok:
                    print(f"  + restored MTU on {name} to {orig}")
                else:
                    print_command_failure(f"restore MTU on {name}", r)

        elif item.get("type") == "ecn":
            r = windows_restore_ecn()
            results.append({"type": "ecn", "ok": r.ok})
            if r.ok:
                print("  + restored ECN to disabled")
            else:
                print_command_failure("restore ECN", r)

        elif item.get("type") == "delivery_optimization":
            orig = item.get("original_value")
            if orig is not None:
                r = windows_restore_delivery_optimization(orig)
                results.append({"type": "delivery_optimization", "ok": r.ok})
                if r.ok:
                    print(f"  + restored Delivery Optimization to {orig}")
                else:
                    print_command_failure("restore Delivery Optimization", r)

        elif item.get("type") == "qos":
            orig = item.get("original_value")
            if orig is not None:
                r = windows_set_qos_reserve(orig)
                results.append({"type": "qos", "ok": r.ok})
                if r.ok:
                    print(f"  + restored QoS reservable bandwidth to {orig}")
                else:
                    print_command_failure("restore QoS", r)

        elif item.get("type") == "lso":
            name = item.get("adapter", "")
            if name:
                orig_ipv4 = item.get("original_ipv4", False)
                if orig_ipv4:
                    r = windows_enable_lso(name)
                    results.append({"type": "lso", "ok": r.ok, "adapter": name})
                    if r.ok:
                        print(f"  + restored LSO on {name}")
                    else:
                        print_command_failure(f"restore LSO on {name}", r)

        elif item.get("type") == "tcp_retrans":
            orig_data = item.get("original_data")
            orig_connect = item.get("original_connect")
            if orig_data is not None or orig_connect is not None:
                d = orig_data if orig_data is not None else 5
                c = orig_connect if orig_connect is not None else 3
                rs = windows_set_tcp_retransmissions(d, c)
                ok = all(r.ok for r in rs)
                results.append({"type": "tcp_retrans", "ok": ok})
                if ok:
                    print(f"  + restored TCP retransmissions: data={d}, connect={c}")
                else:
                    for i, r in enumerate(rs):
                        if not r.ok:
                            print_command_failure(f"restore TCP retrans ({i})", r)

    return results


def apply_linux_extended_tuning(
    manifest: Dict[str, Any],
    manifest_path: Path,
) -> None:
    state = manifest.get("state", {}).get("system", {})
    """Write sysctl tuning file and apply."""
    current = state.get("sysctl_current", {})
    needs_write = False
    for key, desired in LINUX_SYSCTL_TUNING.items():
        existing = current.get(key)
        if existing != desired:
            needs_write = True
            break
    if needs_write:
        r = linux_write_sysctl_conf()
        if r.ok:
            print("  + wrote sysctl tuning: /etc/sysctl.d/99-net-optimizer.conf")
            _record_applied(manifest, manifest_path, {
                "type": "sysctl_conf", "scope": "linux",
                "original": dict(current),
                "applied": dict(LINUX_SYSCTL_TUNING),
            })
            apply_r = linux_apply_sysctl()
            if apply_r.ok:
                print("  + applied sysctl settings")
            else:
                print_command_failure("sysctl -p", apply_r)
        else:
            print_command_failure("write sysctl conf", r)
    else:
        print("  - sysctl tuning already at target values")

    """Set NIC ring buffers."""
    ring_state = state.get("ring_buffers", {})
    if ring_state.get("available"):
        for iface in ring_state.get("interfaces", []):
            name = iface.get("name", "")
            if name:
                r = linux_set_nic_ring_buffer(name, 4096, 4096)
                if r.ok:
                    print(f"  + ring buffer: {name} rx=4096 tx=4096")
                    _record_applied(manifest, manifest_path, {
                        "type": "ring_buffer", "scope": "linux",
                        "interface": name, "applied_rx": 4096, "applied_tx": 4096,
                    })
                else:
                    print_command_failure(f"ring buffer on {name}", r)

    """Enable IRQ balance."""
    irq_state = state.get("irqbalance", {})
    if irq_state.get("available") and irq_state.get("active") != "active":
        r = linux_enable_irqbalance()
        if r.ok:
            print("  + irqbalance enabled and started")
            _record_applied(manifest, manifest_path, {
                "type": "irqbalance", "scope": "linux",
                "original_enabled": irq_state.get("enabled"),
                "original_active": irq_state.get("active"),
            })
        else:
            print_command_failure("irqbalance enable", r)

    """Set DNS to 1.1.1.1."""
    dns_state = state.get("dns", {})
    if dns_state.get("available"):
        current_servers = dns_state.get("servers", [])
        if "1.1.1.1" not in current_servers:
            r = linux_set_dns()
            if r.ok:
                print("  + DNS set to 1.1.1.1, 1.0.0.1")
                _record_applied(manifest, manifest_path, {
                    "type": "dns", "scope": "linux",
                    "original_servers": current_servers,
                    "applied": list(DEFAULT_DNS_SERVERS),
                })
            else:
                print_command_failure("DNS set", r)


def restore_linux_extended_tuning(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    applied = manifest.get("applied", {}).get("system", [])
    results: List[Dict[str, Any]] = []
    for item in applied:
        if item.get("type") == "sysctl_conf":
            original = item.get("original", {})
            r = linux_restore_sysctl_conf(original)
            results.append({"type": "sysctl_conf", "ok": r.ok})
            if r.ok:
                print("  + restored sysctl configuration")
                linux_apply_sysctl()
            else:
                print_command_failure("restore sysctl conf", r)

        elif item.get("type") == "irqbalance":
            was_active = item.get("original_active")
            if was_active != "active":
                r = linux_disable_irqbalance()
                results.append({"type": "irqbalance", "ok": r.ok})
                if r.ok:
                    print("  + restored irqbalance state")
                else:
                    print_command_failure("restore irqbalance", r)

        elif item.get("type") == "dns":
            original = item.get("original_servers", [])
            if original:
                r = linux_set_dns(tuple(original))
            else:
                r = linux_set_dns(("Empty",))
            results.append({"type": "dns", "ok": r.ok})
            if r.ok:
                print("  + restored DNS servers")
            else:
                print_command_failure("restore DNS", r)

    return results


def apply_macos_extended_tuning(
    manifest: Dict[str, Any],
    manifest_path: Path,
) -> None:
    state = manifest.get("state", {}).get("system", {})
    """Set DNS to 1.1.1.1."""
    dns_state = state.get("dns", {})
    if dns_state.get("available"):
        servers = dns_state.get("servers", [])
        if "1.1.1.1" not in servers:
            r = macos_set_dns()
            if r.ok:
                print("  + DNS set to 1.1.1.1, 1.0.0.1")
                _record_applied(manifest, manifest_path, {
                    "type": "dns", "scope": "macos",
                    "original_servers": servers,
                    "applied": list(DEFAULT_DNS_SERVERS),
                })
            else:
                print_command_failure("macOS DNS set", r)

    """Set TCP buffers."""
    buf_state = state.get("tcp_buffers", {})
    if buf_state.get("available"):
        send = buf_state.get("sendspace")
        recv = buf_state.get("recvspace")
        if send != 131072 or recv != 131072:
            rs = macos_set_tcp_buffers(131072, 131072)
            ok = all(r.ok for r in rs)
            if ok:
                print("  + TCP buffers: send=131072 recv=131072")
                _record_applied(manifest, manifest_path, {
                    "type": "tcp_buffers", "scope": "macos",
                    "original_send": send, "original_recv": recv,
                    "applied_send": 131072, "applied_recv": 131072,
                })
                conf_r = macos_write_sysctl_conf(131072, 131072)
                if conf_r.ok:
                    print("  + wrote persistent sysctl.conf")
                else:
                    print_command_failure("write sysctl.conf", conf_r)
            else:
                for i, r in enumerate(rs):
                    if not r.ok:
                        label = "sendspace" if i == 0 else "recvspace"
                        print_command_failure(f"TCP buffer {label}", r)


def restore_macos_extended_tuning(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    applied = manifest.get("applied", {}).get("system", [])
    results: List[Dict[str, Any]] = []
    for item in applied:
        if item.get("type") == "dns":
            original = item.get("original_servers", [])
            if original:
                r = macos_set_dns(tuple(original))
            else:
                r = macos_clear_dns()
            results.append({"type": "dns", "ok": r.ok})
            if r.ok:
                print("  + restored DNS servers on macOS")
            else:
                print_command_failure("restore macOS DNS", r)

        elif item.get("type") == "tcp_buffers":
            orig_send = item.get("original_send") or 131072
            orig_recv = item.get("original_recv") or 131072
            rs = macos_set_tcp_buffers(orig_send, orig_recv)
            ok = all(r.ok for r in rs)
            results.append({"type": "tcp_buffers", "ok": ok})
            if ok:
                print(f"  + restored TCP buffers: send={orig_send} recv={orig_recv}")
            else:
                for i, r in enumerate(rs):
                    if not r.ok:
                        print_command_failure(f"restore TCP buffer ({i})", r)

    return results


def apply_system_state(
    manifest: Dict[str, Any],
    manifest_path: Path,
    *,
    include_battery: bool,
    restart: bool,
) -> None:
    system = platform.system()
    if system == "Windows":
        apply_windows_system(
            manifest,
            manifest_path,
            include_battery=include_battery,
            restart=restart,
        )
        apply_windows_extended_tuning(manifest, manifest_path)
    elif system == "Linux":
        apply_linux_system(manifest, manifest_path, restart=restart)
        apply_linux_extended_tuning(manifest, manifest_path)
    elif system == "Darwin":
        apply_macos_extended_tuning(manifest, manifest_path)
    else:
        print(f"  - {system}: no system tuning is implemented")


def restore_system_state(manifest: Dict[str, Any], restart: bool) -> List[Dict[str, Any]]:
    system = str(manifest.get("platform", {}).get("system") or platform.system())
    if system != platform.system():
        raise NetStabilityError(
            f"Snapshot was created on {system}, but this machine is {platform.system()}; system restore refused"
        )
    results: List[Dict[str, Any]] = []
    if system == "Windows":
        results.extend(restore_windows_system(manifest, restart))
        results.extend(restore_windows_extended_tuning(manifest))
    elif system == "Linux":
        results.extend(restore_linux_system(manifest, restart))
        results.extend(restore_linux_extended_tuning(manifest))
    elif system == "Darwin":
        results.extend(restore_macos_extended_tuning(manifest))
    return results


def platform_metadata() -> Dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "hostname": socket.gethostname(),
    }


def planned_changes(do_system: bool, do_npm: bool, include_battery: bool, maxsockets: int) -> List[str]:
    changes: List[str] = []
    system = platform.system()
    if do_system:
        if system == "Windows":
            changes.append("Restore Windows TCP receive-window auto-tuning to normal when restricted or disabled")
            changes.append("Set the active plan's Wi-Fi policy to Maximum Performance on AC" + (" and battery" if include_battery else ""))
            changes.append("Disable supported NDIS SelectiveSuspend and DeviceSleepOnDisconnect on physical Wi-Fi adapters")
            changes.append("Set MTU to 1500 on Wi-Fi interfaces")
            changes.append("Enable ECN (Explicit Congestion Notification)")
            changes.append("Disable Windows Delivery Optimization (P2P update sharing)")
            changes.append("Set QoS reservable bandwidth to 0%")
            changes.append("Disable Large Send Offload on Wi-Fi adapters")
            changes.append("Set TCP retransmission registry values (data=5, connect=3)")
        elif system == "Linux":
            changes.append("Set active NetworkManager Wi-Fi profiles to powersave=2 (disabled)")
            changes.append("Write sysctl TCP/IP tuning (buffers, SACK, window scaling, timestamps, fastopen)")
            changes.append("Enable BBR congestion control and fq_codel qdisc")
            changes.append("Set NIC ring buffers to 4096 (rx/tx)")
            changes.append("Enable and start irqbalance daemon")
            changes.append("Set DNS to 1.1.1.1 / 1.0.0.1")
        elif system == "Darwin":
            changes.append("Set DNS to 1.1.1.1 / 1.0.0.1")
            changes.append("Set TCP buffer sizes (send=131072, recv=131072)")
        else:
            changes.append(f"No system setting for {system}")
    if do_npm:
        changes.append(f"Apply weak-link npm profile (maxsockets={maxsockets}, retries, longer timeout, prefer-offline)")
    return changes


def validate_apply_context(do_system: bool, do_npm: bool) -> None:
    if platform.system() == "Windows" and do_system and not is_windows_admin():
        raise NetStabilityError(
            "Windows system tuning requires an Administrator terminal. Re-run as Administrator, "
            "or use --npm-only for the user-level npm profile."
        )
    if is_sudo_root() and do_npm:
        raise NetStabilityError(
            "Refusing to change npm configuration under sudo because that can target root's npm state. "
            "Run npm tuning as your normal user, and use a separate --system-only command under sudo."
        )


def create_snapshot(do_system: bool, do_npm: bool) -> Tuple[Path, Path, Dict[str, Any]]:
    identifier = snapshot_id()
    directory = ensure_private_dir(backups_root() / identifier)
    manifest_path = directory / "manifest.json"
    manifest: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": APP_DISPLAY_NAME, "version": VERSION},
        "snapshot_id": identifier,
        "created_utc": utc_now_iso(),
        "platform": platform_metadata(),
        "selection": {"system": do_system, "npm": do_npm},
        "state": {},
        "applied": {"system": [], "npm": []},
        "status": "capturing",
    }
    atomic_write_json(manifest_path, manifest)
    if do_system:
        manifest["state"]["system"] = capture_system_state()
        atomic_write_json(manifest_path, manifest)
    if do_npm:
        manifest["state"]["npm"] = capture_npm_state(directory)
        atomic_write_json(manifest_path, manifest)
    manifest["status"] = "captured"
    atomic_write_json(manifest_path, manifest)
    return directory, manifest_path, manifest


def command_reset_network(args: argparse.Namespace) -> int:
    system = platform.system()
    print(f"Network stack reset for {system}")
    print("  WARNING: This resets TCP/IP, Winsock, and DNS settings to OS defaults.")
    print("  A system reboot is recommended after this operation.")
    print()

    if not confirm("Reset the network stack?", args.yes):
        print("Cancelled.")
        return 1

    if system == "Windows":
        if not is_windows_admin():
            raise NetStabilityError("Windows network reset requires an Administrator terminal")
        results = windows_reset_network_stack()
        all_ok = all(r.ok for r in results)
        for i, r in enumerate(results):
            label = ["netsh int ip reset", "netsh winsock reset", "ipconfig /flushdns"][i]
            if r.ok:
                print(f"  + {label}")
            else:
                print_command_failure(label, r)
        if all_ok:
            print("  + Network stack reset completed. Reboot is recommended.")
            print('  + Run: "shutdown /r /t 0" to reboot now.')
        else:
            print("  ! Some reset commands failed. A reboot may still be required.")
        return 0 if all_ok else 2

    elif system == "Darwin":
        if os.geteuid() != 0:
            print("  - Some reset steps require root. Run with sudo for full effect.")
        results = macos_reset_network_config()
        for i, r in enumerate(results):
            label = ["mv config plists", "route -n flush", "dscacheutil -flushcache", "killall mDNSResponder"][i]
            if r.ok:
                print(f"  + {label}")
            else:
                print_command_failure(label, r)
        print("  + macOS network config reset. Reboot is recommended.")
        return 0

    elif system == "Linux":
        if os.geteuid() != 0:
            print("  - Some reset steps require root. Run with sudo for full effect.")
        results = linux_reset_network()
        for i, r in enumerate(results):
            label = ["systemctl restart NetworkManager", "resolvectl flush-caches"][i] if i < len(results) else "reset"
            if r.ok:
                print(f"  + {label}")
            else:
                print_command_failure(label, r)
        # Also try to restart networking
        for svc in ["networking", "systemd-networkd"]:
            r = run_command(["systemctl", "restart", svc], timeout=15)
            if r.ok:
                print(f"  + restarted {svc}")
                break
        print("  + Linux network stack reset.")
        return 0

    else:
        print(f"  - Network reset not implemented for {system}")
        return 1


def command_apply(args: argparse.Namespace) -> int:
    do_system = not args.npm_only
    do_npm = not args.system_only

    print("Planned changes:")
    for change in planned_changes(do_system, do_npm, args.include_battery, args.npm_maxsockets):
        print(f"  - {change}")
    if do_system and not args.no_restart and platform.system() in {"Windows", "Linux"}:
        print("  - The Wi-Fi adapter/connection may disconnect briefly while settings are activated")
    print("Paper-backed MTU, DNS, ECN, BBR, TCP auto-tuning, and selective offload changes ARE applied when supported.")

    if args.dry_run:
        print("Dry run complete; no snapshot or setting was written.")
        return 0
    validate_apply_context(do_system, do_npm)
    if not confirm("Create a backup and apply these changes?", args.yes):
        print("Cancelled.")
        return 1

    snapshot_dir, manifest_path, manifest = create_snapshot(do_system, do_npm)
    print(f"Backup created: {snapshot_dir}")
    manifest["status"] = "applying"
    atomic_write_json(manifest_path, manifest)

    try:
        if do_npm:
            apply_npm_profile(manifest, manifest_path, args.npm_maxsockets)
        if do_system:
            apply_system_state(
                manifest,
                manifest_path,
                include_battery=args.include_battery,
                restart=not args.no_restart,
            )
        issues = manifest.get("issues", [])
        has_errors = any(item.get("severity") == "error" for item in issues)
        has_warnings = any(item.get("severity") == "warning" for item in issues)
        manifest["status"] = (
            "applied_with_errors" if has_errors else "applied_with_warnings" if has_warnings else "applied"
        )
        manifest["completed_utc"] = utc_now_iso()
        atomic_write_json(manifest_path, manifest)
    except Exception:
        manifest["status"] = "apply_interrupted"
        manifest["interrupted_utc"] = utc_now_iso()
        atomic_write_json(manifest_path, manifest)
        raise

    print(f"Applied. Restore point: {manifest['snapshot_id']}")
    print(
        f'Restore command: "{sys.executable}" "{Path(sys.argv[0]).resolve()}" '
        f"restore {manifest['snapshot_id']}"
    )
    errors = [item for item in manifest.get("issues", []) if item.get("severity") == "error"]
    warnings = [item for item in manifest.get("issues", []) if item.get("severity") == "warning"]
    if errors or warnings:
        print(f"Apply issues: {len(errors)} error(s), {len(warnings)} warning(s). See the snapshot manifest.")
    return 2 if errors else 0


def snapshot_directories() -> List[Path]:
    root = backups_root()
    directories = [path for path in root.iterdir() if path.is_dir() and (path / "manifest.json").is_file()]
    return sorted(directories, key=lambda item: item.name, reverse=True)


def resolve_snapshot(identifier: str) -> Tuple[Path, Dict[str, Any]]:
    directories = snapshot_directories()
    if identifier == "latest":
        if not directories:
            raise NetStabilityError(f"No backups found under {backups_root()}")
        directory = directories[0]
    else:
        if Path(identifier).name != identifier or identifier in {".", ".."}:
            raise NetStabilityError("Invalid snapshot identifier")
        directory = backups_root() / identifier
        if not directory.is_dir():
            raise NetStabilityError(f"Snapshot not found: {identifier}")
    manifest = load_json(directory / "manifest.json")
    return directory, manifest


def manifest_has_system_changes(manifest: Mapping[str, Any]) -> bool:
    return bool(manifest.get("applied", {}).get("system", []))


def manifest_has_npm_state(manifest: Mapping[str, Any]) -> bool:
    return bool(manifest.get("selection", {}).get("npm")) and "npm" in manifest.get("state", {})


def validate_restore_context(manifest: Mapping[str, Any], do_system: bool, do_npm: bool) -> None:
    if platform.system() == "Windows" and do_system and manifest_has_system_changes(manifest) and not is_windows_admin():
        raise NetStabilityError(
            "Restoring Windows system settings requires an Administrator terminal. "
            "Use --npm-only to restore only npm without elevation."
        )
    if is_sudo_root() and do_npm and manifest_has_npm_state(manifest):
        raise NetStabilityError(
            "Refusing to restore npm configuration under sudo. Restore npm as the original user, "
            "and restore system settings separately with --system-only if needed."
        )


def command_restore(args: argparse.Namespace) -> int:
    snapshot_dir, manifest = resolve_snapshot(args.snapshot)
    do_system = not args.npm_only
    do_npm = not args.system_only
    validate_restore_context(manifest, do_system, do_npm)

    print(f"Snapshot: {manifest.get('snapshot_id')} ({manifest.get('created_utc')})")
    print(f"Source platform: {manifest.get('platform', {}).get('system')} {manifest.get('platform', {}).get('release')}")
    if do_npm and manifest_has_npm_state(manifest):
        print("  - Restore the exact pre-change npm user configuration")
    if do_system and manifest_has_system_changes(manifest):
        print("  - Restore the recorded pre-change OS/adapter settings")
    if not args.no_restart and do_system and manifest_has_system_changes(manifest):
        print("  - The Wi-Fi adapter/connection may disconnect briefly")

    if args.dry_run:
        print("Dry run complete; nothing was restored.")
        return 0
    if not confirm("Restore this snapshot?", args.yes):
        print("Cancelled.")
        return 1

    restore_record: Dict[str, Any] = {
        "started_utc": utc_now_iso(),
        "selection": {"system": do_system, "npm": do_npm},
        "results": {},
    }
    if do_npm and manifest_has_npm_state(manifest):
        restore_record["results"]["npm"] = restore_npm_state(manifest, snapshot_dir)
    if do_system and manifest_has_system_changes(manifest):
        restore_record["results"]["system"] = restore_system_state(manifest, restart=not args.no_restart)
    restore_record["completed_utc"] = utc_now_iso()
    manifest.setdefault("restore_history", []).append(restore_record)
    atomic_write_json(snapshot_dir / "manifest.json", manifest)

    failures = []
    npm_result = restore_record["results"].get("npm")
    if isinstance(npm_result, dict) and not npm_result.get("ok", True):
        failures.append("npm")
    for item in restore_record["results"].get("system", []) or []:
        if not item.get("ok", True):
            failures.append(str(item.get("type", "system")))
    if failures:
        print(f"Restore completed with failures: {', '.join(failures)}", file=sys.stderr)
        return 2
    print("Restore completed.")
    return 0


def command_list_backups(_args: argparse.Namespace) -> int:
    directories = snapshot_directories()
    if not directories:
        print(f"No backups found under {backups_root()}")
        return 0
    print(f"Backups in {backups_root()}:")
    for directory in directories:
        try:
            manifest = load_json(directory / "manifest.json")
            selection = manifest.get("selection", {})
            scopes = [name for name in ("system", "npm") if selection.get(name)]
            print(
                f"  {directory.name}  {manifest.get('created_utc', '?')}  "
                f"status={manifest.get('status', '?')}  scopes={','.join(scopes) or 'none'}"
            )
        except NetStabilityError as exc:
            print(f"  {directory.name}  invalid: {exc}")
    return 0


# ---------------------------------------------------------------------------
# Diagnostics and command-under-load monitoring
# ---------------------------------------------------------------------------


def default_gateway() -> Optional[str]:
    system = platform.system()
    if system == "Windows":
        script = (
            "$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
            "Where-Object {$_.NextHop -and $_.NextHop -ne '0.0.0.0'} | "
            "Sort-Object @{Expression={$_.RouteMetric+$_.InterfaceMetric}} | Select-Object -First 1;"
            "if($null -ne $r){[string]$r.NextHop}"
        )
        result = run_powershell(script, timeout=10)
        value = result.stdout.strip().splitlines()[-1] if result.ok and result.stdout.strip() else ""
        return value or None
    if system == "Linux":
        ip = shutil.which("ip")
        if ip:
            result = run_command([ip, "-json", "route", "show", "default"], timeout=10)
            if result.ok:
                try:
                    routes = json.loads(result.stdout)
                    for route in routes:
                        gateway = route.get("gateway")
                        if gateway:
                            return str(gateway)
                except (json.JSONDecodeError, TypeError):
                    pass
            result = run_command([ip, "route", "show", "default"], timeout=10)
            if result.ok:
                match = re.search(r"\bvia\s+(\S+)", result.stdout)
                if match:
                    return match.group(1)
    if system == "Darwin":
        route = shutil.which("route") or "/sbin/route"
        result = run_command([route, "-n", "get", "default"], timeout=10)
        if result.ok:
            match = re.search(r"(?m)^\s*gateway:\s*(\S+)", result.stdout)
            if match:
                return match.group(1)
    return None


def ping_once(host: str, timeout_seconds: float = 1.5) -> Dict[str, Any]:
    system = platform.system()
    timeout_ms = max(250, int(timeout_seconds * 1000))
    if system == "Windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    elif system == "Darwin":
        command = ["ping", "-n", "-c", "1", "-W", str(timeout_ms), host]
    else:
        command = ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout_seconds))), host]

    result = run_command(command, timeout=timeout_seconds + 1.5)
    if result.error and "command not found" in result.error:
        return {"available": False, "success": False, "host": host, "error": result.error}
    latency: Optional[float] = None
    match = PING_TIME_RE.search(result.stdout)
    if match:
        latency = float(match.group(1).replace(",", "."))
    elif PING_LT_ONE_RE.search(result.stdout):
        latency = 0.5
    elif result.ok:
        # Localized output may not expose a parsable label. Wall time is a safe
        # upper-bound approximation for a single ping process.
        latency = result.duration_ms
    error = None
    if not result.ok:
        error = result.error or result.stderr.strip() or "no ICMP reply"
    return {
        "available": True,
        "success": result.ok,
        "host": host,
        "latency_ms": round(latency, 3) if latency is not None else None,
        "error": error,
    }


def call_with_timeout(function: Callable[[], Dict[str, Any]], timeout: float) -> Dict[str, Any]:
    output: "queue.Queue[Tuple[bool, Any]]" = queue.Queue(maxsize=1)

    def runner() -> None:
        try:
            output.put((True, function()))
        except Exception as exc:  # probe boundary; returned as diagnostic data
            with contextlib.suppress(queue.Full):
                output.put((False, exc))

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return {"success": False, "error": f"probe timed out after {timeout:g}s"}
    try:
        ok, value = output.get_nowait()
    except queue.Empty:
        return {"success": False, "error": "probe produced no result"}
    if ok:
        return value
    return {"success": False, "error": str(value)}


def dns_probe(host: str, timeout: float = 4.0) -> Dict[str, Any]:
    def action() -> Dict[str, Any]:
        start = time.perf_counter()
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        duration = (time.perf_counter() - start) * 1000.0
        addresses = sorted({str(record[4][0]) for record in records})
        return {
            "success": bool(addresses),
            "latency_ms": round(duration, 3),
            "addresses": addresses[:8],
            "error": None,
        }

    result = call_with_timeout(action, timeout)
    result["host"] = host
    return result


def https_probe(host: str, timeout: float = 5.0) -> Dict[str, Any]:
    def action() -> Dict[str, Any]:
        start = time.perf_counter()
        connection = http.client.HTTPSConnection(
            host,
            443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        try:
            connection.request(
                "GET",
                "/-/ping",
                headers={"User-Agent": f"NetStability/{VERSION}", "Accept": "application/json,text/plain"},
            )
            response = connection.getresponse()
            response.read(4096)
            duration = (time.perf_counter() - start) * 1000.0
            success = 200 <= response.status < 400
            return {
                "success": success,
                "latency_ms": round(duration, 3),
                "status": response.status,
                "error": None if success else f"HTTP {response.status}",
            }
        finally:
            connection.close()

    result = call_with_timeout(action, timeout + 0.5)
    result["host"] = host
    return result


def collect_sample(
    gateway: Optional[str],
    public_target: str,
    registry_host: str,
    include_service: bool,
    phase: str,
) -> Dict[str, Any]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        gateway_future = executor.submit(ping_once, gateway, 1.5) if gateway else None
        public_future = executor.submit(ping_once, public_target, 1.5)
        gateway_result = gateway_future.result() if gateway_future else None
        public_result = public_future.result()

    sample: Dict[str, Any] = {
        "timestamp_utc": utc_now_iso(),
        "phase": phase,
        "gateway_ping": gateway_result,
        "public_ping": public_result,
        "dns": None,
        "registry_https": None,
    }
    if include_service:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            dns_future = executor.submit(dns_probe, registry_host)
            https_future = executor.submit(https_probe, registry_host)
            sample["dns"] = dns_future.result()
            sample["registry_https"] = https_future.result()
    return sample


def collect_samples(
    count: int,
    interval: float,
    gateway: Optional[str],
    public_target: str,
    registry_host: str,
    phase: str,
    *,
    progress: bool = True,
) -> List[Dict[str, Any]]:
    samples: List[Dict[str, Any]] = []
    service_every = max(1, int(round(5.0 / max(interval, 0.1))))
    next_tick = time.monotonic()
    for index in range(count):
        if progress:
            print(f"\r{phase}: sample {index + 1}/{count}", end="", flush=True)
        sample = collect_sample(
            gateway,
            public_target,
            registry_host,
            include_service=(index % service_every == 0 or index == count - 1),
            phase=phase,
        )
        samples.append(sample)
        next_tick += interval
        sleep_for = next_tick - time.monotonic()
        if sleep_for > 0 and index != count - 1:
            time.sleep(sleep_for)
    if progress:
        print()
    return samples


def percentile(values: Sequence[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def ping_summary(samples: Sequence[Mapping[str, Any]], key: str) -> Dict[str, Any]:
    records = [sample.get(key) for sample in samples if sample.get(key) is not None]
    available = [record for record in records if isinstance(record, dict) and record.get("available", True)]
    successes = [record for record in available if record.get("success")]
    latencies = [float(record["latency_ms"]) for record in successes if record.get("latency_ms") is not None]
    if not available:
        return {"available": False, "attempts": 0}
    return {
        "available": True,
        "attempts": len(available),
        "successes": len(successes),
        "loss_percent": round(100.0 * (len(available) - len(successes)) / len(available), 2),
        "median_ms": round(statistics.median(latencies), 3) if latencies else None,
        "p95_ms": round(percentile(latencies, 0.95), 3) if latencies else None,
        "min_ms": round(min(latencies), 3) if latencies else None,
        "max_ms": round(max(latencies), 3) if latencies else None,
    }


def service_summary(samples: Sequence[Mapping[str, Any]], key: str) -> Dict[str, Any]:
    records = [sample.get(key) for sample in samples if isinstance(sample.get(key), dict)]
    if not records:
        return {"available": False, "attempts": 0}
    successes = [record for record in records if record.get("success")]
    latencies = [float(record["latency_ms"]) for record in successes if record.get("latency_ms") is not None]
    return {
        "available": True,
        "attempts": len(records),
        "successes": len(successes),
        "failure_percent": round(100.0 * (len(records) - len(successes)) / len(records), 2),
        "median_ms": round(statistics.median(latencies), 3) if latencies else None,
        "p95_ms": round(percentile(latencies, 0.95), 3) if latencies else None,
    }


def summarize_samples(samples: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    return {
        "gateway_ping": ping_summary(samples, "gateway_ping"),
        "public_ping": ping_summary(samples, "public_ping"),
        "dns": service_summary(samples, "dns"),
        "registry_https": service_summary(samples, "registry_https"),
    }


def format_metric(summary: Mapping[str, Any], failure_key: str = "loss_percent") -> str:
    if not summary.get("available"):
        return "unavailable"
    failure = summary.get(failure_key)
    median = summary.get("median_ms")
    p95 = summary.get("p95_ms")
    parts = []
    if failure is not None:
        label = "loss" if failure_key == "loss_percent" else "failures"
        parts.append(f"{failure:g}% {label}")
    if median is not None:
        parts.append(f"median {median:g} ms")
    if p95 is not None:
        parts.append(f"p95 {p95:g} ms")
    return ", ".join(parts) or "no successful measurements"


def print_sample_summary(summary: Mapping[str, Any], title: Optional[str] = None) -> None:
    if title:
        print(title)
    print(f"  Gateway ICMP: {format_metric(summary['gateway_ping'])}")
    print(f"  Public ICMP:  {format_metric(summary['public_ping'])}")
    print(f"  DNS lookup:   {format_metric(summary['dns'], 'failure_percent')}")
    print(f"  npm registry: {format_metric(summary['registry_https'], 'failure_percent')}")


def compare_phases(
    baseline: Mapping[str, Any],
    load: Mapping[str, Any],
) -> List[str]:
    signals: List[str] = []
    base_gateway = baseline.get("gateway_ping", {})
    load_gateway = load.get("gateway_ping", {})
    base_public = baseline.get("public_ping", {})
    load_public = load.get("public_ping", {})
    load_registry = load.get("registry_https", {})

    if load_gateway.get("available"):
        gateway_loss = float(load_gateway.get("loss_percent") or 0.0)
        base_loss = float(base_gateway.get("loss_percent") or 0.0)
        if gateway_loss >= 10.0 and gateway_loss > base_loss + 5.0:
            signals.append(
                "Gateway replies deteriorated under load. This suggests the local Wi-Fi/USB/driver/router path, "
                "though some routers deprioritize ICMP."
            )
    if load_registry.get("available") and float(load_registry.get("failure_percent") or 0.0) > 0:
        if float(load_gateway.get("loss_percent") or 0.0) < 5.0:
            signals.append(
                "The gateway remained reachable while npm-registry HTTPS probes failed; investigate DNS, ISP/router uplink, "
                "proxy/VPN, or upstream queueing rather than only the Wi-Fi radio."
            )
    base_med = base_public.get("median_ms")
    load_p95 = load_public.get("p95_ms")
    if base_med is not None and load_p95 is not None:
        threshold = max(200.0, float(base_med) * 4.0)
        if float(load_p95) >= threshold and float(load_gateway.get("loss_percent") or 0.0) < 10.0:
            signals.append(
                "Public latency rose sharply under load while the gateway was mostly reachable. This is consistent with "
                "bufferbloat at the router/ISP bottleneck; confirm with a router-side loaded-latency test."
            )
    if not signals:
        signals.append(
            "This short run did not isolate a clear failure domain. Repeat the watch command during a failing install and "
            "compare with Ethernet or a USB 2.0 extension-cable test."
        )
    return signals


def collect_platform_diagnostics() -> Dict[str, Any]:
    system = platform.system()
    commands: List[Tuple[str, Sequence[str], float]] = []
    data: Dict[str, Any] = {}
    if system == "Windows":
        commands.extend(
            [
                ("wlan_interfaces", ["netsh", "wlan", "show", "interfaces"], 15),
                ("wlan_drivers", ["netsh", "wlan", "show", "drivers"], 15),
                ("tcp_global", ["netsh", "interface", "tcp", "show", "global"], 15),
                ("power_active", ["powercfg", "/getactivescheme"], 10),
            ]
        )
        adapter_script = r"""
$items=@(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Select-Object Name,InterfaceDescription,InterfaceGuid,Status,LinkSpeed,DriverInformation,DriverFileName,DriverVersionString,PnPDeviceID)
ConvertTo-Json -InputObject $items -Depth 4 -Compress
"""
        data["windows_netadapters"] = run_powershell(adapter_script, timeout=20).to_report()
        driver_script = r"""
$items=@(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object {$_.DeviceClass -eq 'NET'} | Select-Object DeviceName,Manufacturer,DriverProviderName,DriverVersion,DriverDate,InfName,DeviceID)
ConvertTo-Json -InputObject $items -Depth 4 -Compress
"""
        data["windows_network_drivers"] = run_powershell(driver_script, timeout=30).to_report()
    elif system == "Linux":
        if shutil.which("nmcli"):
            commands.extend(
                [
                    ("nmcli_devices", ["nmcli", "-f", "GENERAL,IP4,IP6", "device", "show"], 20),
                    (
                        "nmcli_wifi",
                        ["nmcli", "-f", "IN-USE,SSID,MODE,CHAN,RATE,SIGNAL,BARS,SECURITY,DEVICE", "device", "wifi", "list", "--rescan", "no"],
                        20,
                    ),
                ]
            )
        if shutil.which("iw"):
            commands.append(("iw_dev", ["iw", "dev"], 10))
        if shutil.which("ip"):
            commands.extend(
                [
                    ("ip_address", ["ip", "-brief", "address"], 10),
                    ("ip_route", ["ip", "route"], 10),
                ]
            )
    elif system == "Darwin":
        commands.extend(
            [
                ("hardware_ports", ["networksetup", "-listallhardwareports"], 15),
                ("airport_profiler", ["system_profiler", "SPAirPortDataType", "-detailLevel", "mini"], 45),
                ("route", ["route", "-n", "get", "default"], 10),
            ]
        )
    else:
        if shutil.which("ipconfig"):
            commands.append(("ipconfig", ["ipconfig"], 15))
        elif shutil.which("ifconfig"):
            commands.append(("ifconfig", ["ifconfig"], 15))

    for label, command, timeout in commands:
        data[label] = run_command(command, timeout=timeout).to_report()
    return data


def capability_matrix() -> List[Dict[str, str]]:
    system = platform.system()
    matrix: List[Dict[str, str]] = [
        {
            "capability": "Idle gateway and remote latency probes",
            "available": "yes",
            "source": "ping command with HTTPS/DNS corroboration",
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
            "capability": "npm weak-link profile",
            "available": "yes" if npm_executable() else "no",
            "source": "npm config user location",
            "privilege": "user",
            "mutation": "application-scoped, snapshot-backed",
        },
        {
            "capability": "Router SQM/AQM control",
            "available": "no",
            "source": "endpoint-only tool boundary",
            "privilege": "router administrator",
            "mutation": "advice only",
        },
    ]
    if system == "Windows":
        matrix.extend(
            [
                {
                    "capability": "Wi-Fi adapter inventory",
                    "available": "yes",
                    "source": "PowerShell NetAdapter structured JSON",
                    "privilege": "none",
                    "mutation": "none",
                },
                {
                    "capability": "Adapter-scoped power stability profile",
                    "available": "conditional",
                    "source": "Get/Set-NetAdapterPowerManagement and powercfg",
                    "privilege": "administrator to write",
                    "mutation": "snapshot-backed, opt-in apply path",
                },
                {
                    "capability": "MTU optimization (1500)",
                    "available": "conditional",
                    "source": "netsh interface ipv4 set subinterface",
                    "privilege": "administrator",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "ECN enable",
                    "available": "conditional",
                    "source": "Set-NetTCPSetting",
                    "privilege": "administrator",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "Delivery Optimization disable",
                    "available": "conditional",
                    "source": "registry DODownloadMode",
                    "privilege": "administrator",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "QoS reservable bandwidth 0%",
                    "available": "conditional",
                    "source": "registry NonBestEffortLimit",
                    "privilege": "administrator",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "LSO disable on Wi-Fi",
                    "available": "conditional",
                    "source": "Disable-NetAdapterLso",
                    "privilege": "administrator",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "TCP retransmission tuning",
                    "available": "conditional",
                    "source": "registry TcpMaxData/ConnectRetransmissions",
                    "privilege": "administrator",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "Network stack reset",
                    "available": "conditional",
                    "source": "netsh int ip reset, winsock reset, ipconfig /flushdns",
                    "privilege": "administrator",
                    "mutation": "requires reboot",
                },
                {
                    "capability": "Windows WLAN report",
                    "available": "conditional",
                    "source": "netsh wlan report",
                    "privilege": "user",
                    "mutation": "none",
                },
            ]
        )
    elif system == "Linux":
        matrix.extend(
            [
                {
                    "capability": "NetworkManager Wi-Fi profile inventory",
                    "available": "yes" if shutil.which("nmcli") else "no",
                    "source": "nmcli structured fields",
                    "privilege": "none",
                    "mutation": "none",
                },
                {
                    "capability": "NetworkManager Wi-Fi powersave profile",
                    "available": "conditional",
                    "source": "nmcli 802-11-wireless.powersave",
                    "privilege": "polkit/root to write",
                    "mutation": "snapshot-backed, opt-in apply path",
                },
                {
                    "capability": "sysctl TCP/IP tuning (buffers, BBR, fq_codel)",
                    "available": "conditional",
                    "source": "sysctl / /etc/sysctl.d/",
                    "privilege": "root",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "NIC ring buffer tuning",
                    "available": "conditional",
                    "source": "ethtool -G",
                    "privilege": "root",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "IRQ balance daemon",
                    "available": "conditional",
                    "source": "systemctl irqbalance",
                    "privilege": "root",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "DNS optimization",
                    "available": "conditional",
                    "source": "resolvectl / /etc/resolv.conf",
                    "privilege": "root",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "nl80211 deep station counters",
                    "available": "planned",
                    "source": "kernel nl80211",
                    "privilege": "none or platform-dependent",
                    "mutation": "none",
                },
            ]
        )
    elif system == "Darwin":
        matrix.extend(
            [
                {
                    "capability": "Working-condition responsiveness",
                    "available": "conditional",
                    "source": "networkQuality when present",
                    "privilege": "none",
                    "mutation": "none",
                },
                {
                    "capability": "DNS optimization",
                    "available": "conditional",
                    "source": "networksetup -setdnsservers",
                    "privilege": "root",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "TCP buffer tuning",
                    "available": "conditional",
                    "source": "sysctl / /etc/sysctl.conf",
                    "privilege": "root",
                    "mutation": "snapshot-backed",
                },
                {
                    "capability": "Network config reset",
                    "available": "conditional",
                    "source": "SystemConfiguration plist + route flush + mDNSResponder restart",
                    "privilege": "root",
                    "mutation": "requires reboot",
                },
                {
                    "capability": "Wi-Fi system mutation",
                    "available": "no",
                    "source": "no documented public control used by this tool",
                    "privilege": "n/a",
                    "mutation": "none",
                },
            ]
        )
    else:
        matrix.append(
            {
                "capability": f"{system} system tuning",
                "available": "no",
                "source": "unsupported platform",
                "privilege": "n/a",
                "mutation": "none",
            }
        )
    return matrix


def repository_map() -> Dict[str, Any]:
    return {
        "public_commands": [
            "diagnose",
            "measure idle",
            "watch -- <command>",
            "audit",
            "apply",
            "restore",
            "list-backups",
            "reset-network",
        ],
        "platform_abstractions": {
            "windows": "PowerShell/PowerCFG/NetAdapter read and adapter-scoped power writes",
            "linux": "NetworkManager/nmcli read and active Wi-Fi profile powersave writes",
            "macos": "diagnostics plus optional networkQuality; no undocumented Wi-Fi writes",
        },
        "snapshot_restore": {
            "location": str(state_root() / "backups"),
            "schema_version": SCHEMA_VERSION,
            "restore_semantics": "snapshot-backed restore with conflict backup for npm user config",
        },
        "application_profiles": ["npm weak-link profile"],
        "privileged_operations": [
            "Windows system apply/restore requires Administrator",
            "Linux NetworkManager write may require polkit/root",
        ],
        "tests": "standard-library smoke checks plus policy tests",
        "remaining_gaps": [
            "Native Wi-Fi ctypes backend is not yet implemented",
            "Linux nl80211 counter backend is not yet implemented",
            "Out-of-process rollback watchdog is not yet implemented",
            "Benchmark acceptance still requires repeated external workloads",
            "Router integration remains advisory only",
        ],
    }


def observation_record(
    kind: str,
    severity: str,
    facts: Sequence[str],
    confidence: float,
    limitations: Sequence[str],
) -> Dict[str, Any]:
    return {
        "id": f"obs-{kind}",
        "kind": kind,
        "severity": severity,
        "facts": list(facts),
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "limitations": list(limitations),
    }


def recommendation_record(
    identifier: str,
    layer: str,
    title: str,
    evidence_grade: str,
    risk: str,
    observations: Sequence[str],
    expected_metrics: Sequence[str],
    uncertainty: str,
) -> Dict[str, Any]:
    return {
        "id": identifier,
        "control_layer": layer,
        "title": title,
        "evidence_grade": evidence_grade,
        "risk": risk,
        "automatic": False,
        "trigger_observations": list(observations),
        "expected_metrics": list(expected_metrics),
        "uncertainty": uncertainty,
    }


def classify_measurement(
    baseline: Mapping[str, Any],
    load: Optional[Mapping[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    active = load if load is not None else baseline
    observations: List[Dict[str, Any]] = []
    recommendations: List[Dict[str, Any]] = []
    gateway = active.get("gateway_ping", {})
    public = active.get("public_ping", {})
    dns = active.get("dns", {})
    registry = active.get("registry_https", {})

    gateway_loss = float(gateway.get("loss_percent") or 0.0)
    public_loss = float(public.get("loss_percent") or 0.0)
    dns_fail = float(dns.get("failure_percent") or 0.0)
    registry_fail = float(registry.get("failure_percent") or 0.0)

    if gateway.get("available") and gateway_loss >= 10.0:
        observations.append(
            observation_record(
                "gateway_latency_or_loss",
                "high",
                [f"gateway_loss_percent={gateway_loss:g}"],
                0.72,
                ["ICMP may be deprioritized by some routers."],
            )
        )
        recommendations.append(
            recommendation_record(
                "rec-local-link-watch",
                "wifi_link",
                "Repeat a watched run and compare with placement, band, or wired/Ethernet evidence",
                "A/B/C",
                "read-only",
                ["obs-gateway_latency_or_loss"],
                ["loss", "loaded_latency", "disconnects"],
                "Gateway loss alone cannot distinguish Wi-Fi RF, AP contention, adapter reset, or router CPU behavior.",
            )
        )

    if public.get("available") and public_loss >= 10.0 and gateway_loss < 5.0:
        observations.append(
            observation_record(
                "remote_path_loss",
                "high",
                [f"public_loss_percent={public_loss:g}", f"gateway_loss_percent={gateway_loss:g}"],
                0.76,
                ["A single public target can be rate-limited or filtered."],
            )
        )
        recommendations.append(
            recommendation_record(
                "rec-remote-path-diversity",
                "isp_path",
                "Test multiple remote endpoints before changing local Wi-Fi or TCP settings",
                "A",
                "read-only",
                ["obs-remote_path_loss"],
                ["loss", "target_diversity"],
                "Remote loss with a stable gateway can be ISP, route, target, proxy, or VPN behavior.",
            )
        )

    if dns.get("available") and dns_fail > 0.0 and registry_fail == 0.0:
        observations.append(
            observation_record(
                "resolver_delay_or_failure",
                "medium",
                [f"dns_failure_percent={dns_fail:g}", "https_probe_success=true"],
                0.66,
                ["The current probe does not separate cached from uncached resolver responses."],
            )
        )
        recommendations.append(
            recommendation_record(
                "rec-dns-phase-timing",
                "host_transport",
                "Run request-phase diagnostics before changing DNS providers",
                "A",
                "read-only",
                ["obs-resolver_delay_or_failure"],
                ["dns_latency", "connect_latency"],
                "DNS changes can affect lookup latency or address selection, not raw Wi-Fi capacity.",
            )
        )

    if load is not None:
        base_public = baseline.get("public_ping", {})
        base_median = base_public.get("median_ms")
        load_p95 = public.get("p95_ms")
        if base_median is not None and load_p95 is not None:
            threshold = max(200.0, float(base_median) * 4.0)
            if float(load_p95) >= threshold and gateway_loss < 10.0:
                observations.append(
                    observation_record(
                        "loaded_latency_inflation",
                        "high",
                        [f"idle_public_median_ms={float(base_median):g}", f"load_public_p95_ms={float(load_p95):g}"],
                        0.82,
                        ["Short runs are preliminary; repeat with upload/download direction separated."],
                    )
                )
                recommendations.append(
                    recommendation_record(
                        "rec-router-sqm-advice",
                        "router_queue",
                        "Evaluate SQM/FQ-CoDel/CAKE at the WAN bottleneck",
                        "A",
                        "moderate",
                        ["obs-loaded_latency_inflation"],
                        ["loaded_latency", "loss", "fairness"],
                        "A PC-side tool can measure this symptom but cannot directly fix a modem/router queue.",
                    )
                )

    if not observations:
        observations.append(
            observation_record(
                "insufficient_evidence",
                "low",
                ["no_threshold_crossed=true"],
                0.35,
                ["More samples or a watched failing workload may be required."],
            )
        )
        recommendations.append(
            recommendation_record(
                "rec-collect-working-evidence",
                "application",
                "Capture a watched run during the failure",
                "A/B",
                "read-only",
                ["obs-insufficient_evidence"],
                ["command_exit_status", "gateway_latency", "remote_latency"],
                "The current data does not identify a single control layer.",
            )
        )
    return observations, recommendations


def redact_command(command: Sequence[str]) -> List[str]:
    redacted: List[str] = []
    hide_next = False
    for item in command:
        if hide_next:
            redacted.append("<redacted-secret>")
            hide_next = False
            continue
        if SECRET_ARG_RE.search(item):
            redacted.append("<redacted-secret-arg>")
            if "=" not in item:
                hide_next = True
            continue
        redacted.append(TOKEN_VALUE_RE.sub("<redacted-secret>", item))
    return redacted


def redact_report_value(value: Any) -> Any:
    if isinstance(value, str):
        redacted = MAC_RE.sub("<redacted-mac>", value)
        redacted = TOKEN_VALUE_RE.sub("<redacted-secret>", redacted)
        return IPV4_RE.sub("<redacted-ipv4>", redacted)
    if isinstance(value, list):
        return [redact_report_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_report_value(item) for key, item in value.items()}
    return value


def report_path(prefix: str) -> Path:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return reports_root() / f"{prefix}-{stamp}-{secrets.token_hex(2)}.json"


def maybe_run_network_quality(enabled: bool) -> Optional[Dict[str, Any]]:
    if not enabled or platform.system() != "Darwin":
        return None
    executable = shutil.which("networkQuality") or "/usr/bin/networkQuality"
    return run_command([executable, "-v"], timeout=180).to_report()


def maybe_generate_windows_wlan_report(enabled: bool) -> Optional[Dict[str, Any]]:
    if not enabled or platform.system() != "Windows":
        return None
    result = run_command(["netsh", "wlan", "show", "wlanreport"], timeout=90)
    program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    expected = Path(program_data) / "Microsoft" / "Windows" / "WlanReport" / "wlan-report-latest.html"
    record = result.to_report()
    record["expected_report_path"] = str(expected)
    record["report_exists"] = expected.is_file()
    if result.ok:
        print(f"Windows WLAN report: {expected}")
    else:
        print_command_failure("Windows WLAN report", result)
    return record


def command_audit(args: argparse.Namespace) -> int:
    gateway = default_gateway()
    report: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": APP_DISPLAY_NAME, "version": VERSION},
        "created_utc": utc_now_iso(),
        "platform": platform_metadata(),
        "gateway": gateway,
        "repository_map": repository_map(),
        "control_layers": list(CONTROL_LAYERS),
        "capability_matrix": capability_matrix(),
        "evidence_policy": list(EVIDENCE_POLICY),
        "anti_folklore_denylist": list(ANTI_FOLKLORE_DENYLIST),
        "normal_mode_boundaries": [
            "audit, diagnose, measure, watch, and list-backups are read-only apart from explicit report files",
            "apply and restore are the only normal commands that write persistent settings",
            "reset-network resets the TCP/IP and DNS stack (requires reboot)",
            "router queue control remains advisory unless a separate reviewed router plugin exists",
            "macOS Wi-Fi mutation is not implemented through undocumented controls",
        ],
    }
    if args.platform_diagnostics:
        report["platform_diagnostics"] = collect_platform_diagnostics()
    if args.redact:
        report = redact_report_value(report)
    destination = Path(args.output).expanduser() if args.output else report_path("audit")
    atomic_write_json(destination, report, private_parent=not bool(args.output))

    print("Evidence audit:")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print(f"  Gateway: {gateway or 'not detected'}")
    print("  Normal mode policy:")
    print("    Denied (folklore, no evidence):")
    for item in ANTI_FOLKLORE_DENYLIST:
        if not item.lstrip().startswith("#"):
            print(f"      - {item}")
    print("    Overridden (paper-backed, evidence-guided):")
    print("      - Fixed MTU=1500 on Wi-Fi interfaces")
    print("      - DNS replacement to 1.1.1.1 / 1.0.0.1")
    print("      - ECN enable on Windows")
    print("      - BBR congestion control + fq_codel on Linux")
    print("      - Selective LSO disable on Wi-Fi adapters when it causes latency")
    print("      - QoS reservable bandwidth set to 0%")
    print("  Capability matrix:")
    for row in report["capability_matrix"]:
        print(f"    - {row['capability']}: {row['available']} ({row['mutation']})")
    print(f"Report saved: {destination}")
    return 0


def command_diagnose(args: argparse.Namespace) -> int:
    gateway = default_gateway()
    print(f"Default gateway: {gateway or 'not detected'}")
    samples = collect_samples(
        args.samples,
        args.interval,
        gateway,
        args.public_target,
        args.registry_host,
        "idle",
    )
    summary = summarize_samples(samples)
    print_sample_summary(summary, "Measurement summary:")
    observations, recommendations = classify_measurement(summary)

    report: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": APP_DISPLAY_NAME, "version": VERSION},
        "created_utc": utc_now_iso(),
        "platform": platform_metadata(),
        "gateway": gateway,
        "targets": {"public_ping": args.public_target, "registry": args.registry_host},
        "samples": samples,
        "summary": summary,
        "observations": observations,
        "recommendations": recommendations,
        "capability_matrix": capability_matrix(),
        "platform_diagnostics": collect_platform_diagnostics(),
        "network_quality": maybe_run_network_quality(args.network_quality),
        "windows_wlan_report": maybe_generate_windows_wlan_report(args.wlan_report),
        "notes": [
            "ICMP can be rate-limited or blocked; interpret ping together with HTTPS results.",
            "This report contains local adapter/network metadata. Use --redact before sharing it.",
        ],
    }
    if args.redact:
        report = redact_report_value(report)
    destination = Path(args.output).expanduser() if args.output else report_path("diagnose")
    atomic_write_json(destination, report, private_parent=not bool(args.output))
    print(f"Report saved: {destination}")
    return 0


def command_measure_idle(args: argparse.Namespace) -> int:
    return command_diagnose(args)


def launch_monitored_command(command: Sequence[str]) -> subprocess.Popen[Any]:
    kwargs: Dict[str, Any] = {}
    if platform.system() == "Windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return subprocess.Popen(list(command), **kwargs)


def command_watch(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise NetStabilityError("watch requires a command after --, for example: watch -- npm install")

    gateway = default_gateway()
    baseline_count = max(1, int(math.ceil(args.baseline_seconds / args.interval)))
    print(f"Default gateway: {gateway or 'not detected'}")
    print(f"Collecting {args.baseline_seconds:g}s baseline before launching: {' '.join(command)}")
    baseline_samples = collect_samples(
        baseline_count,
        args.interval,
        gateway,
        args.public_target,
        args.registry_host,
        "baseline",
    )
    baseline_summary = summarize_samples(baseline_samples)
    print_sample_summary(baseline_summary, "Baseline:")

    try:
        process = launch_monitored_command(command)
    except OSError as exc:
        raise NetStabilityError(f"Could not launch command: {exc}") from exc

    load_samples: List[Dict[str, Any]] = []
    service_every = max(1, int(round(5.0 / max(args.interval, 0.1))))
    next_tick = time.monotonic()
    index = 0
    interrupted = False
    try:
        while process.poll() is None:
            sample = collect_sample(
                gateway,
                args.public_target,
                args.registry_host,
                include_service=(index % service_every == 0),
                phase="load",
            )
            load_samples.append(sample)
            index += 1
            next_tick += args.interval
            sleep_for = next_tick - time.monotonic()
            if sleep_for > 0 and process.poll() is None:
                time.sleep(sleep_for)
    except KeyboardInterrupt:
        interrupted = True
        print("\nMonitor interrupted; terminating child command...", file=sys.stderr)
        with contextlib.suppress(OSError):
            process.terminate()
    finally:
        try:
            returncode = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                process.kill()
            returncode = process.wait()

    if not load_samples:
        load_samples.append(
            collect_sample(gateway, args.public_target, args.registry_host, True, "load")
        )
    load_summary = summarize_samples(load_samples)
    print_sample_summary(load_summary, "During command:")
    signals = compare_phases(baseline_summary, load_summary)
    observations, recommendations = classify_measurement(baseline_summary, load_summary)
    print("Interpretation:")
    for signal in signals:
        print(f"  - {signal}")

    report: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": APP_DISPLAY_NAME, "version": VERSION},
        "created_utc": utc_now_iso(),
        "platform": platform_metadata(),
        "gateway": gateway,
        "targets": {"public_ping": args.public_target, "registry": args.registry_host},
        "command": redact_command(command) if args.redact else command,
        "command_returncode": returncode,
        "interrupted": interrupted,
        "baseline_samples": baseline_samples,
        "load_samples": load_samples,
        "baseline_summary": baseline_summary,
        "load_summary": load_summary,
        "interpretation": signals,
        "observations": observations,
        "recommendations": recommendations,
        "capability_matrix": capability_matrix(),
        "notes": [
            "ICMP can be rate-limited or blocked; HTTPS probes are included for corroboration.",
            "A host-side tool cannot repair queues inside an ISP modem/router; SQM must run at the bottleneck.",
        ],
    }
    if args.redact:
        report = redact_report_value(report)
    destination = Path(args.output).expanduser() if args.output else report_path("watch")
    atomic_write_json(destination, report, private_parent=not bool(args.output))
    print(f"Report saved: {destination}")
    return 130 if interrupted else returncode


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def add_scope_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--system-only", action="store_true", help="change/restore only OS settings")
    group.add_argument("--npm-only", action="store_true", help="change/restore only the npm user configuration")


def add_probe_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interval", type=positive_float, default=1.0, help="seconds between samples (default: 1)")
    parser.add_argument("--public-target", default=DEFAULT_PUBLIC_PING_TARGET, help="public ICMP target")
    parser.add_argument("--registry-host", default=DEFAULT_REGISTRY_HOST, help="HTTPS/DNS probe host")
    parser.add_argument("--output", help="write JSON report to this path")
    parser.add_argument("--redact", action="store_true", help="redact MAC addresses in the saved report")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description="Diagnose weak Wi-Fi links and apply conservative, reversible OS/npm reliability tuning.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    audit = subparsers.add_parser("audit", help="write a read-only evidence, capability, and safety-policy report")
    audit.add_argument("--output", help="write JSON report to this path")
    audit.add_argument("--redact", action="store_true", help="redact identifiers in the saved report")
    audit.add_argument(
        "--no-platform-diagnostics",
        dest="platform_diagnostics",
        action="store_false",
        help="skip OS command diagnostics and only emit the policy/capability model",
    )
    audit.set_defaults(function=command_audit, platform_diagnostics=True)

    diagnose = subparsers.add_parser("diagnose", help="collect idle network and adapter diagnostics")
    diagnose.add_argument("--samples", type=positive_int, default=10, help="number of network samples (default: 10)")
    diagnose.add_argument(
        "--network-quality",
        action="store_true",
        help="on macOS, additionally run Apple's loaded networkQuality test",
    )
    diagnose.add_argument(
        "--wlan-report",
        action="store_true",
        help="on Windows, generate Microsoft's WLAN disconnect report",
    )
    add_probe_options(diagnose)
    diagnose.set_defaults(function=command_diagnose)

    measure = subparsers.add_parser("measure", help="measurement-first diagnostics without applying settings")
    measure_subparsers = measure.add_subparsers(dest="measure_name", required=True)
    measure_idle = measure_subparsers.add_parser("idle", help="collect idle baseline samples")
    measure_idle.add_argument("--samples", type=positive_int, default=10, help="number of network samples (default: 10)")
    measure_idle.add_argument(
        "--network-quality",
        action="store_true",
        help="on macOS, additionally run Apple's loaded networkQuality test",
    )
    measure_idle.add_argument(
        "--wlan-report",
        action="store_true",
        help="on Windows, generate Microsoft's WLAN disconnect report",
    )
    add_probe_options(measure_idle)
    measure_idle.set_defaults(function=command_measure_idle)

    watch = subparsers.add_parser("watch", help="monitor gateway/public/registry health while a command runs")
    watch.add_argument(
        "--baseline-seconds",
        type=positive_float,
        default=5.0,
        help="idle baseline duration before launching the command (default: 5)",
    )
    add_probe_options(watch)
    watch.add_argument("command", nargs=argparse.REMAINDER, help="command after --, e.g. -- npm install")
    watch.set_defaults(function=command_watch)

    apply_parser = subparsers.add_parser("apply", help="back up current state, then apply reliability tuning")
    add_scope_options(apply_parser)
    apply_parser.add_argument(
        "--include-battery",
        action="store_true",
        help="Windows: also use Maximum Performance for Wi-Fi while on battery",
    )
    apply_parser.add_argument(
        "--npm-maxsockets",
        type=positive_int,
        default=4,
        help="npm connections per origin for the weak-link profile (default: 4)",
    )
    apply_parser.add_argument("--no-restart", action="store_true", help="do not restart/reapply the Wi-Fi adapter")
    apply_parser.add_argument("--dry-run", action="store_true", help="show intended changes only")
    apply_parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    apply_parser.set_defaults(function=command_apply)

    restore = subparsers.add_parser("restore", help="restore an exact pre-change snapshot")
    restore.add_argument("snapshot", nargs="?", default="latest", help="snapshot ID or 'latest' (default: latest)")
    add_scope_options(restore)
    restore.add_argument("--no-restart", action="store_true", help="do not restart/reapply the Wi-Fi adapter")
    restore.add_argument("--dry-run", action="store_true", help="show intended restore only")
    restore.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    restore.set_defaults(function=command_restore)

    listing = subparsers.add_parser("list-backups", help="list available restore snapshots")
    listing.set_defaults(function=command_list_backups)

    reset = subparsers.add_parser(
        "reset-network",
        help="reset TCP/IP, Winsock, and DNS to OS defaults (requires reboot)",
    )
    reset.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    reset.set_defaults(function=command_reset_network)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.function(args))
    except NetStabilityError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        if os.environ.get("NET_STABILITY_DEBUG") == "1":
            raise
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
