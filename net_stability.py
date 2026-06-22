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

NPM_PROFILE_BASE: Dict[str, str] = {
    "fetch-retries": "5",
    "fetch-retry-factor": "2",
    "fetch-retry-mintimeout": "20000",
    "fetch-retry-maxtimeout": "120000",
    "fetch-timeout": "600000",
    "prefer-offline": "true",
}

MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
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


def capture_windows_state() -> Dict[str, Any]:
    return {
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
    if system == "Windows":
        return capture_windows_state()
    if system == "Linux":
        return capture_linux_state()
    if system == "Darwin":
        return {
            "supported_changes": [],
            "note": "No documented public macOS Wi-Fi power setting is modified; diagnostics and npm tuning only.",
        }
    return {"supported_changes": [], "note": f"No system tuning implemented for {system}."}


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
    elif system == "Linux":
        apply_linux_system(manifest, manifest_path, restart=restart)
    elif system == "Darwin":
        print("  - macOS: no undocumented Wi-Fi system setting was changed")
    else:
        print(f"  - {system}: no system tuning is implemented")


def restore_system_state(manifest: Dict[str, Any], restart: bool) -> List[Dict[str, Any]]:
    system = str(manifest.get("platform", {}).get("system") or platform.system())
    if system != platform.system():
        raise NetStabilityError(
            f"Snapshot was created on {system}, but this machine is {platform.system()}; system restore refused"
        )
    if system == "Windows":
        return restore_windows_system(manifest, restart)
    if system == "Linux":
        return restore_linux_system(manifest, restart)
    return []


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
            changes.append("Set the active plan's Wi-Fi policy to Maximum Performance on AC" + (" and battery" if include_battery else ""))
            changes.append("Disable supported NDIS SelectiveSuspend and DeviceSleepOnDisconnect on physical Wi-Fi adapters")
        elif system == "Linux":
            changes.append("Set active NetworkManager Wi-Fi profiles to powersave=2 (disabled)")
        elif system == "Darwin":
            changes.append("No system setting (macOS has no documented public equivalent used by this tool)")
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


def command_apply(args: argparse.Namespace) -> int:
    do_system = not args.npm_only
    do_npm = not args.system_only
    validate_apply_context(do_system, do_npm)

    print("Planned changes:")
    for change in planned_changes(do_system, do_npm, args.include_battery, args.npm_maxsockets):
        print(f"  - {change}")
    if do_system and not args.no_restart and platform.system() in {"Windows", "Linux"}:
        print("  - The Wi-Fi adapter/connection may disconnect briefly while settings are activated")
    print("No MTU, DNS, TCP auto-tuning, global USB suspend, or blanket offload settings will be changed.")

    if args.dry_run:
        print("Dry run complete; no snapshot or setting was written.")
        return 0
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


def redact_report_value(value: Any) -> Any:
    if isinstance(value, str):
        return MAC_RE.sub("<redacted-mac>", value)
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

    report: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": APP_DISPLAY_NAME, "version": VERSION},
        "created_utc": utc_now_iso(),
        "platform": platform_metadata(),
        "gateway": gateway,
        "targets": {"public_ping": args.public_target, "registry": args.registry_host},
        "samples": samples,
        "summary": summary,
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
        "command": command,
        "command_returncode": returncode,
        "interrupted": interrupted,
        "baseline_samples": baseline_samples,
        "load_samples": load_samples,
        "baseline_summary": baseline_summary,
        "load_summary": load_summary,
        "interpretation": signals,
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
