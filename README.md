# Net Stability

![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-standard%20library-2f855a)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-4c51bf)
![License](https://img.shields.io/badge/license-Unlicense-brightgreen)

Net Stability is a small, reversible network reliability helper for weak Wi-Fi links and flaky `npm install` runs. It diagnoses the likely failure layer first, applies conservative tuning only on explicit action, and restores exact backups.

It now includes a simple desktop UI for non-technical users: one main read-only audit button, with advanced actions underneath for baseline measurement, full diagnostics, npm-only tuning, restore, or backup listing.

## What It Does

- Creates a restore point before applying changes.
- Applies a weak-link npm profile: fewer per-origin sockets, longer fetch timeouts, more retries, and `prefer-offline`.
- On Windows, adjusts documented Wi-Fi power behavior and supported adapter power properties when run as Administrator.
- On Linux, disables NetworkManager Wi-Fi powersave on active Wi-Fi profiles when authorized.
- On macOS, keeps system tuning diagnostic-only because there is no documented public Wi-Fi power equivalent used here.
- Saves diagnostic JSON reports with control-layer observations, recommendations, capability matrices, and optional identifier/token redaction.
- Generates a read-only evidence audit that lists supported capabilities, denied folklore tweaks, and the current implementation gaps.
- Avoids broad folklore tweaks such as DNS replacement, MTU guessing, TCP auto-tuning edits, QoS-reservation changes, global USB suspend changes, or blanket NIC offload disabling.

## Quick Start

Clone the repository, then run the desktop UI:

```bash
python net_stability_gui.py
```

Click **Audit evidence first**. The app will show the stages as they run and print the underlying command output in the log.

For Windows system tuning, open the terminal as Administrator before launching the GUI:

```powershell
python net_stability_gui.py
```

If you do not have admin access, use **Optimize npm only** in the advanced section.

## Command Line

The GUI wraps the same CLI, so everything can also be run from a terminal.

```bash
python net_stability.py diagnose
python net_stability.py audit
python net_stability.py measure idle
python net_stability.py apply
python net_stability.py apply --npm-only
python net_stability.py restore latest
python net_stability.py list-backups
python net_stability.py watch -- npm install
```

Useful options:

```bash
python net_stability.py diagnose --samples 20 --redact
python net_stability.py audit --redact
python net_stability.py measure idle --samples 20 --redact
python net_stability.py apply --dry-run
python net_stability.py apply --system-only
python net_stability.py restore latest --npm-only
```

## Beginner UI

The desktop UI is intentionally small and cross-platform:

- Built with `tkinter`, included with most Python desktop installs.
- No third-party runtime dependencies.
- One primary action: **Audit evidence first**.
- Advanced actions stay visible but secondary.
- The stage list explains what is happening without hiding the real log.

This keeps the project easy to package later with tools such as PyInstaller or Briefcase.

## Restore Points

Backups are stored outside the repository:

| OS | Backup location |
| --- | --- |
| Windows | `%LOCALAPPDATA%\NetStability\backups` |
| macOS | `~/Library/Application Support/NetStability/backups` |
| Linux | `$XDG_STATE_HOME/netstability/backups` or `~/.local/state/netstability/backups` |

To undo the latest change:

```bash
python net_stability.py restore latest
```

To inspect available backups:

```bash
python net_stability.py list-backups
```

## Platform Notes

### Windows

System tuning requires an Administrator terminal. User-level npm tuning does not.

The tool may briefly restart or reapply the Wi-Fi adapter/connection so the setting takes effect.

### Linux

Run npm tuning as your normal user:

```bash
python net_stability.py apply --npm-only
```

If NetworkManager denies permission for system tuning, run the system-only operation separately:

```bash
sudo python net_stability.py apply --system-only
```

The tool refuses to modify npm configuration under `sudo` to avoid changing root's npm state by accident.

### macOS

The tool collects diagnostics and can tune npm. It does not change undocumented system Wi-Fi settings.

## Install As A Local Command

The project has no runtime dependencies. For a local editable install:

```bash
uv pip install -e .
net-stability-gui
```

If you prefer not to install it, run the files directly with `python`.

## Development Checks

Basic verification:

```bash
python -m py_compile net_stability.py net_stability_gui.py
python net_stability.py --version
python net_stability_gui.py --smoke
```

The smoke check verifies the GUI entry point without opening a desktop window.

## Safety Model

Net Stability is intentionally conservative:

- Every change is backed up before it is applied.
- Restore commands target exact snapshots.
- User npm state and elevated system state are handled separately when needed.
- The tool favors documented OS knobs and explicit diagnostics.
- Reports can be redacted before sharing.
- Router queue management is advisory only; a PC-side utility cannot directly fix queues inside an ISP modem or router.
- The normal path refuses fixed-MTU guesses, global IPv6/DNS/TCP folklore tweaks, blanket offload changes, global USB selective-suspend changes, and generic "gaming" registry recipes.

## License

Released under [The Unlicense](LICENSE). Use it, fork it, package it, sell it, or change it for any purpose.
