# Net Stability

![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-standard%20library-2f855a)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-4c51bf)
![License](https://img.shields.io/badge/license-Unlicense-brightgreen)

Net Stability is a small, reversible network reliability helper for weak Wi-Fi links and flaky `npm install` runs. It diagnoses the likely failure layer first, applies conservative (but evidence-backed) tuning, and restores exact backups.

It includes a simple desktop UI with two primary paths: **Audit evidence first** for read-only diagnostics, and **Full Optimization** to apply every supported OS and npm tuning tweak in one shot.
It also includes a cross-platform **Repair DNS** action: Windows keeps the deeper DNS policy repair for corrupted NRPT state, while Linux and macOS use platform-native DNS cache and resolver repair.

---

## What It Does

- Creates a restore point **before** applying any change.
- Applies a weak-link npm profile: fewer per-origin sockets, longer fetch timeouts, more retries, and `prefer-offline`.
- **Windows**: Restores restricted TCP receive-window auto-tuning, adjusts Wi-Fi power policy and adapter power properties, sets MTU to 1500, enables ECN, disables Delivery Optimization P2P sharing, sets QoS reservable bandwidth to 0%, disables Large Send Offload on Wi-Fi adapters, and tunes TCP retransmission registry values.
- **Windows DNS policy**: Diagnoses NRPT corruption, DNS Client timeout events, and invalid resolver entries; repairs only invalid DNS server assignments and flushes the DNS cache, without deleting VPN or NRPT rules automatically.
- **Linux DNS repair**: Flushes the resolver cache when supported and repairs DNS servers to the stable 1.1.1.1 / 1.0.0.1 profile when the current resolver state is missing or invalid.
- **macOS DNS repair**: Flushes DNS and mDNS responder caches and repairs DNS servers to the stable 1.1.1.1 / 1.0.0.1 profile when needed.
- **Linux**: Disables NetworkManager Wi-Fi powersave, writes sysctl TCP/IP tuning (buffers, SACK, window scaling, timestamps, fastopen), enables BBR congestion control with fq_codel qdisc, increases NIC ring buffers, enables the irqbalance daemon, and sets DNS to 1.1.1.1.
- **macOS**: Sets DNS to 1.1.1.1 / 1.0.0.1, tunes TCP buffer sizes (131072 send/recv), and writes persistent sysctl.conf.
- **All platforms**: `reset-network` command resets the TCP/IP stack, Winsock (Windows), and DNS cache to OS defaults.
- Saves diagnostic JSON reports with control-layer observations, recommendations, capability matrices, and optional identifier/token redaction.
- Generates a read-only evidence audit that lists supported capabilities, denylisted folklore tweaks, and overridden paper-backed optimizations.

---

## Quick Start

Clone the repository, then run the desktop UI:

```bash
python net_stability_gui.py
```

Two primary buttons at the top:

- **Audit evidence first** -- read-only diagnostics and capability report.
- **Full Optimization** -- backs up current state, then applies every supported OS tuning and npm profile in one operation.
- **Repair DNS** -- platform-specific DNS repair for Windows, Linux, and macOS.

For Windows system tuning, open the terminal as Administrator before launching the GUI:

```powershell
python net_stability_gui.py
```

If you do not have admin access, use **Optimize npm only** in the advanced section.

---

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
python net_stability.py reset-network
python net_stability.py repair-dns
```

Useful options:

```bash
python net_stability.py diagnose --samples 20 --redact
python net_stability.py audit --redact
python net_stability.py measure idle --samples 20 --redact
python net_stability.py apply --dry-run
python net_stability.py apply --system-only
python net_stability.py restore latest --npm-only
python net_stability.py repair-dns --dry-run
```

---

## Beginner UI

The desktop UI is intentionally small and cross-platform:

- Built with `tkinter`, included with most Python desktop installs.
- No third-party runtime dependencies.
- Two primary buttons: **Audit evidence first** and **Full Optimization**.
- Advanced actions (DNS repair, diagnostics, npm-only, reset network, restore, backups) stay visible but secondary.
- An 8-stage progress panel tracks every step of the pipeline.
- The log panel streams real command output in a dark terminal-style view.

This keeps the project easy to package later with tools such as PyInstaller or Briefcase.

---

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

---

## Platform Notes

### Windows

System tuning requires an Administrator terminal. User-level npm tuning does not.

The tool applies these Windows-specific optimizations:
- TCP receive-window auto-tuning set to `normal` (repairs restricted/disabled states)
- Wi-Fi power policy set to Maximum Performance
- NDIS SelectiveSuspend and DeviceSleepOnDisconnect disabled on Wi-Fi adapters
- MTU set to 1500 on Wi-Fi interfaces
- ECN (Explicit Congestion Notification) enabled
- Delivery Optimization P2P sharing disabled via registry
- QoS reservable bandwidth set to 0%
- Large Send Offload disabled on Wi-Fi adapters
- TCP retransmission registry: `TcpMaxDataRetransmissions=5`, `TcpMaxConnectRetransmissions=3`

Windows DNS policy repair is available separately via `repair-dns`:
- Detects NRPT-effective query failures, DNS Client event 1014/1023 spikes, and invalid resolver entries like `0.0.0.0`
- Flushes the DNS cache before repair
- Rewrites only invalid interface DNS server assignments, preserving VPN and enterprise NRPT rules
- Recommends reboot or `reset-network` if NRPT corruption persists

The tool may briefly restart or reapply the Wi-Fi adapter so settings take effect.

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

Linux-specific optimizations:
- NetworkManager Wi-Fi powersave disabled on active profiles
- sysctl TCP/IP tuning: buffer sizes, SACK, window scaling, timestamps, TCP fastopen
- BBR congestion control enabled with fq_codel qdisc
- NIC ring buffers set to rx=4096 / tx=4096 (via ethtool)
- irqbalance daemon enabled and started
- DNS set to 1.1.1.1 / 1.0.0.1

Linux DNS repair is available via `repair-dns`:
- Reports current DNS servers
- Flushes resolver caches with `resolvectl` or `systemd-resolve` when available
- Sets DNS to 1.1.1.1 / 1.0.0.1 when the resolver state is missing, invalid, or not already using the stable profile

### macOS

macOS-specific optimizations:
- DNS set to 1.1.1.1 / 1.0.0.1
- TCP buffer sizes: send=131072, recv=131072
- Persistent sysctl.conf written for buffer settings

macOS DNS repair is available via `repair-dns`:
- Reports current DNS servers
- Flushes DNS and mDNS responder caches
- Sets DNS to 1.1.1.1 / 1.0.0.1 when the resolver state is missing, invalid, or not already using the stable profile

The tool does not change undocumented system Wi-Fi knobs.

---

## Network Stack Reset

The `reset-network` command resets TCP/IP, Winsock, and DNS settings to OS defaults:

```bash
python net_stability.py reset-network
```

This is a separate, destructive operation (not part of the normal `apply` path) and requires a system reboot afterward.

---

## Install As A Local Command

The project has no runtime dependencies. For a local editable install:

```bash
uv pip install -e .
net-stability-gui
```

If you prefer not to install it, run the files directly with `python`.

---

## Development Checks

Basic verification:

```bash
python -m py_compile net_stability.py net_stability_gui.py
python net_stability.py --version
python net_stability_gui.py --smoke
```

The smoke check verifies the GUI entry point without opening a desktop window.

---

## Safety Model

Net Stability is intentionally conservative:

- Every change is backed up **before** it is applied.
- Restore commands target exact snapshots with full pre-change state.
- User npm state and elevated system state are handled in separate operations when needed.
- Windows DNS policy repair is conservative and does not delete NRPT or VPN rules automatically.
- Linux and macOS DNS repair is scoped to resolver cache cleanup and the documented stable DNS server profile.
- The tool favors documented OS knobs and explicit diagnostics.
- Reports can be redacted before sharing.
- Router queue management is advisory only; a PC-side utility cannot directly fix queues inside an ISP modem or router.
- Some previously-denylisted tweaks (MTU, DNS, ECN, BBR, LSO, QoS) are now applied with **evidence-backed safe values** from the research paper. The `audit` command clearly lists which folklore tweaks are still denied and which are overridden with paper-backed justification.
- The `reset-network` command is intentionally kept separate from `apply` because it is a destructive operation.
- Non-evidence-backed folklore tweaks (global IPv6 disable, TCP ACK/Nagle recipes, RSS/VMQ on Wi-Fi, forced band/frequency, global USB suspend disable, firewall/antivirus disable, automatic driver installation) remain permanently denylisted.

---

## License

Released under [The Unlicense](LICENSE). Use it, fork it, package it, sell it, or change it for any purpose.
