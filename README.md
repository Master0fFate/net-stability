# Net Stability

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-websockets-2f855a)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-4c51bf)
![License](https://img.shields.io/badge/license-Unlicense-brightgreen)

Net Stability is a small, reversible network reliability helper for weak Wi-Fi links and flaky `npm install` runs. It diagnoses the likely failure layer first, verifies speed with M-Lab NDT7 when requested, applies conservative evidence-backed tuning, and restores exact backups.

For CPU-heavy package builds, the cross-platform **Build Guard** keeps one logical CPU available for network/USB driver work, lowers the build process priority, and monitors the connection. It does not throttle downloads or cap network bandwidth.

It includes a simple desktop UI with three primary paths: **Audit evidence first** for read-only diagnostics, **Verify speed and stability** for the M-Lab speed gate plus Wi-Fi link inspection, and **Full Optimization** to apply every supported OS and npm tuning tweak in one shot.
It also includes a cross-platform **Repair DNS** action: Windows keeps the deeper DNS policy repair for corrupted NRPT state, while Linux and macOS use platform-native DNS cache and resolver repair. On Windows USB Wi-Fi adapters, system optimization now records and repairs the active power-plan USB suspend path that can leave a reconnected adapter stuck in a no-internet state.
For cases where device-side tuning is already clean, **Diagnose router side** separates router/AP/WAN symptoms from client-side symptoms and prints only evidence-backed router actions to verify.

---

## What It Does

- Creates a restore point **before** applying any change.
- Applies a weak-link npm profile: fewer per-origin sockets, longer fetch timeouts, more retries, and `prefer-offline`.
- Runs builds with CPU headroom through `guard`, without limiting network bandwidth.
- Runs a read-only M-Lab NDT7 application speed test through the Locate API v2 and stores reports without access tokens.
- Inspects Wi-Fi link evidence from documented OS surfaces: Windows `netsh wlan`, Linux `nmcli`/`iw`, and macOS `networksetup`/`system_profiler`.
- Runs a read-only pressure-point benchmark with idle baseline probes, bounded HTTPS download load, packet loss, jitter, DNS, HTTPS, throughput, and adapter counter evidence.
- Runs a router-side diagnostic suite that classifies Wi-Fi channel/placement, AP/router first-hop degradation, WAN queue pressure, router DNS forwarding symptoms, and router/ISP throughput ceilings without mutating router settings.
- **Windows**: Restores restricted TCP receive-window auto-tuning, adjusts Wi-Fi power policy, disables active-plan USB suspend for detected USB Wi-Fi adapters, repairs exact USB adapter power-management flags when Windows exposes them, sets MTU to 1500, disables Delivery Optimization P2P sharing, sets QoS reservable bandwidth to 0%, and tunes TCP retransmission registry values.
- **Windows DNS policy**: Diagnoses NRPT corruption, DNS Client timeout events, and invalid resolver entries; repairs only invalid DNS server assignments and flushes the DNS cache, without deleting VPN or NRPT rules automatically.
- **Linux DNS repair**: Flushes the resolver cache when supported and repairs DNS servers to the stable 1.1.1.1 / 1.0.0.1 profile when the current resolver state is missing or invalid.
- **macOS DNS repair**: Flushes DNS and mDNS responder caches and repairs DNS servers to the stable 1.1.1.1 / 1.0.0.1 profile when needed.
- **Linux**: Disables NetworkManager Wi-Fi powersave, writes sysctl TCP/IP tuning (buffers, SACK, window scaling, timestamps, fastopen), enables BBR congestion control with fq_codel qdisc, increases NIC ring buffers, enables the irqbalance daemon, and sets DNS to 1.1.1.1.
- **macOS**: Sets DNS to 1.1.1.1 / 1.0.0.1, tunes TCP buffer sizes (131072 send/recv), and writes persistent sysctl.conf.
- **All platforms**: `reset-network` command resets the TCP/IP stack, Winsock (Windows), and DNS cache to OS defaults.
- Saves diagnostic JSON reports with control-layer observations, recommendations, capability matrices, optimizer action ledgers, and optional identifier/token redaction.
- Generates a read-only evidence audit that lists supported capabilities, denylisted folklore tweaks, and overridden paper-backed optimizations.

---

## Quick Start

Clone the repository, then run the desktop UI:

```bash
python net_stability_gui.py
```

Two primary buttons at the top:

- **Audit evidence first** -- read-only diagnostics and capability report.
- **Verify speed and stability** -- read-only M-Lab speed gate, Wi-Fi link inspection, and baseline probes.
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
python net_stability.py speedtest
python net_stability.py link-quality
python net_stability.py verify
python net_stability.py benchmark
python net_stability.py router-diagnose
python net_stability.py apply
python net_stability.py apply --npm-only
python net_stability.py restore latest
python net_stability.py list-backups
python net_stability.py watch -- npm install
python net_stability.py guard -- npm run build
python net_stability.py reset-network
python net_stability.py repair-dns
```

Useful options:

```bash
python net_stability.py diagnose --samples 20 --redact
python net_stability.py audit --redact
python net_stability.py measure idle --samples 20 --redact
python net_stability.py speedtest --skip-upload --redact
python net_stability.py verify --min-download-mbps 15 --redact
python net_stability.py verify --loaded --load-seconds 10 --parallel-downloads 2 --redact
python net_stability.py benchmark --load-seconds 30 --parallel-downloads 4 --download-mb 16 --redact
python net_stability.py router-diagnose --min-download-mbps 18 --redact
python net_stability.py apply --dry-run
python net_stability.py apply --system-only
python net_stability.py restore latest --npm-only
python net_stability.py repair-dns --dry-run
python net_stability.py guard --dry-run -- npm run build
```

### Build Guard

Use `guard` when npm lifecycle scripts or native compilation expose adapter or driver instability:

```bash
python net_stability.py guard -- npm run build
```

The guard lowers the child process priority and publishes a conservative worker count through standard build-tool environment variables used by node-gyp, Make, Ninja, CMake, Cargo, and libuv. It reserves one logical CPU by default so kernel network and USB work is less likely to be starved. It does **not** shape traffic, limit download speed, or change package-manager registries. Use `--jobs` or `--reserve-cpus` to override the CPU policy.

---

## Beginner UI

The desktop UI is intentionally small and cross-platform:

- Built with `tkinter`, included with most Python desktop installs.
- One runtime dependency: `websockets`, used only for M-Lab NDT7 speed tests.
- Three primary buttons: **Audit evidence first**, **Verify speed and stability**, and **Full Optimization**.
- Advanced actions (M-Lab speed test, Wi-Fi link inspection, DNS repair, idle measurement, pressure-point benchmark, router-side diagnosis, diagnostics, npm-only, reset network, restore, backups) stay visible but secondary.
- An 8-stage progress panel tracks every step of the pipeline.
- The log panel streams real command output in a dark terminal-style view.

This keeps the project easy to package later with tools such as PyInstaller or Briefcase.

---

## Pressure-Point Benchmark

Use `benchmark` when idle diagnostics look acceptable but downloads still show loss, jitter, or stutter:

```bash
python net_stability.py benchmark --redact
```

The benchmark is read-only apart from its JSON report. It collects an idle baseline, runs bounded HTTPS download traffic, keeps probing the gateway and a public target, checks DNS and HTTPS health, estimates throughput, and on Windows captures adapter statistics before and after the loaded phase.

The pressure-point classifier separates the likely failure layer:

- Gateway loss rises under load: local Wi-Fi, adapter, USB, AP, or router CPU path is suspect.
- Gateway stays clean but public loss or jitter rises: router/WAN queueing, ISP path, VPN/proxy, or remote target behavior is suspect.
- Loaded p95 latency rises sharply without gateway loss: evaluate SQM/AQM such as FQ-CoDel or CAKE at the actual bottleneck.

StableNet does not silently mutate router settings. Router queue control remains advisory unless a reviewed router integration is added later.

---

## Router-Side Diagnosis

Use `router-diagnose` when OS/client optimization is already applied but throughput or package installs still collapse:

```bash
python net_stability.py router-diagnose --min-download-mbps 18 --redact
```

The suite is read-only apart from the JSON report and intentional download test traffic. It combines:

- Idle gateway, public ICMP, DNS, and HTTPS probes.
- Bounded HTTPS download pressure while the same probes continue.
- Cross-platform Wi-Fi link evidence from Windows, Linux, or macOS.
- Adapter counters on Windows when available.

The router classifier only recommends actions when the evidence supports them:

- Overlapping 2.4 GHz AP channel or marginal signal: verify router/AP channel plan, width, band choice, and placement.
- Gateway degrades during load: inspect AP/router CPU, wireless airtime, client caps, guest-network policy, and local-link contention.
- Gateway stays clean while public latency/jitter rises: evaluate SQM/AQM such as FQ-CoDel or CAKE at the WAN bottleneck.
- DNS fails while HTTPS is not equally broken: inspect router DNS forwarding only after repeated evidence, without deleting VPN or split-DNS policy.
- Throughput misses the target with a clean first hop: inspect router rate limits, WAN link state, modem/router logs, and compare with a wired or second-device run.

Every recommendation includes expected metrics and a verification command. StableNet does not apply router settings automatically because router firmware, ISP modem modes, and household-wide policies need router-admin review.

---

## Speed Verification and Link Quality

Use `verify` when you want a clear pass/fail gate after changing hardware placement, adapter choice, router settings, or Net Stability optimization:

```bash
python net_stability.py verify --min-download-mbps 15 --redact
```

The default gate treats download below 15 Mbps as degraded. That matches the practical target for the weak-link case this project was built around: roughly 10 Mbps is bad evidence, while 15 Mbps or better is acceptable enough to continue investigating higher layers.

For raw speed measurement only:

```bash
python net_stability.py speedtest --redact
```

For local radio/link evidence only:

```bash
python net_stability.py link-quality --redact
```

The speed test uses M-Lab Locate API v2 and NDT7 WebSocket/TLS measurements. Locate access tokens are required for the test connection, but saved reports strip query strings from service URLs.

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
- Active power-plan USB selective suspend disabled when a physical USB Wi-Fi adapter is detected
- Exact USB Wi-Fi device power-management flag disabled when Windows exposes `MSPower_DeviceEnable`
- NDIS SelectiveSuspend and DeviceSleepOnDisconnect disabled on Wi-Fi adapters
- MTU set to 1500 on Wi-Fi interfaces
- Delivery Optimization P2P sharing disabled via registry
- QoS reservable bandwidth set to 0%
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

For a local editable install:

```bash
uv pip install -e .
net-stability-gui
```

If you prefer not to install it, run the files directly with `python`.

## Release Build and Distribution

Run locally to build cross-platform installers on the current machine:

```bash
python -m pip install ".[build]"
python scripts/build_release.py
```

Built outputs appear in `release-artifacts/<platform>-<arch>/`:

- `net-stability-<platform>-<arch>.tar.gz`
- `net-stability-gui-<platform>-<arch>`
- `net-stability-<platform>-<arch>`
- `checksums.txt`

To publish release assets through GitHub, tag and push the release version:

```bash
git tag v1.4.0
git push origin v1.4.0
```

The GitHub Actions workflow in `.github/workflows/release.yml` builds Windows, Linux, and macOS artifacts from tags (or via workflow dispatch), creates a combined `checksums.txt`, and uploads `.exe`, extensionless Unix executables, `.tar.gz`, and macOS `.dmg` outputs to the release.

---

## Development Checks

Basic verification:

```bash
python -m py_compile net_stability.py net_stability_ndt7.py net_stability_gui.py
python net_stability.py --version
python net_stability_gui.py --smoke
python net_stability.py verify --skip-speedtest --samples 1
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
- M-Lab NDT7 speed tests and Wi-Fi link inspection are read-only measurement surfaces; they never authorize unsafe TCP, driver, band, or offload folklore.
- The tool favors documented OS knobs and explicit diagnostics.
- Reports can be redacted before sharing.
- Router queue management is advisory only; a PC-side utility cannot directly fix queues inside an ISP modem or router.
- Some previously-denylisted tweaks (MTU, DNS, BBR, QoS) are now applied with **evidence-backed safe values** from the research paper. The `audit` command clearly lists which folklore tweaks are still denied and which are overridden with paper-backed justification.
- The `reset-network` command is intentionally kept separate from `apply` because it is a destructive operation.
- Non-evidence-backed folklore tweaks (global IPv6 disable, TCP ACK/Nagle recipes, RSS/VMQ on Wi-Fi, forced band/frequency, blanket USB suspend disable without USB Wi-Fi evidence, firewall/antivirus disable, automatic driver installation) remain permanently denylisted.

---

## License

Released under [The Unlicense](LICENSE). Use it, fork it, package it, sell it, or change it for any purpose.
