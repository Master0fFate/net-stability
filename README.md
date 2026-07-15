# Net Stability

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-websockets-2f855a)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-4c51bf)
![License](https://img.shields.io/badge/license-Unlicense-brightgreen)

Net Stability is a diagnostic-first desktop and CLI tool for investigating unreliable Ethernet, Wi-Fi, DNS, router, WAN, and package-download paths. It measures before it recommends, keeps router changes advisory, and avoids blanket “optimize everything” operations.

It supports Windows, Linux, and macOS, including macOS on Apple Silicon when the Python/runtime and native tools are available. **iOS and iPadOS are not supported:** this project is a desktop Python application that relies on OS command-line diagnostics and Tkinter.

## Operating model

- **Run diagnostics** is the primary GUI action and is read-only apart from report files and requested test traffic.
- **Review recommended changes** shows the exact evidence-gated system actions available for the current platform without changing settings.
- **Apply recommended changes** is a separate, confirmed system-only action. It creates a restore point first, never acts as a blanket optimizer, and cannot be stopped safely after execution begins.
- Restore manifests are captured before an explicit mutation and record the original state needed for rollback where the OS exposes it.
- Router, AP, ISP, VPN, and physical-placement recommendations remain advisory; the tool does not change router settings.
- Reports support identifier and token redaction before sharing.

The normal system policy is intentionally narrow:

- Windows may repair abnormal TCP receive-window auto-tuning and invalid DNS policy state after health checks identify a repairable condition.
- Linux and macOS normal apply performs no automatic system mutation; configured DNS, kernel buffers, congestion control, ring sizes, IRQ policy, and persistent sysctl files are preserved. Cache repair remains a separate explicit command.
- npm weak-link settings are a separate, explicit opt-in user configuration profile with snapshot-backed restore.
- Fixed MTU, QoS, retransmission registry defaults, blanket USB selective suspend changes, BBR/fq_codel, fixed TCP buffers, public-DNS replacement, and undocumented Wi-Fi or driver tweaks are not default optimization actions.

## What it measures

- Ethernet carrier, speed, duplex, autonegotiation, media state, and exposed error/drop counters.
- Wi-Fi signal/noise/SNR when exposed, band/channel/width/PHY, receive/transmit rates, and platform link reports.
- Gateway and public latency, loss, jitter, DNS and HTTPS health, loaded latency, and bounded goodput.
- IPv4/IPv6 path evidence, default route, PMTU symptoms, VPN/proxy context, and interface ownership when exposed by the operating system.
- Router-side symptoms such as local-link degradation, WAN queue pressure, DNS forwarding failures, or throughput ceilings, with confidence-calibrated manual recommendations.

## Quick start

Run the GUI directly:

```bash
python net_stability_gui.py
```

The compact GUI provides one primary action and a small Tools section:

- **Run diagnostics** — read-only evidence collection.
- **Review recommended changes** — dry-run, no settings changed.
- **Apply recommended changes** — confirmed, snapshot-backed system repairs only; npm settings stay unchanged.
- **View restore points** — inspect snapshots and use the CLI for an explicit restore.
- **Verify speed and stability** — loaded latency and optional M-Lab NDT7 goodput.
- **Inspect Ethernet and Wi-Fi link** — platform link inventory.
- **Diagnose router side** — bounded loaded-path classification.
- **Review DNS repair** — read-only preview of the platform DNS repair plan. Confirmed system apply may repair evidence-gated Windows DNS policy; Linux and macOS cache repair remains an explicit CLI action.

Use `python net_stability_gui.py --smoke` to verify the GUI entry point without opening a window.

## Command line

The GUI calls the same CLI:

```bash
python net_stability.py diagnose --redact
python net_stability.py audit --redact
python net_stability.py link-quality --redact
python net_stability.py verify --redact
python net_stability.py benchmark --redact
python net_stability.py router-diagnose --redact
python net_stability.py apply --dry-run --system-only --no-restart
python net_stability.py apply --npm-only
python net_stability.py repair-dns --dry-run
python net_stability.py list-backups
python net_stability.py restore latest
```

The GUI's confirmed apply action uses the same system-only CLI path shown by its dry run. Use `--npm-only` from the CLI for the separate user-level npm profile. Windows system repair requires an Administrator process; Linux authorization may require a separate system-only invocation. npm changes are refused under `sudo` so root's configuration is not changed accidentally.

## Verification and loaded-path diagnosis

Use `verify` after changing hardware placement, adapter choice, router settings, or cabling:

```bash
python net_stability.py verify --min-download-mbps 15 --redact
```

Use `link-quality` for local Ethernet and Wi-Fi evidence, and `router-diagnose` when idle behavior looks healthy but downloads or package installs fail under load. The benchmark uses bounded HTTPS traffic and concurrent probes; it does not claim that one short run proves an ISP limit. Recommendations identify the evidence, confidence, expected metric, and manual verification step.

M-Lab NDT7 uses the Locate API v2 and WebSocket/TLS measurements when requested. Saved reports strip access-token query strings.

## Build Guard

`guard` is a qualified mitigation for builds that compete with network or USB driver work:

```bash
python net_stability.py guard -- npm run build
```

It can lower child-process priority and publish conservative worker-count environment variables for common build tools. This may leave CPU headroom for system work, but it does not prove a network fix, shape traffic, cap bandwidth, change registries, or repair a driver.

## Restore points and reset

Backups are stored outside the repository:

| OS | Location |
| --- | --- |
| Windows | `%LOCALAPPDATA%\\NetStability\\backups` |
| macOS | `~/Library/Application Support/NetStability/backups` |
| Linux | `$XDG_STATE_HOME/netstability/backups` or `~/.local/state/netstability/backups` |

```bash
python net_stability.py list-backups
python net_stability.py restore latest
```

`reset-network` is a separate, disruptive troubleshooting command. It may reset OS network-stack state and should only be used after review with the expected reboot/reconnect impact understood. macOS reset is limited to transient route/DNS/mDNS cache flushing and does not delete untracked Apple configuration files.

## Platform notes

### Windows

Read-only diagnostics use documented `netsh`, PowerShell, adapter, DNS-policy, and link-report surfaces. The conservative repair path can restore abnormal receive-window auto-tuning. DNS repair removes an invalid sentinel only when an existing valid resolver can be preserved exactly; invalid-only configurations remain advisory. Resolver changes are snapshot-backed and restore the exact original list. It does not set a fixed MTU, overwrite DNS for speed, disable QoS, set retransmission folklore defaults, or blanket-disable USB power management.

### Linux

Diagnostics use available `ip`, `nmcli`, `iw`, `ethtool`, `resolvectl`, and route surfaces. Ethernet reports include speed/duplex/carrier and exposed counters; Wi-Fi reports include NetworkManager and `iw` evidence. Normal system apply preserves NetworkManager, resolver configuration, kernel TCP policy, ring sizes, IRQ state, and persistent sysctl files. DNS troubleshooting flushes caches without replacing configured servers.

### macOS

Diagnostics use `networksetup`, `system_profiler`, `ifconfig`, route, and cache tools available on the host. Ethernet media and Wi-Fi radio evidence are reported when exposed. Normal system apply does not write fixed TCP buffers, overwrite `/etc/sysctl.conf`, replace DNS servers, or delete plist configuration. DNS troubleshooting flushes transient caches only.

## Packaging and release staging

Install locally in editable mode if desired:

```bash
python -m pip install -e .
net-stability-gui
```

Build staging artifacts on the current native host:

```bash
python -m pip install ".[build]"
python scripts/build_release.py
```

The script stages platform/architecture-specific archives and executable bundles under `release-artifacts/`. The macOS target is Apple Silicon (`arm64`): its DMG contains a real `Net Stability` `.app` bundle plus a separate CLI executable. No Intel macOS artifact is currently staged. Native GitHub Actions runners are required for trustworthy outputs. Signing, notarization, and Windows code signing require external certificates/secrets and are not claimed by local staging. Release publication is intentionally a separate reviewed operation.

## Source layout

The repository root contains only the stable CLI and GUI compatibility launchers. Application code, diagnostics, policies, platform integrations, and GUI implementation live in the `modules/` package. Keeping the launchers at the root preserves existing commands and packaged entry points while preventing implementation modules from accumulating beside project configuration files.

## Development checks

```bash
python -m unittest discover -s tests -v
python -m compileall -q net_stability.py net_stability_gui.py modules scripts
python net_stability.py --version
python net_stability_gui.py --smoke
```

## Safety boundaries

Net Stability is not a universal optimizer and does not promise that every slow download is caused by the host. It reports uncertainty when command surfaces are unavailable, keeps mutations narrow and reviewable, preserves configured resolver and router policy, and treats physical, VPN/proxy, driver, AP, WAN, and ISP causes as separate hypotheses. No iOS application or iPhone/iPad support is provided by this desktop architecture.

## License

Released under [The Unlicense](LICENSE). Use it, fork it, package it, sell it, or change it for any purpose.
