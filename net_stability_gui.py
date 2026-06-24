#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import platform
import queue
import subprocess
import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import ttk
from typing import Final, Literal

APP_TITLE: Final = "Net Stability"
SCRIPT_PATH: Final = Path(__file__).with_name("net_stability.py")

StageName = Literal["check", "audit", "backup", "npm", "system", "tuning", "reset", "done"]


@dataclass(frozen=True, slots=True)
class CommandSpec:
    label: str
    args: tuple[str, ...]
    description: str
    primary: bool = False


COMMANDS: Final[tuple[CommandSpec, ...]] = (
    CommandSpec(
        "Audit evidence first",
        ("audit", "--redact"),
        "Create a read-only evidence, capability, and safety-policy report.",
        primary=True,
    ),
    CommandSpec(
        "Full Optimization",
        ("apply", "--yes"),
        "Back up and apply ALL supported reliability, TCP/IP, and DNS optimizations.",
        primary=True,
    ),
    CommandSpec(
        "Measure idle baseline",
        ("measure", "idle", "--samples", "5", "--redact"),
        "Collect baseline gateway, remote, DNS, and HTTPS measurements.",
    ),
    CommandSpec(
        "Run full diagnostics",
        ("diagnose", "--samples", "5", "--redact"),
        "Measure network health and save a redacted JSON report.",
    ),
    CommandSpec(
        "Optimize connection",
        ("apply", "--system-only", "--yes"),
        "Apply system-level OS reliability and tuning settings (requires admin).",
    ),
    CommandSpec(
        "Optimize npm only",
        ("apply", "--npm-only", "--yes"),
        "Use only user-level npm settings. Does not require administrator rights.",
    ),
    CommandSpec(
        "Reset Network Stack",
        ("reset-network", "--yes"),
        "Reset TCP/IP, Winsock, and DNS to OS defaults (requires reboot).",
    ),
    CommandSpec(
        "Restore latest backup",
        ("restore", "latest", "--yes"),
        "Undo the most recent Net Stability change set.",
    ),
    CommandSpec(
        "Show backups",
        ("list-backups",),
        "List restore points created by this tool.",
    ),
)

STAGE_LABELS: Final[dict[StageName, str]] = {
    "check": "Check the connection and platform",
    "audit": "Map evidence and safe capabilities",
    "backup": "Create a restore point",
    "npm": "Tune npm for weak links",
    "system": "Apply OS Wi-Fi power and adapter settings",
    "tuning": "Apply TCP/IP, DNS, and buffer tuning",
    "reset": "Reset network stack",
    "done": "Show the result and restore path",
}

STAGE_ORDER: Final[tuple[StageName, ...]] = ("check", "audit", "backup", "npm", "system", "tuning", "reset", "done")


class NetStabilityGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.events: queue.Queue[str] = queue.Queue()
        self.stage_vars = {name: tk.StringVar(value="Waiting") for name in STAGE_ORDER}
        self.status_var = tk.StringVar(value="Ready")
        self.running = False

        self.root.title(APP_TITLE)
        self.root.geometry("860+780")
        self.root.minsize(720, 600)
        self._configure_style()
        self._build()
        self.root.after(120, self._drain_events)

    def _configure_style(self) -> None:
        self.root.configure(bg="#f6f7f9")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f6f7f9")
        style.configure("Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f6f7f9", foreground="#172033", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 24, "bold"), foreground="#172033")
        style.configure("Lead.TLabel", font=("Segoe UI", 11), foreground="#40516f")
        style.configure("Stage.TLabel", background="#ffffff", foreground="#172033", font=("Segoe UI", 10))
        style.configure("StageStatus.TLabel", background="#ffffff", foreground="#556987", font=("Segoe UI", 10, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 14, "bold"), padding=(24, 16))
        style.configure("Danger.TButton", font=("Segoe UI", 12, "bold"), padding=(18, 14))
        style.configure("TButton", font=("Segoe UI", 10), padding=(14, 8))

    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=28)
        outer.pack(fill=tk.BOTH, expand=True)

        ttk.Label(outer, text=APP_TITLE, style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            outer,
            text="Diagnose the failing layer first, then apply only reversible changes with restore points.",
            style="Lead.TLabel",
            wraplength=740,
        ).pack(anchor=tk.W, pady=(6, 20))

        primary_frame = ttk.Frame(outer)
        primary_frame.pack(fill=tk.X)
        for index, spec in enumerate(COMMANDS):
            if not spec.primary:
                continue
            btn = ttk.Button(
                primary_frame,
                text=spec.label,
                style="Primary.TButton",
                command=lambda item=spec: self._start(item),
            )
            btn.pack(fill=tk.X, pady=(4, 4))

        ttk.Label(outer, textvariable=self.status_var, style="Lead.TLabel").pack(anchor=tk.W, pady=(14, 12))

        stage_panel = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        stage_panel.pack(fill=tk.X, pady=(0, 14))
        for index, name in enumerate(STAGE_ORDER):
            ttk.Label(stage_panel, text=f"{index + 1}. {STAGE_LABELS[name]}", style="Stage.TLabel").grid(
                row=index,
                column=0,
                sticky=tk.W,
                pady=3,
            )
            ttk.Label(stage_panel, textvariable=self.stage_vars[name], style="StageStatus.TLabel").grid(
                row=index,
                column=1,
                sticky=tk.E,
                padx=(16, 0),
                pady=3,
            )
        stage_panel.columnconfigure(0, weight=1)

        advanced_header = ttk.Label(
            outer, text="Advanced actions", style="Lead.TLabel"
        )
        advanced_header.pack(anchor=tk.W, pady=(0, 6))

        advanced = ttk.Frame(outer)
        advanced.pack(fill=tk.X, pady=(0, 12))
        non_primary = [spec for spec in COMMANDS if not spec.primary]
        grid_cols = 3
        for index, spec in enumerate(non_primary):
            row = index // grid_cols
            column = index % grid_cols
            style = "Danger.TButton" if "Reset" in spec.label else "TButton"
            button = ttk.Button(
                advanced, text=spec.label, style=style, command=lambda item=spec: self._start(item)
            )
            button.grid(
                row=row,
                column=column,
                sticky=tk.EW,
                padx=(0 if column == 0 else 8, 0),
                pady=(0 if row == 0 else 6, 0),
            )
            advanced.columnconfigure(column, weight=1)

        log_frame = ttk.Frame(outer, style="Panel.TFrame", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log = tk.Text(
            log_frame,
            height=14,
            bg="#0f172a",
            fg="#e5eefb",
            insertbackground="#e5eefb",
            relief=tk.FLAT,
            wrap=tk.WORD,
            font=("Consolas", 10),
        )
        scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _start(self, spec: CommandSpec) -> None:
        if self.running:
            self._write_log("A task is already running.\n")
            return
        self.running = True
        self.status_var.set(spec.description)
        self._reset_stages()
        self.log.delete("1.0", tk.END)
        thread = threading.Thread(target=self._run_command, args=(spec,), daemon=True)
        thread.start()

    def _run_command(self, spec: CommandSpec) -> None:
        command = (sys.executable, str(SCRIPT_PATH), *spec.args)
        self.events.put(f"$ {' '.join(command)}\n")
        self.events.put("STAGE:check:Running")
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        assert process.stdout is not None
        for line in process.stdout:
            self.events.put(line)
            self._infer_stage(line)
        return_code = process.wait()
        self.events.put("STAGE:done:Complete" if return_code == 0 else "STAGE:done:Needs attention")
        self.events.put(f"\nFinished with exit code {return_code}.\n")
        self.events.put("DONE")

    def _infer_stage(self, line: str) -> None:
        lowered = line.lower()
        if "evidence audit" in lowered or "capability matrix" in lowered:
            self.events.put("STAGE:audit:Running")
        if "backup created" in lowered or "restore point" in lowered:
            self.events.put("STAGE:backup:Complete")
        if "npm " in lowered and "reset" not in lowered:
            self.events.put("STAGE:npm:Running")
        if "wi-fi" in lowered or "networkmanager" in lowered or "adapter" in lowered or "powersave" in lowered:
            self.events.put("STAGE:system:Running")
        if "mtu" in lowered or "ecn" in lowered or "delivery optimization" in lowered or "qos" in lowered:
            self.events.put("STAGE:tuning:Running")
        if "lso" in lowered or "tcp retrans" in lowered or "sysctl" in lowered or "ring buffer" in lowered:
            self.events.put("STAGE:tuning:Running")
        if "irqbalance" in lowered or "dns set" in lowered or "tcp buffer" in lowered:
            self.events.put("STAGE:tuning:Running")
        if "network stack" in lowered or "netsh int ip reset" in lowered or "winsock" in lowered:
            self.events.put("STAGE:reset:Running")
        if "route -n flush" in lowered or "systemctl restart networkmanager" in lowered:
            self.events.put("STAGE:reset:Running")
        if "applied." in lowered or "report saved" in lowered or "restored" in lowered:
            self.events.put("STAGE:done:Complete")
        if "reset completed" in lowered or "reboot is recommended" in lowered:
            self.events.put("STAGE:done:Complete")

    def _drain_events(self) -> None:
        while not self.events.empty():
            event = self.events.get()
            if event == "DONE":
                self.running = False
                self.status_var.set("Ready")
                continue
            if event.startswith("STAGE:"):
                try:
                    _, stage, value = event.strip().split(":", 2)
                    if stage in self.stage_vars:
                        self.stage_vars[stage].set(value)
                except ValueError:
                    pass
                continue
            self._write_log(event)
        self.root.after(120, self._drain_events)

    def _reset_stages(self) -> None:
        for name in STAGE_ORDER:
            self.stage_vars[name].set("Waiting")

    def _write_log(self, text: str) -> None:
        self.log.insert(tk.END, text)
        self.log.see(tk.END)


def smoke_check() -> int:
    if not SCRIPT_PATH.is_file():
        print(f"Missing CLI script: {SCRIPT_PATH}", file=sys.stderr)
        return 1
    print(f"{APP_TITLE} GUI smoke check passed on {platform.system()}.")
    print("Primary actions: Audit evidence first, Full Optimization")
    print(
        "Advanced actions: Measure idle baseline, Run full diagnostics, Optimize connection, "
        "Optimize npm only, Reset Network Stack, Restore latest backup, Show backups"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the Net Stability desktop UI.")
    parser.add_argument("--smoke", action="store_true", help="verify GUI assets without opening a window")
    args = parser.parse_args()
    if args.smoke:
        return smoke_check()
    root = tk.Tk()
    NetStabilityGui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
