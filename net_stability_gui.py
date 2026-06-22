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

StageName = Literal["check", "backup", "npm", "system", "done"]


@dataclass(frozen=True, slots=True)
class CommandSpec:
    label: str
    args: tuple[str, ...]
    description: str


COMMANDS: Final[tuple[CommandSpec, ...]] = (
    CommandSpec(
        "Optimize connection",
        ("apply", "--yes"),
        "Back up current settings, tune npm, and apply supported OS Wi-Fi reliability settings.",
    ),
    CommandSpec(
        "Run diagnostics",
        ("diagnose", "--samples", "5", "--redact"),
        "Measure network health and save a redacted JSON report.",
    ),
    CommandSpec(
        "Optimize npm only",
        ("apply", "--npm-only", "--yes"),
        "Use only user-level npm settings. This does not require administrator rights.",
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
    "backup": "Create a restore point",
    "npm": "Tune npm for weak links",
    "system": "Apply supported Wi-Fi power settings",
    "done": "Show the result and restore path",
}

STAGE_ORDER: Final[tuple[StageName, ...]] = ("check", "backup", "npm", "system", "done")


class NetStabilityGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.events: queue.Queue[str] = queue.Queue()
        self.stage_vars = {name: tk.StringVar(value="Waiting") for name in STAGE_ORDER}
        self.status_var = tk.StringVar(value="Ready")
        self.running = False

        self.root.title(APP_TITLE)
        self.root.geometry("860x680")
        self.root.minsize(720, 560)
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
        style.configure("Primary.TButton", font=("Segoe UI", 15, "bold"), padding=(24, 18))
        style.configure("TButton", font=("Segoe UI", 10), padding=(14, 8))

    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=28)
        outer.pack(fill=tk.BOTH, expand=True)

        ttk.Label(outer, text=APP_TITLE, style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            outer,
            text="Make weak Wi-Fi and npm installs more tolerant, with automatic backups before changes.",
            style="Lead.TLabel",
            wraplength=740,
        ).pack(anchor=tk.W, pady=(6, 20))

        primary = ttk.Button(
            outer,
            text="Optimize connection",
            style="Primary.TButton",
            command=lambda: self._start(COMMANDS[0]),
        )
        primary.pack(fill=tk.X)

        ttk.Label(outer, textvariable=self.status_var, style="Lead.TLabel").pack(anchor=tk.W, pady=(14, 16))

        stage_panel = ttk.Frame(outer, style="Panel.TFrame", padding=18)
        stage_panel.pack(fill=tk.X, pady=(0, 18))
        for index, name in enumerate(STAGE_ORDER):
            ttk.Label(stage_panel, text=f"{index + 1}. {STAGE_LABELS[name]}", style="Stage.TLabel").grid(
                row=index,
                column=0,
                sticky=tk.W,
                pady=5,
            )
            ttk.Label(stage_panel, textvariable=self.stage_vars[name], style="StageStatus.TLabel").grid(
                row=index,
                column=1,
                sticky=tk.E,
                padx=(16, 0),
                pady=5,
            )
        stage_panel.columnconfigure(0, weight=1)

        advanced = ttk.Frame(outer)
        advanced.pack(fill=tk.X, pady=(0, 12))
        for column, spec in enumerate(COMMANDS[1:]):
            button = ttk.Button(advanced, text=spec.label, command=lambda item=spec: self._start(item))
            button.grid(row=0, column=column, sticky=tk.EW, padx=(0 if column == 0 else 8, 0))
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
        if "backup created" in lowered or "restore point" in lowered:
            self.events.put("STAGE:backup:Complete")
        if "npm " in lowered:
            self.events.put("STAGE:npm:Running")
        if "wi-fi" in lowered or "networkmanager" in lowered or "adapter" in lowered:
            self.events.put("STAGE:system:Running")
        if "applied." in lowered or "report saved" in lowered or "restored" in lowered:
            self.events.put("STAGE:done:Complete")

    def _drain_events(self) -> None:
        while not self.events.empty():
            event = self.events.get()
            if event == "DONE":
                self.running = False
                self.status_var.set("Ready")
                continue
            if event.startswith("STAGE:"):
                _, stage, value = event.strip().split(":", 2)
                self.stage_vars[stage].set(value)
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
    print("Primary action: Optimize connection")
    print("Advanced actions: Run diagnostics, Optimize npm only, Restore latest backup, Show backups")
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
