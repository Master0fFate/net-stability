#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import platform
import queue
import subprocess
from importlib import import_module
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Final, List, Optional

_gui_commands = import_module("modules.net_stability_gui_commands")
COMMANDS = _gui_commands.COMMANDS
STAGE_LABELS = _gui_commands.STAGE_LABELS
STAGE_ORDER = _gui_commands.STAGE_ORDER
CommandSpec = _gui_commands.CommandSpec

APP_TITLE: Final = "Net Stability"
PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
SCRIPT_PATH: Final = PROJECT_ROOT / "net_stability.py"


def packaged_cli_path() -> Path:
    executable = Path(sys.executable)
    marker = "-gui-"
    if marker in executable.name:
        cli_name = executable.name.replace(marker, "-", 1)
    else:
        suffix = ".exe" if platform.system() == "Windows" else ""
        cli_name = f"net-stability{suffix}"
    bundle_root = Path(getattr(sys, "_MEIPASS", executable.parent))
    embedded = bundle_root / cli_name
    return embedded if embedded.is_file() else executable.with_name(cli_name)


def command_for(spec: CommandSpec) -> tuple[str, ...]:
    if getattr(sys, "frozen", False):
        return (str(packaged_cli_path()), *spec.args)
    return (sys.executable, str(SCRIPT_PATH), *spec.args)


class NetStabilityGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.events: queue.Queue[str] = queue.Queue()
        self.stage_vars = {name: tk.StringVar(value="Waiting") for name in STAGE_ORDER}
        self.status_var = tk.StringVar(value="Ready")
        self.buttons: List[ttk.Button] = []
        self.process: Optional[subprocess.Popen[str]] = None
        self.running = False
        self.cancel_requested = False

        self.root.title(APP_TITLE)
        self.root.geometry("920x760")
        self.root.minsize(680, 560)
        self._configure_style()
        self._build()
        self.root.bind("<Control-l>", lambda _event: self.log.focus_set())
        self.root.after(120, self._drain_events)

    def _configure_style(self) -> None:
        self.root.configure(bg="#f6f7f9")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f6f7f9")
        style.configure(
            "Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1
        )
        style.configure(
            "TLabel", background="#f6f7f9", foreground="#172033", font=("Segoe UI", 10)
        )
        style.configure(
            "Title.TLabel", font=("Segoe UI", 24, "bold"), foreground="#172033"
        )
        style.configure("Lead.TLabel", font=("Segoe UI", 11), foreground="#40516f")
        style.configure(
            "Stage.TLabel",
            background="#ffffff",
            foreground="#172033",
            font=("Segoe UI", 10),
        )
        style.configure(
            "StageStatus.TLabel",
            background="#ffffff",
            foreground="#556987",
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "Primary.TButton", font=("Segoe UI", 14, "bold"), padding=(24, 16)
        )
        style.configure(
            "Danger.TButton", font=("Segoe UI", 12, "bold"), padding=(18, 14)
        )
        style.configure("TButton", font=("Segoe UI", 10), padding=(14, 8))
        style.configure(
            "Activity.Horizontal.TProgressbar",
            troughcolor="#e7ebf1",
            background="#2878d0",
            bordercolor="#e7ebf1",
            lightcolor="#2878d0",
            darkcolor="#2878d0",
            thickness=4,
        )
        style.map("TButton", foreground=[("disabled", "#7a8798")])

    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=28)
        outer.pack(fill=tk.BOTH, expand=True)
        self._build_header(outer)
        self._build_primary(outer)
        self._build_status(outer)
        self._build_stages(outer)
        self._build_tools(outer)
        self._build_log(outer)
        if self.buttons:
            self.buttons[0].focus_set()

    def _build_header(self, outer: ttk.Frame) -> None:
        ttk.Label(outer, text=APP_TITLE, style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            outer,
            text="Measure first. Repairs stay explicit, narrow, and reviewable.",
            style="Lead.TLabel",
            wraplength=740,
        ).pack(anchor=tk.W, pady=(6, 20))

    def _build_primary(self, outer: ttk.Frame) -> None:
        primary_frame = ttk.Frame(outer)
        primary_frame.pack(fill=tk.X)
        for spec in COMMANDS:
            if spec.primary:
                button = ttk.Button(
                    primary_frame,
                    text=spec.label,
                    style="Primary.TButton",
                    command=lambda item=spec: self._start(item),
                    takefocus=True,
                )
                button.pack(fill=tk.X, pady=4)
                self.buttons.append(button)

    def _build_status(self, outer: ttk.Frame) -> None:
        status_row = ttk.Frame(outer)
        status_row.pack(fill=tk.X, pady=(14, 12))
        ttk.Label(status_row, textvariable=self.status_var, style="Lead.TLabel").pack(
            side=tk.LEFT, anchor=tk.W
        )
        self.cancel_button = ttk.Button(
            status_row, text="Stop task", command=self._cancel, state=tk.DISABLED
        )
        self.cancel_button.pack(side=tk.RIGHT)
        self.activity = ttk.Progressbar(
            outer,
            mode="indeterminate",
            style="Activity.Horizontal.TProgressbar",
        )
        self.activity.pack(fill=tk.X, pady=(0, 12))

    def _build_stages(self, outer: ttk.Frame) -> None:
        stage_panel = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        stage_panel.pack(fill=tk.X, pady=(0, 14))
        for index, name in enumerate(STAGE_ORDER):
            ttk.Label(
                stage_panel,
                text=f"{index + 1}. {STAGE_LABELS[name]}",
                style="Stage.TLabel",
            ).grid(row=index, column=0, sticky=tk.W, pady=3)
            ttk.Label(
                stage_panel,
                textvariable=self.stage_vars[name],
                style="StageStatus.TLabel",
            ).grid(row=index, column=1, sticky=tk.E, padx=(16, 0), pady=3)
        stage_panel.columnconfigure(0, weight=1)

    def _build_tools(self, outer: ttk.Frame) -> None:
        ttk.Label(outer, text="Focused tools", style="Lead.TLabel").pack(
            anchor=tk.W, pady=(0, 6)
        )
        advanced = ttk.Frame(outer)
        advanced.pack(fill=tk.X, pady=(0, 12))
        for index, spec in enumerate(item for item in COMMANDS if not item.primary):
            row, column = divmod(index, 2)
            button = ttk.Button(
                advanced,
                text=spec.label,
                command=lambda item=spec: self._start(item),
                takefocus=True,
            )
            button.grid(
                row=row,
                column=column,
                sticky=tk.EW,
                padx=(0 if column == 0 else 8, 0),
                pady=(0 if row == 0 else 6, 0),
            )
            self.buttons.append(button)
            advanced.columnconfigure(column, weight=1)

    def _build_log(self, outer: ttk.Frame) -> None:
        log_header = ttk.Frame(outer)
        log_header.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(log_header, text="Command details", style="Lead.TLabel").pack(
            side=tk.LEFT, anchor=tk.W
        )
        self.log_visible = False
        self.log_toggle = ttk.Button(
            log_header, text="Show details", command=self._toggle_log
        )
        self.log_toggle.pack(side=tk.RIGHT)
        self.log_frame = ttk.Frame(outer, style="Panel.TFrame", padding=10)
        self.log = tk.Text(
            self.log_frame,
            height=14,
            bg="#0f172a",
            fg="#e5eefb",
            insertbackground="#e5eefb",
            relief=tk.FLAT,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state=tk.DISABLED,
            takefocus=True,
        )
        scroll = ttk.Scrollbar(
            self.log_frame, orient=tk.VERTICAL, command=self.log.yview
        )
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _toggle_log(self) -> None:
        if self.log_visible:
            self.log_frame.pack_forget()
            self.log_toggle.configure(text="Show details")
        else:
            self.log_frame.pack(fill=tk.BOTH, expand=True)
            self.log_toggle.configure(text="Hide details")
        self.log_visible = not self.log_visible

    def _start(self, spec: CommandSpec) -> None:
        if self.running:
            self._write_log("A task is already running.\n")
            return
        self.running = True
        self.cancel_requested = False
        self._set_controls_state(tk.DISABLED)
        self.cancel_button.configure(state=tk.NORMAL)
        self.activity.start(12)
        self.status_var.set(spec.description)
        self._reset_stages()
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)
        thread = threading.Thread(target=self._run_command, args=(spec,), daemon=True)
        thread.start()

    def _run_command(self, spec: CommandSpec) -> None:
        command = command_for(spec)
        self.events.put(f"$ {' '.join(command)}\n")
        self.events.put("STAGE:check:Running")
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        return_code = 1
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            self.process = process
            assert process.stdout is not None
            for line in process.stdout:
                self.events.put(line)
                self._infer_stage(line)
            return_code = process.wait()
        except OSError as exc:
            self.events.put(f"Unable to start the task: {exc}\n")
        finally:
            self.events.put(
                "STAGE:done:Complete"
                if return_code == 0
                else "STAGE:done:Needs attention"
            )
            self.events.put(f"\nFinished with exit code {return_code}.\n")
            self.events.put(f"DONE:{return_code}:{spec.label}")

    def _cancel(self) -> None:
        process = self.process
        if not self.running or process is None or process.poll() is not None:
            return
        self.cancel_requested = True
        self.status_var.set("Stopping task…")
        process.terminate()
        self._write_log("\nStop requested.\n")

    def _infer_stage(self, line: str) -> None:
        lowered = line.lower()
        audit_markers = (
            "collecting",
            "measurement summary",
            "capability matrix",
            "m-lab",
            "ndt7",
            "verification status",
            "router-side diagnosis",
            "pressure-point interpretation",
        )
        system_markers = (
            "wi-fi",
            "ethernet",
            "link inspector",
            "adapter",
            "networkmanager",
            "dns policy",
            "resolver",
            "route",
            "proxy",
            "vpn",
        )
        if any(marker in lowered for marker in audit_markers):
            self.events.put("STAGE:check:Complete")
            self.events.put("STAGE:audit:Running")
        if any(marker in lowered for marker in system_markers):
            self.events.put("STAGE:check:Complete")
            self.events.put("STAGE:system:Running")
        if "backup created" in lowered or "restore point" in lowered:
            self.events.put("STAGE:backup:Complete")
        if "report saved" in lowered or "restored" in lowered:
            self.events.put("STAGE:done:Complete")

    def _drain_events(self) -> None:
        while not self.events.empty():
            event = self.events.get()
            if event.startswith("DONE:"):
                _, return_code, label = event.split(":", 2)
                self.running = False
                self.process = None
                self.activity.stop()
                self.activity.configure(value=0)
                self.cancel_button.configure(state=tk.DISABLED)
                succeeded = return_code == "0"
                self._finalize_stages(succeeded, self.cancel_requested)
                if self.cancel_requested:
                    self.status_var.set("Task stopped")
                elif succeeded:
                    self.status_var.set(f"{label} complete")
                else:
                    self.status_var.set(f"{label} needs attention")
                self.cancel_requested = False
                self._set_controls_state(tk.NORMAL)
                continue
            if event.startswith("STAGE:"):
                parts = event.strip().split(":", 2)
                if len(parts) == 3:
                    _, stage, value = parts
                    if stage in self.stage_vars:
                        self.stage_vars[stage].set(value)
                continue
            self._write_log(event)
        self.root.after(120, self._drain_events)

    def _reset_stages(self) -> None:
        for name in STAGE_ORDER:
            self.stage_vars[name].set("Waiting")

    def _finalize_stages(self, succeeded: bool, cancelled: bool) -> None:
        for value in self.stage_vars.values():
            current = value.get()
            if current == "Complete":
                continue
            if cancelled:
                value.set("Stopped" if current == "Running" else "Not reached")
            elif succeeded:
                value.set("Complete" if current == "Running" else "Not needed")
            else:
                value.set("Needs attention" if current == "Running" else "Not reached")
        self.stage_vars["done"].set(
            "Stopped" if cancelled else "Complete" if succeeded else "Needs attention"
        )

    def _write_log(self, text: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text)
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _set_controls_state(self, state: str) -> None:
        for button in self.buttons:
            button.configure(state=state)


def smoke_check() -> int:
    cli_target = packaged_cli_path() if getattr(sys, "frozen", False) else SCRIPT_PATH
    if not cli_target.is_file():
        print(f"Missing CLI entry point: {cli_target}", file=sys.stderr)
        return 1
    primary = [command.label for command in COMMANDS if command.primary]
    tools = [command.label for command in COMMANDS if not command.primary]
    print(f"{APP_TITLE} GUI smoke check passed on {platform.system()}.")
    print(f"Primary action: {', '.join(primary)}")
    print(f"Tools: {', '.join(tools)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the Net Stability desktop UI.")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="verify GUI assets without opening a window",
    )
    args = parser.parse_args()
    if args.smoke:
        return smoke_check()
    root = tk.Tk()
    NetStabilityGui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
