from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class BuildGuardPlan:
    cpu_count: int
    jobs: int
    reserved_cpus: int
    priority: str
    environment: Mapping[str, str]

    def to_report(self) -> dict[str, Any]:
        return {
            "cpu_count": self.cpu_count,
            "jobs": self.jobs,
            "reserved_cpus": self.reserved_cpus,
            "priority": self.priority,
            "environment": dict(self.environment),
            "network_bandwidth_limited": False,
        }


def create_build_guard_plan(
    *, jobs: int | None = None, reserve_cpus: int = 1
) -> BuildGuardPlan:
    cpu_count = max(1, os.cpu_count() or 1)
    reserved = min(max(0, reserve_cpus), max(0, cpu_count - 1))
    available_jobs = max(1, cpu_count - reserved)
    selected_jobs = available_jobs if jobs is None else min(max(1, jobs), available_jobs)
    values = {
        "CARGO_BUILD_JOBS": str(selected_jobs),
        "CMAKE_BUILD_PARALLEL_LEVEL": str(selected_jobs),
        "MAKEFLAGS": f"-j{selected_jobs}",
        "NINJAFLAGS": f"-j{selected_jobs}",
        "npm_config_jobs": str(selected_jobs),
        "UV_THREADPOOL_SIZE": str(selected_jobs),
    }
    priority = "below-normal" if platform.system() == "Windows" else "nice+5"
    return BuildGuardPlan(cpu_count, selected_jobs, reserved, priority, values)


def guarded_environment(
    plan: BuildGuardPlan, base: Mapping[str, str] | None = None
) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    environment.update(plan.environment)
    return environment


def _increase_niceness() -> None:
    os.nice(5)


def launch_guarded_command(
    command: Sequence[str], plan: BuildGuardPlan
) -> subprocess.Popen[Any]:
    kwargs: dict[str, Any] = {"env": guarded_environment(plan)}
    if platform.system() == "Windows":
        kwargs["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        ) | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0x00004000)
    else:
        kwargs["preexec_fn"] = _increase_niceness
    return subprocess.Popen(list(command), **kwargs)
