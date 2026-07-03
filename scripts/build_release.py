#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_FILE = PROJECT_ROOT / "pyproject.toml"
ASSET_DIR = PROJECT_ROOT / "assets" / "icons"
ICON_PNG = ASSET_DIR / "net_stability.png"
ICON_ICO = ASSET_DIR / "net_stability.ico"
ICON_ICNS = ASSET_DIR / "net_stability.icns"
VERSION_INFO = ASSET_DIR / "net_stability_version_info.txt"
OUTPUT_ROOT = PROJECT_ROOT / "release-artifacts"


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def project_metadata() -> tuple[str, str, str]:
    data = tomllib.loads(PROJECT_FILE.read_text(encoding="utf-8"))
    project = data.get("project", {})
    name = str(project.get("name", "net-stability"))
    version = str(project.get("version", "1.0.0"))
    authors = project.get("authors", [])
    author = str(authors[0].get("name")) if authors else "Master0fFate"
    return name, version, author


def draw_icon(
    size: int, background: tuple[int, int, int], accent: tuple[int, int, int]
) -> Image.Image:
    image = Image.new("RGBA", (size, size), (*background, 255))
    draw = ImageDraw.Draw(image)
    cx = size // 2
    cy = size // 2
    pad = int(size * 0.09)
    for i in range(0, int(size * 0.20)):
        a = max(18, 140 - i * 2)
        d = pad + i
        draw.ellipse(
            (d, d, size - d, size - d),
            outline=(accent[0], accent[1], accent[2], a),
            width=max(1, int(size * 0.012)),
        )

    nodes = [(0.26, 0.32), (0.76, 0.26), (0.74, 0.74)]
    points: list[tuple[int, int]] = [
        (int(cx + (x - 0.5) * size), int(cy + (y - 0.5) * size)) for x, y in nodes
    ]
    stroke = max(2, size // 40)

    for i in range(len(points) - 1):
        draw.line(
            (points[i][0], points[i][1], points[i + 1][0], points[i + 1][1]),
            fill=(140, 238, 255, 230),
            width=stroke,
        )
    draw.line(
        (points[0][0], points[0][1], points[2][0], points[2][1]),
        fill=(140, 238, 255, 230),
        width=stroke,
    )

    node_radius = max(3, size // 18)
    for x, y in points:
        fill = (238, 250, 255, 250)
        draw.ellipse(
            (x - node_radius, y - node_radius, x + node_radius, y + node_radius),
            fill=fill,
            outline=(255, 255, 255, 255),
        )

    center_radius = max(4, size // 16)
    draw.ellipse(
        (
            cx - center_radius,
            cy - center_radius,
            cx + center_radius,
            cy + center_radius,
        ),
        fill=(250, 250, 250, 255),
    )
    draw.arc(
        (size * 0.24, size * 0.24, size * 0.76, size * 0.76),
        0,
        330,
        fill=accent + (255,),
        width=stroke,
    )
    return image


def ensure_icons() -> tuple[Path, Path, Path]:
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    base = draw_icon(512, (8, 24, 58), (78, 206, 255))
    base.save(ICON_PNG, format="PNG")

    icon_sizes = [256, 128, 96, 64, 48, 32, 24, 16]
    rendered = [draw_icon(size, (8, 24, 58), (78, 206, 255)) for size in icon_sizes]
    rendered[0].save(
        ICON_ICO,
        format="ICO",
        append_images=rendered[1:],
        sizes=[(s, s) for s in icon_sizes],
    )

    try:
        base.save(ICON_ICNS, format="ICNS")
    except Exception:
        if not ICON_ICNS.exists():
            shutil.copy2(ICON_PNG, ICON_PNG.with_name("net_stability.icns"))

    return ICON_PNG, ICON_ICO, ICON_ICNS


def write_version_file(version: str, author: str) -> Path:
    major, minor, patch = version.split(".")
    content = "\n".join(
        [
            "# UTF-8",
            "VSVersionInfo(",
            "  ffi=FixedFileInfo(",
            f"    filevers=({major}, {minor}, {patch}, 0),",
            f"    prodvers=({major}, {minor}, {patch}, 0),",
            "    mask=0x3f,",
            "    flags=0x0,",
            "    OS=0x40004,",
            "    fileType=0x1,",
            "    subtype=0x0,",
            "    date=(0, 0)",
            "  ),",
            "  kids=[",
            "    StringFileInfo(",
            "      [",
            "        StringTable('040904B0',",
            "          [",
            f"            StringStruct('CompanyName', '{author}'),",
            "            StringStruct('FileDescription', 'Net Stability'),",
            f"            StringStruct('FileVersion', '{version}.0'),",
            "            StringStruct('InternalName', 'net_stability'),",
            f"            StringStruct('LegalCopyright', 'Copyright © 2026 {author}'),",
            "            StringStruct('OriginalFilename', 'net-stability.exe'),",
            "            StringStruct('ProductName', 'Net Stability'),",
            f"            StringStruct('ProductVersion', '{version}.0'),",
            "            StringStruct('Comments', 'Built with PyInstaller')",
            "          ]",
            "        )",
            "      ]",
            "    ),",
            "    VarFileInfo([VarStruct('Translation', [1033, 1200])])",
            "  ]",
            ")",
        ]
    )
    VERSION_INFO.write_text(content, encoding="utf-8")
    return VERSION_INFO


def normalize_platform(platform_name: str) -> str:
    value = platform_name.lower()
    if value == "darwin":
        return "macos"
    return value


def normalize_arch() -> str:
    value = os.environ.get(
        "RUNNER_ARCH", os.environ.get("PROCESSOR_ARCHITECTURE", "")
    ).lower()
    if not value:
        value = platform.machine().lower()
    if value in {"amd64", "x64"}:
        return "x86_64"
    if value in {"arm64", "aarch64"}:
        return "arm64"
    if value.startswith("x86"):
        return "x86_64"
    return value or "x86_64"


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(items: Iterable[Path], output: Path) -> None:
    rows = [
        f"{sha256_path(item)}\t{item.name}" for item in sorted(items) if item.is_file()
    ]
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _build_onefile(
    entry: Path,
    name: str,
    *,
    icon: Path,
    windowed: bool,
    system: str,
    version: str,
    author: str,
    out_dir: Path,
) -> Path:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        name,
        "--distpath",
        str(out_dir),
        "--specpath",
        str(out_dir / "specs"),
        "--workpath",
        str(out_dir / "build"),
        "--icon",
        str(icon),
        "--collect-submodules",
        "websockets",
        str(entry),
    ]
    if windowed:
        cmd.append("--windowed")
    if system == "windows":
        cmd += ["--version-file", str(write_version_file(version, author))]

    run(cmd)
    return out_dir / f"{name}.exe" if system == "windows" else out_dir / name


def package_bundle(
    artifacts: list[Path], root: Path, version: str, system: str, arch: str
) -> list[Path]:
    all_files = []
    for artifact in artifacts:
        destination = root / artifact.name
        if artifact.resolve() == destination.resolve():
            all_files.append(destination)
            continue
        shutil.copy2(artifact, destination)
        all_files.append(destination)

    if system in {"linux", "macos", "windows"}:
        archive = root / f"net-stability-{version}-{system}-{arch}.tar.gz"
        if archive.exists():
            archive.unlink()
        with tarfile.open(archive, "w:gz") as tar:
            for artifact in all_files:
                tar.add(artifact, arcname=artifact.name)
        all_files.append(archive)

    checksum = root / "checksums.txt"
    write_checksums(all_files, checksum)
    all_files.append(checksum)
    return all_files


def build_release(system_override: str | None, version: str, author: str) -> list[Path]:
    system = normalize_platform(system_override or sys.platform)
    if system.startswith("win"):
        system = "windows"
    elif system.startswith("linux"):
        system = "linux"
    elif system.startswith("darwin"):
        system = "macos"

    arch = normalize_arch()
    output_dir = OUTPUT_ROOT / f"{system}-{arch}"
    if output_dir.exists():
        for path in output_dir.iterdir():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()

    icon_png, icon_ico, icon_icns = ensure_icons()
    icon = icon_ico if system == "windows" else icon_png
    if system == "macos" and icon_icns.exists():
        icon = icon_icns

    outputs = [
        _build_onefile(
            PROJECT_ROOT / "net_stability.py",
            f"net-stability-{system}-{arch}",
            icon=icon,
            windowed=False,
            system=system,
            version=version,
            author=author,
            out_dir=output_dir,
        ),
        _build_onefile(
            PROJECT_ROOT / "net_stability_gui.py",
            f"net-stability-gui-{system}-{arch}",
            icon=icon,
            windowed=(system == "windows"),
            system=system,
            version=version,
            author=author,
            out_dir=output_dir,
        ),
    ]

    return package_bundle(outputs, output_dir, version, system, arch)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build stable Net Stability binaries.")
    parser.add_argument(
        "--platform",
        choices=("auto", "linux", "windows", "darwin", "macos"),
        default="auto",
    )
    parser.add_argument("--version", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    _, version, author = project_metadata()
    version = args.version or version
    system = None if args.platform == "auto" else args.platform
    artifacts = build_release(system, version, author)
    for artifact in artifacts:
        print(artifact.as_posix())


if __name__ == "__main__":
    main()
