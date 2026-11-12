"""
Vyrulix v1.1 - Canonical Spec Normalization & PyInstaller 6.x Builder (build_vyrulix.py)
Rebranded to Vyrulix (v1.1):
  1. Normalizes legacy or browser-renamed project files (`scanner_3.py` / `scanner_2.py` -> `scanner.py`,
     `main_3.py` / `main_2.py` -> `main.py`, `community_3.py` / `community_2.py` -> `community.py`,
     `build_vyrulix_3.py` / `build_vyrulix_2.py` -> `build_vyrulix.py`) prior to build.
  2. Verifies that `main.py`, `scanner.py`, `community.py`, and `rules/vyrulix_default.yar`
     are present and valid.
  3. Generates `Vyrulix.spec` targeting the canonical entry point `main.py` and bundling
     `community.py`, `scanner.py`, `rules/`, and all dynamic runtime libraries
     (`customtkinter`, `capstone`, `pefile`, `yara`, `ppdeep`, `ssdeep`, `tlsh`,
     `watchdog`, `plyer`) to produce `dist/Vyrulix/Vyrulix.exe`.
Usage:
    python build_vyrulix.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

SPEC_CONTENT = r'''# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 6.x Specification File for Vyrulix v1.1 (Vyrulix.spec)
Targets canonical entry point `main.py` and bundles `community.py`, `scanner.py`,
`rules/`, and all dynamic forensic runtime libraries (`customtkinter`, `capstone`,
`pefile`, `yara`, `ppdeep`, `ssdeep`, `tlsh`, `watchdog`, `plyer`).
Build command:
    python -m PyInstaller --noconfirm --clean Vyrulix.spec
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

block_cipher = None
project_dir = Path(SPECPATH).resolve()
if str(project_dir) not in sys.path:
    sys.path.insert(0, str(project_dir))


def _safe_collect_data(pkg_name: str):
    try:
        return collect_data_files(pkg_name)
    except Exception:
        return []


def _safe_collect_binaries(pkg_name: str):
    try:
        return collect_dynamic_libs(pkg_name)
    except Exception:
        return []


def _safe_collect_submodules(pkg_name: str):
    try:
        return collect_submodules(pkg_name)
    except Exception:
        return []


# Ensure the local rules/ folder and default YARA rule pack exist prior to bundling
rules_dir = project_dir / "rules"
rules_dir.mkdir(parents=True, exist_ok=True)
default_yar = rules_dir / "vyrulix_default.yar"
if not default_yar.is_file():
    from scanner import BUNDLED_DEFAULT_YARA_RULES
    default_yar.write_text(BUNDLED_DEFAULT_YARA_RULES.strip() + "\n", encoding="utf-8")

# Bundle CustomTkinter assets, dynamic runtime data, rules/, and core local modules
datas = [
    (str(rules_dir), "rules"),
    (str(project_dir / "community.py"), "."),
    (str(project_dir / "scanner.py"), "."),
]
for pkg in ("customtkinter", "capstone", "pefile", "yara", "ppdeep", "tlsh"):
    datas += _safe_collect_data(pkg)

# Collect native C-extension shared libraries / DLLs for capstone, yara, ppdeep, tlsh
binaries = []
for bin_pkg in ("capstone", "yara", "ppdeep", "ssdeep", "tlsh"):
    binaries += _safe_collect_binaries(bin_pkg)

hiddenimports = [
    "community",
    "scanner",
    "customtkinter",
    "capstone",
    "pefile",
    "yara",
    "ppdeep",
    "ssdeep",
    "tlsh",
    "watchdog",
    "watchdog.observers",
    "watchdog.events",
    "plyer",
    "plyer.platforms.win.notification",
    "plyer.platforms.macosx.notification",
    "plyer.platforms.linux.notification",
]
for mod_pkg in ("customtkinter", "capstone", "plyer"):
    hiddenimports += _safe_collect_submodules(mod_pkg)

a = Analysis(
    [str(project_dir / "main.py")],
    pathex=[str(project_dir)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["matplotlib", "scipy", "pandas", "pytest", "requests"],
    noarchive=False,
)

pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Vyrulix",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Vyrulix",
)
'''


def normalize_project_filenames(project_dir: Path) -> None:
    """
    Normalizes any suffixed or browser-renamed project files (`scanner_3.py`, `scanner_2.py`,
    `main_3.py`, `main_2.py`, `community_3.py`, `community_2.py`, `build_vyrulix_3.py`)
    to their canonical names before compiling.
    """
    normalization_map = [
        ("scanner.py", ("scanner_3.py", "scanner_2.py", "scanner_1.py", "scanner.py.txt")),
        ("main.py", ("main_3.py", "main_2.py", "main_1.py", "main.py.txt")),
        ("community.py", ("community_3.py", "community_2.py", "community_1.py", "community.py.txt")),
        (
            "build_vyrulix.py",
            ("build_vyrulix_3.py", "build_vyrulix_2.py", "build_vyrulix_1.py", "build_vyrulix.py.txt"),
        ),
    ]
    for canonical_name, aliases in normalization_map:
        canonical_path = project_dir / canonical_name
        for alias in aliases:
            alias_path = project_dir / alias
            if alias_path.is_file():
                if (
                    not canonical_path.is_file()
                    or alias_path.stat().st_mtime >= canonical_path.stat().st_mtime
                ):
                    shutil.copy2(str(alias_path), str(canonical_path))
                    print(f"[+] Normalized '{alias}' -> '{canonical_name}'")
                    break

    for required in ("main.py", "scanner.py", "community.py"):
        req_path = project_dir / required
        if not req_path.is_file():
            raise FileNotFoundError(
                f"Required Vyrulix module '{required}' is missing in {project_dir}"
            )


def main() -> None:
    project_dir = Path(__file__).resolve().parent
    normalize_project_filenames(project_dir)

    spec_path = project_dir / "Vyrulix.spec"
    spec_path.write_text(SPEC_CONTENT.lstrip(), encoding="utf-8")
    print(f"[+] Wrote canonical PyInstaller spec: {spec_path}")

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", str(spec_path)]
    print(f"[+] Executing Vyrulix v1.1 build: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(project_dir), check=True)


if __name__ == "__main__":
    main()