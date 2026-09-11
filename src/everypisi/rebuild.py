from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import ConversionRefused
from .validator import validate_pisi_package


@dataclass
class RebuildResult:
    command: list[str]
    output_packages: list[Path]
    log: str


def validate_recipe_directory(recipe_dir: Path) -> None:
    recipe_dir = recipe_dir.resolve()
    if not recipe_dir.is_dir():
        raise ConversionRefused(f"recipe directory does not exist: {recipe_dir}")
    for required in ("pspec.xml", "actions.py"):
        if not (recipe_dir / required).is_file():
            raise ConversionRefused(f"Pisi native recipe is missing {required}: {recipe_dir}")
    if (recipe_dir / "pspec.xml").stat().st_size == 0 or (recipe_dir / "actions.py").stat().st_size == 0:
        raise ConversionRefused("Pisi native recipe contains an empty required file")


def rebuild_recipe(recipe_dir: Path, output_dir: Path, *, pisi_command: str = "pisi") -> RebuildResult:
    """Build a Pisi-native recipe through Pisi's own build operation.

    The command intentionally does not pass --ignore-sandbox, --ignore-check,
    or --ignore-safety. A Pisi installation controls those policies through its
    normal configuration and the caller can inspect the captured log.
    """
    validate_recipe_directory(recipe_dir)
    pisi = shutil.which(pisi_command) or (pisi_command if Path(pisi_command).is_file() else None)
    if not pisi:
        raise ConversionRefused("Pisi build command not found; install Pisi Linux's pisi tool in the build environment")
    output_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.setdefault("LC_ALL", "C")
    with tempfile.TemporaryDirectory(prefix="everypisi-rebuild-", dir=output_dir.parent) as staging_name:
        staging = Path(staging_name)
        command = [pisi, "bi", "--package", "--package-format", "1.2", "--output-dir", str(staging), str(recipe_dir / "pspec.xml")]
        result = subprocess.run(command, cwd=recipe_dir, env=environment, check=False, capture_output=True, text=True)
        log = result.stdout + ("\n" + result.stderr if result.stderr else "")
        if result.returncode:
            raise ConversionRefused(f"Pisi native rebuild failed (exit {result.returncode})\n{log[-12000:]}")
        staged_outputs = sorted(staging.glob("*.pisi"))
        if not staged_outputs:
            raise ConversionRefused("Pisi rebuild completed without producing a .pisi package")
        invalid = {str(path): validate_pisi_package(path, strict_install_tar_hash=True) for path in staged_outputs}
        invalid = {name: errors for name, errors in invalid.items() if errors}
        if invalid:
            details = "; ".join(f"{name}: {', '.join(errors)}" for name, errors in invalid.items())
            raise ConversionRefused("Pisi rebuild produced invalid packages: " + details)
        outputs: list[Path] = []
        for staged in staged_outputs:
            destination = output_dir / staged.name
            temporary_fd, temporary_name = tempfile.mkstemp(prefix=".everypisi-output-",
                                                            suffix=".tmp", dir=output_dir)
            os.close(temporary_fd)
            temporary = Path(temporary_name)
            try:
                shutil.copy2(staged, temporary)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
            outputs.append(destination)
        return RebuildResult(command, outputs, log)
