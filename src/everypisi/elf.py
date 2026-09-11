from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ElfInfo:
    path: str
    bits: int
    machine: str
    interpreter: str | None = None
    needed: list[str] = field(default_factory=list)
    soname: str | None = None
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    version_requirements: dict[str, str] = field(default_factory=dict)


TARGET_ELF_PROFILES = {
    "x86_64": {"machine": "x86-64", "bits": 64,
               "interpreters": {"ld-linux-x86-64.so.2"}},
    "aarch64": {"machine": "AArch64", "bits": 64,
                 "interpreters": {"ld-linux-aarch64.so.1"}},
    "i686": {"machine": "i386", "bits": 32,
             "interpreters": {"ld-linux.so.2", "ld-linux-i686.so.2"}},
}


def elf_compatibility_issues(elf: dict, target_arch: str) -> list[tuple[str, str]]:
    """Return critical ELF ABI mismatches for a Pisi target architecture."""
    profile = TARGET_ELF_PROFILES.get(target_arch)
    if profile is None:
        return [("unsupported-target-architecture", target_arch)]
    issues: list[tuple[str, str]] = []
    if elf.get("machine") and elf["machine"] != profile["machine"]:
        issues.append(("elf-machine", str(elf["machine"])))
    if elf.get("bits") and elf["bits"] != profile["bits"]:
        issues.append(("elf-bitness", f"{elf['bits']}-bit"))
    interpreter = elf.get("interpreter")
    if interpreter and Path(interpreter).name not in profile["interpreters"]:
        issues.append(("elf-interpreter", str(interpreter)))
    return issues


def _elf_header(path: Path) -> tuple[int, str] | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    bits = {1: 32, 2: 64}.get(header[4])
    endian = "little" if header[5] == 1 else "big" if header[5] == 2 else None
    if not bits or not endian:
        return None
    machine = int.from_bytes(header[18:20], endian)
    machines = {3: "i386", 40: "ARM", 62: "x86-64", 183: "AArch64", 8: "MIPS"}
    return bits, machines.get(machine, f"machine-{machine}")


def analyze_elf(path: Path, root: Path) -> ElfInfo | None:
    header = _elf_header(path)
    if header is None:
        return None
    bits, machine = header
    info = ElfInfo(path.relative_to(root).as_posix(), bits, machine)
    readelf = shutil.which("readelf")
    if not readelf:
        return info
    dynamic = _run_readelf(readelf, "-dW", path)
    for line in dynamic.splitlines():
        match = re.search(r"\(NEEDED\).*\[(.+)]", line)
        if match:
            info.needed.append(match.group(1))
        match = re.search(r"\((SONAME|RPATH|RUNPATH)\).*\[(.+)]", line)
        if match:
            kind, value = match.groups()
            if kind == "SONAME":
                info.soname = value
            elif kind == "RPATH":
                info.rpath = value.split(":")
            else:
                info.runpath = value.split(":")
    program = _run_readelf(readelf, "-lW", path)
    match = re.search(r"Requesting program interpreter:\s*([^\s\]]+)", program)
    if match:
        info.interpreter = match.group(1)
    versions = _run_readelf(readelf, "--version-info", path)
    current_library: str | None = None
    for line in versions.splitlines():
        file_match = re.search(r"\bFile:\s*(\S+)", line)
        if file_match:
            current_library = file_match.group(1)
            continue
        version_match = re.search(r"\bName:\s*(?:GLIBC|GLIBCXX|CXXABI|GCC)_(\d[0-9.]*)\b", line)
        if version_match and current_library:
            required = version_match.group(1)
            previous = info.version_requirements.get(current_library)
            if previous is None or _version_tuple(required) > _version_tuple(previous):
                info.version_requirements[current_library] = required
    return info


def _run_readelf(readelf: str, option: str, path: Path) -> str:
    try:
        result = subprocess.run([readelf, option, str(path)], check=False,
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".") if part.isdigit())


def analyze_payload(root: Path) -> tuple[list[ElfInfo], list[str], list[str]]:
    """Return ELF records, script interpreters and suspicious file flags."""
    elf_files: list[ElfInfo] = []
    script_interpreters: list[str] = []
    flags: list[str] = []
    for current, _, filenames in os.walk(root, followlinks=False):
        for filename in filenames:
            path = Path(current) / filename
            if path.is_symlink():
                continue
            try:
                mode = path.stat().st_mode
                if mode & stat.S_ISUID:
                    flags.append(f"setuid:{path.relative_to(root).as_posix()}")
                if mode & stat.S_ISGID:
                    flags.append(f"setgid:{path.relative_to(root).as_posix()}")
                with path.open("rb") as stream:
                    prefix = stream.read(256)
            except OSError:
                continue
            info = analyze_elf(path, root)
            if info:
                elf_files.append(info)
            elif prefix.startswith(b"#!"):
                first_line = prefix.splitlines()[0].decode("utf-8", "replace")
                script_interpreters.append(first_line[2:].strip())
    return elf_files, sorted(set(script_interpreters)), sorted(set(flags))
