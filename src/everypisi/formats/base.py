from __future__ import annotations

import re
from pathlib import Path

from ..model import DependencyAtom, DependencyGroup, Script


DEPENDENCY_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9+_.:@/-]*)(?:\s*(<<|<=|=|>=|>>|<|>)\s*([^\s,)]+))?\s*$")


def split_top_level(value: str, separator: str = ",") -> list[str]:
    result: list[str] = []
    current: list[str] = []
    depth = 0
    for char in value:
        if char in "(":
            depth += 1
        elif char in ")" and depth:
            depth -= 1
        if char == separator and depth == 0:
            item = "".join(current).strip()
            if item:
                result.append(item)
            current = []
        else:
            current.append(char)
    item = "".join(current).strip()
    if item:
        result.append(item)
    return result


def parse_dependency_group(value: str, scope: str = "runtime") -> DependencyGroup | None:
    alternatives: list[DependencyAtom] = []
    for raw_atom in re.split(r"\s*\|\s*", value.strip()):
        atom = raw_atom.strip()
        atom = re.sub(r"\s*\[[^]]+\]$", "", atom)
        debian_relation = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9+_.:@/-]*)\s*\((<<|<=|=|>=|>>|<|>)\s*([^\)]+)\)$",
            atom,
        )
        if debian_relation:
            atom = f"{debian_relation.group(1)} {debian_relation.group(2)} {debian_relation.group(3).strip()}"
        architecture = None
        match_arch = re.search(r":([A-Za-z0-9_-]+)$", atom)
        if match_arch:
            architecture = match_arch.group(1)
            atom = atom[:match_arch.start()]
        match = DEPENDENCY_RE.match(atom)
        if match:
            operator = {"<<": "<", ">>": ">"}.get(match.group(2), match.group(2))
            alternatives.append(DependencyAtom(match.group(1), operator, match.group(3), architecture, raw_atom.strip()))
    return DependencyGroup(tuple(alternatives), scope) if alternatives else None


def parse_script(name: str, body: bytes) -> Script:
    first_line = body.splitlines()[0].decode("utf-8", "replace") if body.splitlines() else ""
    interpreter = first_line[2:].strip() if first_line.startswith("#!") else None
    text = body.decode("utf-8", "replace")
    risk_flags: list[str] = []
    checks = {
        "writes-system-state": (r"\b(systemctl|service|rc-service|update-rc\.d|ldconfig)\b", "system state command"),
        "user-or-group-change": (r"\b(user(add|del|mod)|group(add|del|mod))\b", "user/group command"),
        "network-access": (r"\b(curl|wget|ftp|nc|curl)\b", "network command"),
        "dynamic-execution": (r"\b(eval|python|perl|ruby|lua)\b", "dynamic interpreter/eval"),
        "debian-specific": (r"\b(dpkg|debconf|ucf|update-alternatives)\b", "Debian-specific command"),
        "rpm-specific": (r"\b(rpm|selinux|alternatives)\b", "RPM/platform-specific command"),
    }
    for flag, (pattern, _) in checks.items():
        if re.search(pattern, text):
            risk_flags.append(flag)
    return Script(name, body, interpreter, risk_flags)


class PackageParser:
    format_name = "unknown"

    def parse(self, package: Path, workdir: Path):
        raise NotImplementedError


def split_foreign_version(value: str, source_format: str) -> tuple[str, str]:
    """Split a foreign package version into Pisi version and numeric release."""
    value = value.strip() or "0"
    if source_format == "deb" and ":" in value:
        _, value = value.split(":", 1)  # preserve the original in raw metadata
    candidate_version, separator, candidate_release = value.rpartition("-")
    if separator and candidate_version and candidate_release.isdigit():
        return candidate_version, candidate_release
    return value, "1"


_PISI_VERSION_RE = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:_(?:alpha|beta|pre|rc|m|p)[0-9]*(?:\.[0-9]+)*)?$"
)


def is_pisi_version(value: str) -> bool:
    return bool(_PISI_VERSION_RE.fullmatch(value.strip()))


def normalize_pisi_version(value: str) -> str:
    """Map common foreign versions to Pisi's strictly parsed version grammar."""
    raw = value.strip()
    if is_pisi_version(raw):
        return raw
    raw = re.sub(r"^[0-9]+:", "", raw)
    numeric = re.match(r"([0-9]+(?:\.[0-9]+)*)", raw)
    if not numeric:
        return "0"
    base = numeric.group(1)
    suffix = re.search(r"(?:^|[^a-z])(alpha|beta|pre|rc|m|p)([0-9.]*)", raw.lower())
    if suffix:
        tail = suffix.group(2).strip(".")
        return f"{base}_{suffix.group(1)}{tail}"
    return base


def normalize_pisi_release(value: str) -> str:
    """Return the numeric release accepted by Pisi's package database."""
    raw = str(value).strip()
    if raw.isdigit():
        return str(int(raw))
    match = re.match(r"[0-9]+", raw)
    return str(int(match.group(0))) if match else "1"


def is_pisi_release(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9]+", str(value).strip()))
