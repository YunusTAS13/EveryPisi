from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DependencyAtom:
    name: str
    operator: str | None = None
    version: str | None = None
    architecture: str | None = None
    raw: str = ""
    version_to: str | None = None
    release: str | None = None
    release_from: str | None = None
    release_to: str | None = None


@dataclass(frozen=True)
class DependencyGroup:
    alternatives: tuple[DependencyAtom, ...]
    scope: str = "runtime"


@dataclass
class Script:
    name: str
    body: bytes
    interpreter: str | None = None
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class FileEntry:
    path: str
    kind: str
    size: int = 0
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    sha1: str | None = None
    link_target: str | None = None


@dataclass
class ParsedPackage:
    source_format: str
    source_path: Path
    name: str
    version: str
    architecture: str
    summary: str = ""
    description: str = ""
    homepage: str = ""
    license: str = "Unknown"
    dependencies: list[DependencyGroup] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    payload_root: Path | None = None
    files: list[FileEntry] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elf_files: list[dict[str, Any]] = field(default_factory=list)
    script_interpreters: list[str] = field(default_factory=list)
    file_flags: list[str] = field(default_factory=list)
    payload_metadata: dict[str, dict[str, int]] = field(default_factory=dict)
    metadata_flags: list[str] = field(default_factory=list)
    source_integrity: dict[str, str] = field(default_factory=dict)
    release: str = "1"
    replaces: list[str] = field(default_factory=list)

    @property
    def is_convertible(self) -> bool:
        return bool(self.name and self.version and self.payload_root and not self.errors)
