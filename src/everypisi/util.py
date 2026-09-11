from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

from .errors import ResourceLimitError, UnsafeArchiveError
from .model import FileEntry


# Hard limits prevent accidental or maliciously compressed inputs from
# exhausting the converter host.
MAX_PACKAGE_BYTES = 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 1_000_000
MAX_ARCHIVE_PATH_BYTES = 4096


def check_input_size(path: Path) -> None:
    size = path.stat().st_size
    if size > MAX_PACKAGE_BYTES:
        raise ResourceLimitError(
            f"package is {size} bytes; safety limit is {MAX_PACKAGE_BYTES} bytes"
        )


def safe_relative_path(path: str) -> str:
    """Normalize an archive member and reject traversal/absolute paths."""
    path = path.replace("\\", "/")
    if "\x00" in path:
        raise UnsafeArchiveError("NUL byte in archive path")
    if len(path.encode("utf-8", "surrogatepass")) > MAX_ARCHIVE_PATH_BYTES:
        raise ResourceLimitError("archive member path exceeds the safety limit")
    if path.startswith("/"):
        raise UnsafeArchiveError(f"absolute archive path: {path}")
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise UnsafeArchiveError(f"path traversal archive member: {path}")
    return "/".join(parts)


def ensure_inside(root: Path, candidate: Path) -> None:
    root_real = root.resolve()
    candidate_real = candidate.resolve(strict=False)
    try:
        candidate_real.relative_to(root_real)
    except ValueError as exc:
        raise UnsafeArchiveError(f"archive member escapes extraction root: {candidate}") from exc


def ensure_safe_parent(root: Path, candidate: Path) -> None:
    """Reject symlinked parents before writing an extracted archive member.

    ``Path.resolve`` alone is not sufficient here: a link which points back
    inside the extraction root can still redirect a later archive member to a
    different path.  Archive extraction must follow directories created by
    the archive only, never symlinks in the parent chain.
    """
    ensure_inside(root, candidate)
    root = root.resolve()
    parent = candidate.parent
    try:
        # Walk the lexical path, not the resolved path.  Resolving first would
        # erase the symlink component we need to detect.
        relative = parent.relative_to(root)
    except ValueError as exc:
        raise UnsafeArchiveError(f"archive member parent escapes extraction root: {candidate}") from exc
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise UnsafeArchiveError(f"archive member uses symlinked parent: {candidate}")


def ensure_entry_absent(root: Path, candidate: Path) -> None:
    """Require an archive member destination to be a fresh filesystem entry."""
    ensure_safe_parent(root, candidate)
    if candidate.exists() or candidate.is_symlink():
        raise UnsafeArchiveError(f"archive member collides with an existing path: {candidate}")


def sha1_path(path: Path) -> str | None:
    if path.is_symlink():
        return hashlib.sha1(os.readlink(path).encode()).hexdigest()
    if path.is_dir():
        return None
    digest = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_hashes(path: Path, algorithms: tuple[str, ...] = ("sha256", "sha512")) -> dict[str, str]:
    """Calculate audit-friendly hashes without loading a package into memory."""
    try:
        digests = {name: hashlib.new(name) for name in algorithms}
    except ValueError as exc:
        raise ValueError(f"unsupported hash algorithm: {exc}") from exc
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def classify_path(rel_path: str, mode: int) -> str:
    lower = "/" + rel_path.lower()
    name = lower.rsplit("/", 1)[-1]
    if "/usr/share/man/" in lower or re.search(r"\.[0-9](\.gz|\.xz|\.bz2)?$", name):
        return "man"
    if "/usr/share/doc/" in lower or "/usr/share/licenses/" in lower:
        return "doc"
    if "/usr/share/locale/" in lower:
        return "localedata"
    if lower.startswith("/etc/"):
        return "config"
    if "/usr/include/" in lower or name.endswith((".h", ".hpp")):
        return "header"
    if ".so" in name or "/usr/lib/" in lower or "/lib64/" in lower:
        return "library"
    if stat.S_IMODE(mode) & 0o111:
        return "executable"
    return "data"


def scan_payload(root: Path, source_metadata: dict[str, dict[str, int]] | None = None) -> list[FileEntry]:
    source_metadata = source_metadata or {}
    entries: list[FileEntry] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted(dirs + files):
            path = current_path / name
            rel = path.relative_to(root).as_posix()
            st = path.lstat()
            if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode) or stat.S_ISFIFO(st.st_mode):
                continue
            source = source_metadata.get(rel, {})
            if path.is_dir() and not path.is_symlink():
                if not any(path.iterdir()):
                    entries.append(FileEntry(
                        rel, "directory",
                        mode=source.get("mode", stat.S_IMODE(st.st_mode)),
                        uid=source.get("uid", st.st_uid),
                        gid=source.get("gid", st.st_gid),
                    ))
                continue
            kind = "symlink" if path.is_symlink() else "file"
            entries.append(FileEntry(
                rel,
                kind,
                size=st.st_size if kind == "file" else 0,
                mode=source.get("mode", stat.S_IMODE(st.st_mode)),
                uid=source.get("uid", st.st_uid),
                gid=source.get("gid", st.st_gid),
                sha1=sha1_path(path),
                link_target=os.readlink(path) if kind == "symlink" else None,
            ))
    return sorted(entries, key=lambda item: item.path)


def archive_metadata_flags(member) -> list[str]:
    """Metadata classes not retained by plain filesystem staging."""
    flags: list[str] = []
    for key in getattr(member, "pax_headers", {}):
        lower = key.lower()
        if "xattr" in lower or "acl" in lower or "capability" in lower:
            flags.append(f"{key}:{member.name}")
    return flags
