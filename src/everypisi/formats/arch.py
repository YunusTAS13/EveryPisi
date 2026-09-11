from __future__ import annotations

import io
import hashlib
import os
import shlex
import shutil
import tarfile
from pathlib import Path

from ..errors import ResourceLimitError, UnsupportedFormatError
from ..compression import decompress
from ..model import ParsedPackage
from ..util import (archive_metadata_flags, check_input_size, ensure_inside, ensure_safe_parent,
                    ensure_entry_absent, MAX_ARCHIVE_MEMBERS, safe_relative_path, scan_payload)
from .base import (PackageParser, normalize_pisi_release, normalize_pisi_version,
                   parse_dependency_group, parse_script, split_foreign_version)


def parse_pkginfo(data: bytes) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if not line or line.startswith("#") or " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        fields.setdefault(key, []).append(value)
    return fields


def parse_mtree(data: bytes) -> list[tuple[str, dict[str, str]]]:
    defaults: dict[str, str] = {}
    records: list[tuple[str, dict[str, str]]] = []
    try:
        text = decompress(data, hint=".mtree.gz").decode("utf-8", "replace")
    except (OSError, EOFError) as exc:
        raise UnsupportedFormatError(f"invalid Arch .MTREE compression: {exc}") from exc
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = shlex.split(line)
        if not fields:
            continue
        directive = fields[0]
        if directive == "/set":
            defaults.update(_mtree_attributes(fields[1:]))
        elif directive == "/unset":
            for key in fields[1:]:
                defaults.pop(key, None)
        elif directive.startswith("./"):
            rel = safe_relative_path(directive[2:])
            attributes = defaults.copy()
            attributes.update(_mtree_attributes(fields[1:]))
            records.append((rel, attributes))
    return records


def _mtree_attributes(fields: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for field in fields:
        if "=" in field:
            key, value = field.split("=", 1)
            result[key] = value
    return result


def verify_mtree(data: bytes | None, root: Path, source_metadata: dict[str, dict[str, int]]) -> str:
    if data is None:
        return "not-present"
    records = parse_mtree(data)
    seen: set[str] = set()
    checked = 0
    for rel, attributes in records:
        if not rel or rel.startswith("."):
            continue
        if rel in seen:
            raise UnsupportedFormatError(f"duplicate Arch .MTREE path: {rel}")
        seen.add(rel)
        if rel not in source_metadata:
            raise UnsupportedFormatError(f"Arch .MTREE path is absent from archive payload: {rel}")
        target = root / rel
        ensure_inside(root, target)
        if not target.exists() and not target.is_symlink():
            raise UnsupportedFormatError(f"Arch .MTREE references missing payload path: {rel}")
        expected_type = attributes.get("type", "file")
        if expected_type == "dir":
            if not target.is_dir() or target.is_symlink():
                raise UnsupportedFormatError(f"Arch .MTREE type mismatch: {rel}")
        elif expected_type == "link":
            if not target.is_symlink() or os.readlink(target) != attributes.get("link", ""):
                raise UnsupportedFormatError(f"Arch .MTREE symlink mismatch: {rel}")
        elif expected_type == "file":
            if not target.is_file() or target.is_symlink():
                raise UnsupportedFormatError(f"Arch .MTREE type mismatch: {rel}")
            if "size" in attributes and target.stat().st_size != int(float(attributes["size"])):
                raise UnsupportedFormatError(f"Arch .MTREE size mismatch: {rel}")
            expected_hash = attributes.get("sha256digest")
            if expected_hash:
                digest = hashlib.sha256()
                with target.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                actual = digest.hexdigest()
                if actual.lower() != expected_hash.lower():
                    raise UnsupportedFormatError(f"Arch .MTREE SHA-256 mismatch: {rel}")
        else:
            raise UnsupportedFormatError(f"unsupported Arch .MTREE type: {expected_type}")
        source = source_metadata.get(rel)
        if source:
            if "uid" in attributes and source["uid"] != int(attributes["uid"]):
                raise UnsupportedFormatError(f"Arch .MTREE UID mismatch: {rel}")
            if "gid" in attributes and source["gid"] != int(attributes["gid"]):
                raise UnsupportedFormatError(f"Arch .MTREE GID mismatch: {rel}")
            if "mode" in attributes and source["mode"] != int(attributes["mode"], 8):
                raise UnsupportedFormatError(f"Arch .MTREE mode mismatch: {rel}")
        checked += 1
    payload_paths = {rel for rel in source_metadata if not rel.startswith(".")}
    missing_records = sorted(payload_paths - seen)
    if missing_records:
        raise UnsupportedFormatError(
            "Arch .MTREE does not cover payload paths: " + ", ".join(missing_records[:8])
        )
    return f"verified:{checked}"


class ArchParser(PackageParser):
    format_name = "arch"

    def parse(self, package: Path, workdir: Path, *, signature_keyring: Path | None = None) -> ParsedPackage:
        check_input_size(package)
        root = workdir / "payload"
        root.mkdir(parents=True, exist_ok=True)
        warnings: list[str] = []
        source_metadata: dict[str, dict[str, int]] = {}
        metadata_flags: list[str] = []
        pkginfo: bytes | None = None
        install: bytes | None = None
        mtree: bytes | None = None
        seen: set[str] = set()
        pending_hardlinks: list[tuple[Path, Path, str]] = []
        try:
            archive = tarfile.open(package, mode="r:*")
        except (tarfile.TarError, OSError) as first_error:
            try:
                archive = tarfile.open(fileobj=io.BytesIO(decompress(package.read_bytes(), hint=package.name)), mode="r:")
            except (tarfile.TarError, OSError, UnsupportedFormatError) as second_error:
                raise UnsupportedFormatError(f"unsupported Arch archive compression: {second_error}") from first_error
        with archive:
            for member_index, member in enumerate(archive, 1):
                if member_index > MAX_ARCHIVE_MEMBERS:
                    raise ResourceLimitError("Arch archive contains too many members")
                rel = safe_relative_path(member.name)
                if not rel:
                    continue
                if rel in seen:
                    raise UnsupportedFormatError(f"duplicate Arch archive member: {rel}")
                seen.add(rel)
                if rel == ".PKGINFO":
                    source = archive.extractfile(member)
                    pkginfo = source.read() if source else b""
                    continue
                elif rel == ".INSTALL":
                    source = archive.extractfile(member)
                    install = source.read() if source else b""
                    continue
                elif rel == ".MTREE":
                    source = archive.extractfile(member)
                    mtree = source.read() if source else b""
                    continue
                elif rel.startswith("."):
                    continue
                metadata_flags.extend(archive_metadata_flags(member))
                target = root / rel
                ensure_safe_parent(root, target)
                source_metadata[rel] = {"uid": member.uid, "gid": member.gid, "mode": member.mode & 0o7777}
                if member.isdir():
                    if target.is_symlink() or (target.exists() and not target.is_dir()):
                        raise UnsupportedFormatError(f"Arch directory collides with non-directory: {rel}")
                    target.mkdir(parents=True, exist_ok=True)
                elif member.issym():
                    ensure_entry_absent(root, target)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(member.linkname)
                elif member.isfile():
                    ensure_entry_absent(root, target)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source:
                        with target.open("wb") as target_stream:
                            shutil.copyfileobj(source, target_stream, length=1024 * 1024)
                    target.chmod(member.mode & 0o7777)
                elif member.islnk():
                    link_target = safe_relative_path(member.linkname)
                    hardlink_target = root / link_target
                    ensure_safe_parent(root, hardlink_target)
                    if hardlink_target.is_file() and not hardlink_target.is_symlink():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.hardlink_to(hardlink_target)
                    else:
                        pending_hardlinks.append((target, hardlink_target, rel))
                else:
                    warnings.append(f"unsupported special archive member skipped: {rel}")
                    metadata_flags.append(f"special-file-not-supported:{rel}")
        for target, hardlink_target, rel in pending_hardlinks:
            if not hardlink_target.is_file() or hardlink_target.is_symlink():
                raise UnsupportedFormatError(f"hardlink target missing or non-regular: {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.hardlink_to(hardlink_target)
        if pkginfo is None:
            raise UnsupportedFormatError("Arch package lacks .PKGINFO")
        fields = parse_pkginfo(pkginfo)
        deps = []
        for key, scope in (("depend", "runtime"), ("optdepend", "optional")):
            for value in fields.get(key, []):
                value = value.split(": ", 1)[0]
                group = parse_dependency_group(value, scope)
                if group:
                    deps.append(group)
        foreign_version = fields.get("pkgver", ["0"])[0]
        version, release = split_foreign_version(foreign_version, "arch")
        normalized_version = normalize_pisi_version(version)
        if normalized_version != version:
            warnings.append(f"Arch version normalized for Pisi: {version} -> {normalized_version}")
            metadata_flags.append("arch-version-normalized")
            version = normalized_version
        normalized_release = normalize_pisi_release(release)
        if normalized_release != release:
            metadata_flags.append("arch-release-normalized")
            release = normalized_release
        scripts = []
        if install:
            scripts.append(parse_script(".INSTALL", install))
        parsed = ParsedPackage("arch", package, fields.get("pkgname", [package.stem])[0],
                               version, fields.get("arch", ["any"])[0],
                               fields.get("pkgdesc", [""])[0], fields.get("pkgdesc", [""])[0],
                               fields.get("url", [""])[0], ", ".join(fields.get("license", ["Unknown"])),
                               deps, fields.get("provides", []), fields.get("conflict", []), scripts,
                               root, raw_metadata={k: v[:] for k, v in fields.items()}, warnings=warnings)
        parsed.replaces = fields.get("replaces", [])[:]
        parsed.files = scan_payload(root, source_metadata)
        parsed.payload_metadata = source_metadata
        parsed.metadata_flags = sorted(set(metadata_flags))
        for provided in parsed.provides:
            if provided and not provided.startswith(parsed.name + "=") and provided != parsed.name:
                parsed.metadata_flags.append(f"foreign-provide-not-supported:{provided}")
        parsed.metadata_flags = sorted(set(parsed.metadata_flags))
        parsed.source_integrity = {"arch-mtree": verify_mtree(mtree, root, source_metadata)}
        parsed.release = release
        return parsed
