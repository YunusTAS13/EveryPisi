from __future__ import annotations

import hashlib
import io
import re
import shutil
import tarfile
from pathlib import Path

from ..errors import ResourceLimitError, UnsafeArchiveError, UnsupportedFormatError
from ..compression import decompress
from ..model import ParsedPackage
from ..util import (archive_metadata_flags, check_input_size, ensure_entry_absent, ensure_inside,
                    ensure_safe_parent, MAX_ARCHIVE_MEMBERS, safe_relative_path, scan_payload)
from .base import (PackageParser, normalize_pisi_release, normalize_pisi_version,
                   parse_dependency_group, parse_script, split_foreign_version, split_top_level)


class ArMember:
    def __init__(self, name: str, data: bytes):
        self.name = name
        self.data = data


def read_ar(path: Path) -> list[ArMember]:
    check_input_size(path)
    blob = path.read_bytes()
    if not blob.startswith(b"!<arch>\n"):
        raise UnsupportedFormatError("not an ar archive")
    pos = 8
    long_names = b""
    members: list[ArMember] = []
    while pos < len(blob):
        if blob[pos:pos + 60].strip() == b"":
            break
        header = blob[pos:pos + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise UnsupportedFormatError("invalid ar member header")
        raw_name = header[:16].decode("utf-8", "replace").strip()
        size = int(header[48:58].decode("ascii", "replace").strip() or "0")
        pos += 60
        if size < 0 or pos + size + (size & 1) > len(blob):
            raise UnsupportedFormatError(f"truncated ar member: {raw_name}")
        data = blob[pos:pos + size]
        pos += size + (size & 1)
        name = raw_name.rstrip("/")
        if name == "//":
            long_names = data
            continue
        if name.startswith("#1/"):
            name_len = int(name[3:])
            name = data[:name_len].decode("utf-8", "replace")
            data = data[name_len:]
        elif name.startswith("/") and name[1:].isdigit() and long_names:
            offset = int(name[1:])
            name = long_names[offset:].split(b"\n", 1)[0].decode("utf-8", "replace").rstrip("/")
        members.append(ArMember(name, data))
    return members


def read_control(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    current: str | None = None
    for raw in data.decode("utf-8", "replace").splitlines():
        if raw.startswith((" ", "\t")) and current:
            result[current] += "\n" + raw[1:]
        elif ":" in raw:
            key, value = raw.split(":", 1)
            current = key.strip()
            result[current] = value.strip()
    return result


def verify_md5sums(data: bytes | None, root: Path) -> str:
    if data is None:
        return "not-present"
    checked = 0
    seen: set[str] = set()
    for line in data.decode("ascii", "replace").splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{32})  (.+)", line)
        if not match:
            raise UnsupportedFormatError("invalid Debian md5sums entry")
        expected, raw_path = match.groups()
        rel = safe_relative_path(raw_path)
        if not rel or rel in seen:
            raise UnsupportedFormatError(f"invalid or duplicate Debian md5sums path: {raw_path}")
        seen.add(rel)
        target = root / rel
        ensure_inside(root, target)
        if not target.is_file() or target.is_symlink():
            raise UnsupportedFormatError(f"Debian md5sums references missing regular file: {rel}")
        digest = hashlib.md5()
        with target.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        digest = digest.hexdigest()
        if digest.lower() != expected.lower():
            raise UnsupportedFormatError(f"Debian md5sum verification failed: {rel}")
        checked += 1
    return f"verified:{checked}"


def extract_tar(data: bytes, destination: Path, warnings: list[str], collect_files: bool = False, source_metadata: dict[str, dict[str, int]] | None = None, metadata_flags: list[str] | None = None) -> dict[str, bytes]:
    controls: dict[str, bytes] = {}
    source_metadata = source_metadata if source_metadata is not None else {}
    metadata_flags = metadata_flags if metadata_flags is not None else []
    data = decompress(data, hint="data.tar")
    seen: set[str] = set()
    pending_hardlinks: list[tuple[Path, Path, str]] = []
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UnsupportedFormatError(f"unsupported Debian tar compression: {exc}") from exc
    with archive:
        for member_index, member in enumerate(archive, 1):
            if member_index > MAX_ARCHIVE_MEMBERS:
                raise ResourceLimitError("Debian archive contains too many members")
            rel = safe_relative_path(member.name)
            if not rel:
                continue
            if rel in seen:
                raise UnsupportedFormatError(f"duplicate Debian tar member: {rel}")
            seen.add(rel)
            metadata_flags.extend(archive_metadata_flags(member))
            destination_path = destination / rel
            ensure_safe_parent(destination, destination_path)
            if not collect_files:
                source_metadata[rel] = {"uid": member.uid, "gid": member.gid, "mode": member.mode & 0o7777}
            if member.isdir():
                if destination_path.is_symlink() or (destination_path.exists() and not destination_path.is_dir()):
                    raise UnsafeArchiveError(f"archive directory collides with non-directory: {rel}")
                destination_path.mkdir(parents=True, exist_ok=True)
                destination_path.chmod(member.mode & 0o7777)
            elif member.issym():
                ensure_entry_absent(destination, destination_path)
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                destination_path.symlink_to(member.linkname)
            elif member.islnk():
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                target = destination / safe_relative_path(member.linkname)
                ensure_safe_parent(destination, target)
                if target.is_file() and not target.is_symlink():
                    destination_path.hardlink_to(target)
                else:
                    pending_hardlinks.append((destination_path, target, rel))
            elif member.isfile():
                ensure_entry_absent(destination, destination_path)
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    warnings.append(f"empty/unreadable file: {rel}")
                    continue
                with destination_path.open("wb") as target_stream:
                    shutil.copyfileobj(source, target_stream, length=1024 * 1024)
                destination_path.chmod(member.mode & 0o7777)
            else:
                warnings.append(f"unsupported special archive member skipped: {rel}")
                if not collect_files:
                    metadata_flags.append(f"special-file-not-supported:{rel}")
            if collect_files and destination_path.is_file():
                controls[rel.removeprefix("DEBIAN/")] = destination_path.read_bytes()
    for destination_path, target, rel in pending_hardlinks:
        if not target.is_file() or target.is_symlink():
            raise UnsupportedFormatError(f"hardlink target missing or non-regular: {rel}")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.hardlink_to(target)
        if collect_files:
            controls[rel.removeprefix("DEBIAN/")] = destination_path.read_bytes()
    return controls


class DebParser(PackageParser):
    format_name = "deb"

    def parse(self, package: Path, workdir: Path, *, signature_keyring: Path | None = None) -> ParsedPackage:
        members = read_ar(package)
        version_members = [m for m in members if m.name == "debian-binary"]
        control_members = [m for m in members if m.name.startswith("control.tar")]
        data_members = [m for m in members if m.name.startswith("data.tar")]
        if len(version_members) != 1 or len(control_members) != 1 or len(data_members) != 1:
            raise UnsupportedFormatError("Debian package lacks control.tar or data.tar")
        version_member = version_members[0]
        control_member = control_members[0]
        data_member = data_members[0]
        names = [member.name for member in members]
        if not names or names[0] != "debian-binary":
            raise UnsupportedFormatError("Debian package must start with debian-binary")
        control_index, data_index = names.index(control_member.name), names.index(data_member.name)
        optional_members = names[1:control_index] + names[control_index + 1:data_index]
        if control_index >= data_index or any(not name.startswith("_") for name in optional_members):
            raise UnsupportedFormatError("invalid Debian ar member order")
        if version_member.data.strip() != b"2.0":
            raise UnsupportedFormatError("unsupported Debian binary format; expected debian-binary 2.0")
        root = workdir / "payload"
        root.mkdir(parents=True, exist_ok=True)
        warnings: list[str] = []
        control_root = workdir / "control"
        control_root.mkdir(parents=True, exist_ok=True)
        controls = extract_tar(control_member.data, control_root, warnings, collect_files=True)
        source_metadata: dict[str, dict[str, int]] = {}
        metadata_flags: list[str] = []
        extract_tar(data_member.data, root, warnings, source_metadata=source_metadata, metadata_flags=metadata_flags)
        fields = read_control(controls.get("control", b""))
        source_integrity = {"debian-md5sums": verify_md5sums(controls.get("md5sums"), root)}
        embedded_signatures = [
            member.name for member in members
            if member.name.lower().startswith(("_gpg", "_sig"))
        ]
        if embedded_signatures:
            source_integrity["debian-embedded-signature"] = "present-unverified"
            warnings.append(
                "Debian embedded signature requires debsig-verify policy/keyring verification"
            )
        if "triggers" in controls:
            metadata_flags.append("debian-triggers-not-supported")
        name = fields.get("Package", package.stem)
        foreign_version = fields.get("Version", "0")
        version, release = split_foreign_version(foreign_version, "deb")
        normalized_version = normalize_pisi_version(version)
        if normalized_version != version:
            warnings.append(f"Debian version normalized for Pisi: {version} -> {normalized_version}")
            metadata_flags.append("debian-version-normalized")
            version = normalized_version
        normalized_release = normalize_pisi_release(release)
        if normalized_release != release:
            metadata_flags.append("debian-release-normalized")
            release = normalized_release
        architecture = fields.get("Architecture", "any")
        deps = []
        for key, scope in (("Pre-Depends", "runtime"), ("Depends", "runtime"), ("Recommends", "optional"), ("Suggests", "suggested")):
            for item in split_top_level(fields.get(key, "")):
                group = parse_dependency_group(item, scope)
                if group:
                    deps.append(group)
        scripts = [parse_script(name, body) for name, body in controls.items() if name in {"preinst", "postinst", "prerm", "postrm", "config"}]
        parsed = ParsedPackage("deb", package, name, version, architecture,
                               fields.get("Description", "").split("\n", 1)[0],
                               fields.get("Description", ""), fields.get("Homepage", ""),
                               fields.get("License", "Unknown"), deps,
                               split_top_level(fields.get("Provides", "")),
                               split_top_level(fields.get("Conflicts", "")) + split_top_level(fields.get("Breaks", "")), scripts,
                               root, raw_metadata=fields, warnings=warnings)
        parsed.replaces = split_top_level(fields.get("Replaces", ""))
        parsed.files = scan_payload(root, source_metadata)
        parsed.payload_metadata = source_metadata
        parsed.metadata_flags = sorted(set(metadata_flags))
        for provided in parsed.provides:
            if provided and provided != parsed.name:
                parsed.metadata_flags.append(f"foreign-provide-not-supported:{provided}")
        parsed.metadata_flags = sorted(set(parsed.metadata_flags))
        parsed.source_integrity = source_integrity
        parsed.release = release
        return parsed
