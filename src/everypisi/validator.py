from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import zipfile
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET
from pathlib import Path

from .compression import decompress
from .errors import ResourceLimitError
from .util import (MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_PATH_BYTES, MAX_EXPANDED_BYTES,
                   check_input_size)


def validate_pisi_package(path: Path, *, strict_install_tar_hash: bool = False) -> list[str]:
    errors: list[str] = []
    manifest_set: set[str] = set()
    try:
        check_input_size(path)
    except (OSError, ResourceLimitError) as exc:
        return [f"Pisi package exceeds the safety limit: {exc}"]
    try:
        outer = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"invalid Pisi outer archive: {exc}"]
    with outer:
        raw_names = outer.namelist()
        if len(raw_names) > MAX_ARCHIVE_MEMBERS:
            errors.append("too many members in Pisi outer archive")
        names = set(raw_names)
        if len(raw_names) != len(names):
            errors.append("duplicate member names in Pisi outer archive")
        required = {"metadata.xml", "files.xml", "install.tar.xz"}
        missing = required - names
        if missing:
            errors.append("missing Pisi members: " + ", ".join(sorted(missing)))
        try:
            metadata = ET.fromstring(outer.read("metadata.xml"))
            package = metadata.find("Package")
            if metadata.tag != "PISI" or package is None:
                errors.append("metadata.xml does not have a PISI/Package root")
            else:
                source = metadata.find("Source")
                if source is None:
                    errors.append("metadata.xml is missing top-level Source")
                elif not (source.findtext("Name") or "").strip() or source.find("Packager") is None:
                    errors.append("metadata.xml top-level Source lacks Name or Packager")
                for field in ("Name", "Distribution", "DistributionRelease", "Architecture", "InstalledSize", "PackageFormat"):
                    if not (package.findtext(field) or "").strip():
                        errors.append(f"metadata.xml missing Package/{field}")
                if package.findtext("PackageFormat") != "1.2":
                    errors.append("unsupported or missing Pisi package format; expected 1.2")
                update = package.find("./History/Update")
                if update is None or not (update.findtext("Version") or "").strip() or not update.attrib.get("release"):
                    errors.append("metadata.xml is missing Package/History/Update version or release")
        except (KeyError, ET.ParseError) as exc:
            errors.append(f"invalid metadata.xml: {exc}")
            package = None
        try:
            files_root = ET.fromstring(outer.read("files.xml"))
            file_nodes = files_root.findall("File")
            if files_root.tag != "Files":
                errors.append("files.xml root is not Files")
            manifest_paths = []
            for node in file_nodes:
                path = (node.findtext("Path") or "").strip()
                if path.startswith("/"):
                    errors.append(f"files.xml path must be relative: {path}")
                if path in manifest_paths:
                    errors.append(f"duplicate files.xml path: {path}")
                manifest_paths.append(path)
            manifest_set = {path.lstrip("/") for path in manifest_paths if path}
        except (KeyError, ET.ParseError) as exc:
            errors.append(f"invalid files.xml: {exc}")
            file_nodes = []
        if "install.tar.xz" not in names:
            return errors
        install_tar_bytes = outer.read("install.tar.xz")
        if len(install_tar_bytes) > MAX_EXPANDED_BYTES:
            errors.append("install.tar.xz exceeds the safety limit")
            return errors
        if package is not None:
            expected_tar_hash = (package.findtext("InstallTarHash") or "").strip()
            if strict_install_tar_hash:
                if not expected_tar_hash:
                    errors.append("InstallTarHash is missing in strict validation mode")
                elif hashlib.sha1(install_tar_bytes).hexdigest() != expected_tar_hash:
                    errors.append("InstallTarHash does not match install.tar.xz")
            expected_installed_size = package.findtext("InstalledSize")
            if expected_installed_size:
                try:
                    manifest_size = sum(int(node.findtext("Size") or "0") for node in file_nodes)
                    if manifest_size != int(expected_installed_size):
                        errors.append(f"InstalledSize mismatch: metadata={expected_installed_size}, manifest={manifest_size}")
                except ValueError:
                    errors.append("InstalledSize is not an integer")
        try:
            install_data = decompress(install_tar_bytes, hint="install.tar.xz")
            install = tarfile.open(fileobj=io.BytesIO(install_data), mode="r:")
        except (KeyError, tarfile.TarError, OSError, ResourceLimitError) as exc:
            errors.append(f"invalid install.tar.xz: {exc}")
            return errors
        with install:
            members = {}
            for member_index, member in enumerate(install, 1):
                if member_index > MAX_ARCHIVE_MEMBERS:
                    errors.append("too many members in install archive")
                    break
                try:
                    normalized = _safe_tar_name(member.name)
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                if normalized in members:
                    errors.append(f"duplicate install archive member: {normalized}")
                members[normalized] = member
            for node in file_nodes:
                rel = (node.findtext("Path") or "").strip().lstrip("/")
                if not rel:
                    errors.append("files.xml contains an empty Path")
                    continue
                try:
                    rel = _safe_tar_name(rel)
                except ValueError as exc:
                    errors.append(f"unsafe files.xml path: {exc}")
                    continue
                member = members.get(rel)
                if member is None:
                    errors.append(f"files.xml entry missing from install archive: {rel}")
                    continue
                if member.isdir():
                    continue
                try:
                    expected_size = int((node.findtext("Size") or "0").strip())
                    expected_uid = int((node.findtext("Uid") or "0").strip())
                    expected_gid = int((node.findtext("Gid") or "0").strip())
                    expected_mode = int((node.findtext("Mode") or "0"), 8)
                except ValueError:
                    errors.append(f"invalid metadata for {rel}")
                    continue
                if member.uid != expected_uid or member.gid != expected_gid:
                    errors.append(f"ownership mismatch for {rel}")
                if stat.S_IMODE(member.mode) != stat.S_IMODE(expected_mode):
                    errors.append(f"mode mismatch for {rel}")
                if member.isreg() and member.size != expected_size:
                    errors.append(f"size mismatch for {rel}: manifest={expected_size}, archive={member.size}")
                expected_hash = (node.findtext("Hash") or node.findtext("SHA1Sum") or "").strip()
                if expected_hash:
                    actual_hash = _member_sha1(install, member)
                    if actual_hash != expected_hash:
                        errors.append(f"SHA-1 mismatch for {rel}")
            for rel, member in members.items():
                if member.ischr() or member.isblk() or member.isfifo():
                    errors.append(f"unsupported special file in install archive: {rel}")
                elif not member.isdir() and rel not in manifest_set:
                    errors.append(f"install archive member missing from files.xml: {rel}")
    return errors


def _safe_tar_name(name: str) -> str:
    if len(name.encode("utf-8", "surrogatepass")) > MAX_ARCHIVE_PATH_BYTES:
        raise ValueError("install archive member path exceeds the safety limit")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe install archive member: {name}")
    return "/".join(part for part in path.parts if part not in ("", "."))


def _member_sha1(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    if member.issym():
        return hashlib.sha1(member.linkname.encode()).hexdigest()
    stream = archive.extractfile(member)
    if stream is None:
        return ""
    digest = hashlib.sha1()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()
