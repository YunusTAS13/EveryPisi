from __future__ import annotations

import hashlib
import os
import stat
import tarfile
import tempfile
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from .errors import ConversionRefused
from .elf import TARGET_ELF_PROFILES, elf_compatibility_issues
from .formats.base import is_pisi_release, is_pisi_version, parse_dependency_group
from .model import DependencyGroup, FileEntry, ParsedPackage
from .repository import PisiRepository, _version_compare
from .validator import validate_pisi_package


ARCH_MAP = {
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "i386": "i686",
    "i686": "i686",
    "all": "any",
    "any": "any",
    "noarch": "any",
}
SUPPORTED_TARGET_ARCHES = frozenset(TARGET_ELF_PROFILES)


def pisi_architecture(source_arch: str) -> str:
    return ARCH_MAP.get(source_arch, source_arch)


def _incompatible_dependency_architectures(package: ParsedPackage, target_arch: str) -> list[str]:
    """Find foreign dependency qualifiers that Pisi 1.2 cannot encode."""
    incompatible: set[str] = set()
    for group in package.dependencies:
        if group.scope != "runtime":
            continue
        for atom in group.alternatives:
            if not atom.architecture:
                continue
            qualified = pisi_architecture(atom.architecture)
            if qualified not in ("any", target_arch):
                incompatible.add(atom.raw or f"{atom.name}:{atom.architecture}")
    return sorted(incompatible)


def _invalid_release_relations(groups: list[DependencyGroup]) -> list[str]:
    invalid = []
    for group in groups:
        for atom in group.alternatives:
            for label, value in (("release", atom.release), ("releaseFrom", atom.release_from),
                                 ("releaseTo", atom.release_to)):
                if value is not None and not is_pisi_release(value):
                    invalid.append(f"{atom.name} {label}={value!r}")
    return sorted(set(invalid))


def _text(parent: ET.Element, tag: str, value: str | int, **attrs) -> ET.Element:
    element = ET.SubElement(parent, tag, attrs)
    element.text = str(value)
    return element


def _indent(root: ET.Element) -> bytes:
    ET.indent(root, space="    ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def build_metadata(package: ParsedPackage, dependencies: list[DependencyGroup], distribution_release: str,
                   distribution_id: str, target_arch: str, install_tar_hash: str = "",
                   conflicts: list[DependencyGroup] | None = None,
                   replaces: list[DependencyGroup] | None = None) -> bytes:
    root = ET.Element("PISI")
    source = ET.SubElement(root, "Source")
    _text(source, "Name", package.name)
    _text(source, "Homepage", package.homepage)
    packager = ET.SubElement(source, "Packager")
    _text(packager, "Name", "EveryPisi")
    _text(packager, "Email", "everypisi@localhost")
    result = ET.SubElement(root, "Package")
    _text(result, "Name", package.name)
    _text(result, "Summary", package.summary or package.name)
    _text(result, "Description", package.description or package.summary or package.name)
    _text(result, "License", package.license or "Unknown")
    _text(result, "IsA", "app:console" if any(f.path.startswith(("usr/bin/", "bin/")) for f in package.files) else "app:gui")
    runtime = [group for group in dependencies if group.scope == "runtime"]
    if runtime:
        dep_node = ET.SubElement(result, "RuntimeDependencies")
        for group in runtime:
            if len(group.alternatives) == 1:
                atom = group.alternatives[0]
                attrs = {}
                if atom.operator in (">=", ">"):
                    attrs["versionFrom"] = atom.version or ""
                elif atom.operator in ("<=", "<"):
                    attrs["versionTo"] = atom.version or ""
                elif atom.operator == "=":
                    attrs["version"] = atom.version or ""
                if atom.version_to:
                    attrs["versionTo"] = atom.version_to
                _release_attrs(attrs, atom)
                _text(dep_node, "Dependency", atom.name, **attrs)
            else:
                any_node = ET.SubElement(dep_node, "AnyDependency")
                for atom in group.alternatives:
                    _text(any_node, "Dependency", atom.name, **_relation_attrs(atom))
    conflict_groups = conflicts or []
    if conflict_groups:
        conflict_node = ET.SubElement(result, "Conflicts")
        for group in conflict_groups:
            for atom in group.alternatives:
                _text(conflict_node, "Package", atom.name, **_relation_attrs(atom))
    replace_groups = replaces or []
    if replace_groups:
        replace_node = ET.SubElement(result, "Replaces")
        for group in replace_groups:
            for atom in group.alternatives:
                _text(replace_node, "Package", atom.name, **_relation_attrs(atom))
    files_node = ET.SubElement(result, "Files")
    for entry in package.files:
        if entry.kind == "directory":
            continue
        _text(files_node, "Path", "/" + entry.path, fileType=_pisi_file_type(entry))
    history = ET.SubElement(result, "History")
    update = ET.SubElement(history, "Update", {"release": package.release})
    _text(update, "Date", _build_date())
    _text(update, "Version", package.version)
    _text(update, "Comment", f"Converted from {package.source_format} by EveryPisi")
    _text(update, "Name", "EveryPisi")
    _text(update, "Email", "everypisi@localhost")
    _text(result, "Build", 0)
    _text(result, "Distribution", "PisiLinux")
    _text(result, "DistributionRelease", distribution_release)
    _text(result, "Architecture", target_arch)
    _text(result, "InstalledSize", sum(item.size for item in package.files))
    if install_tar_hash:
        _text(result, "InstallTarHash", install_tar_hash)
    _text(result, "PackageFormat", "1.2")
    nested_source = ET.SubElement(result, "Source")
    _text(nested_source, "Name", package.name)
    _text(nested_source, "Homepage", package.homepage)
    nested_packager = ET.SubElement(nested_source, "Packager")
    _text(nested_packager, "Name", "EveryPisi")
    _text(nested_packager, "Email", "everypisi@localhost")
    return _indent(root)


def _relation_attrs(atom) -> dict[str, str]:
    attrs: dict[str, str] = {}
    if atom.operator in (">=", ">"):
        attrs["versionFrom"] = atom.version or ""
    elif atom.operator in ("<=", "<"):
        attrs["versionTo"] = atom.version or ""
    elif atom.operator == "=":
        attrs["version"] = atom.version or ""
    if atom.version_to:
        attrs["versionTo"] = atom.version_to
    _release_attrs(attrs, atom)
    return attrs


def _release_attrs(attrs: dict[str, str], atom) -> None:
    if atom.release:
        attrs["release"] = atom.release
    if atom.release_from:
        attrs["releaseFrom"] = atom.release_from
    if atom.release_to:
        attrs["releaseTo"] = atom.release_to


def _build_date() -> str:
    """Honor SOURCE_DATE_EPOCH while retaining a normal current-date default."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), timezone.utc).date().isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    return date.today().isoformat()


def _pisi_file_type(entry: FileEntry) -> str:
    path = entry.path.lower()
    if entry.kind == "symlink":
        return "data"
    if "/usr/share/man/" in "/" + path or path.endswith(tuple(f".{n}" for n in range(1, 10))):
        return "man"
    if "/usr/share/doc/" in "/" + path or "/usr/share/licenses/" in "/" + path:
        return "doc"
    if path.startswith("etc/"):
        return "config"
    if "/usr/share/locale/" in "/" + path:
        return "localedata"
    if path.startswith("usr/include/"):
        return "header"
    if ".so" in path or path.startswith(("lib/", "usr/lib/", "usr/lib64/")):
        return "library"
    if entry.mode & 0o111:
        return "executable"
    return "data"


def build_files_xml(files: list[FileEntry]) -> bytes:
    root = ET.Element("Files")
    for item in files:
        node = ET.SubElement(root, "File")
        _text(node, "Path", item.path)
        _text(node, "Type", _pisi_file_type(item))
        _text(node, "Size", item.size)
        _text(node, "Uid", item.uid)
        _text(node, "Gid", item.gid)
        _text(node, "Mode", format(item.mode, "04o"))
        if item.sha1:
            _text(node, "Hash", item.sha1)
    return _indent(root)


def build_install_archive(root: Path, destination: Path, entries: list[FileEntry] | None = None,
                          source_metadata: dict[str, dict[str, int]] | None = None) -> None:
    entry_map = dict(source_metadata or {})
    entry_map.update({entry.path: entry for entry in (entries or [])})
    with tarfile.open(destination, mode="w:xz", preset=6, dereference=False) as archive:
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            directories.sort()
            files.sort()
            for name in directories + files:
                path = Path(current) / name
                arcname = path.relative_to(root).as_posix()
                info = archive.gettarinfo(str(path), arcname=arcname)
                info = _tar_filter(info, entry_map)
                if info is None:
                    continue
                if info.isreg():
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)


def _tar_filter(info: tarfile.TarInfo, entry_map: dict[str, FileEntry]) -> tarfile.TarInfo | None:
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    entry = entry_map.get(info.name)
    if isinstance(entry, FileEntry):
        info.uid = entry.uid
        info.gid = entry.gid
        info.mode = entry.mode
    elif entry:
        info.uid = entry.get("uid", info.uid)
        info.gid = entry.get("gid", info.gid)
        info.mode = entry.get("mode", info.mode)
    if info.isreg() or info.isdir() or info.issym() or info.islnk():
        return info
    return None


def convert_to_pisi(package: ParsedPackage, output_dir: Path, *, repository: PisiRepository | None = None,
                    allow_unresolved: bool = False, distribution_release: str = "2.0",
                    distribution_id: str = "p2", target_arch: str = "x86_64",
                    allow_foreign_scripts: bool = False,
                    allow_privileged_files: bool = False,
                    allow_unsupported_metadata: bool = False,
                    allow_lossy_relations: bool = False,
                    allow_unverified_signatures: bool = False) -> Path:
    if not package.payload_root or not package.payload_root.is_dir():
        raise ConversionRefused("package payload is not available")
    if target_arch not in SUPPORTED_TARGET_ARCHES:
        raise ConversionRefused(
            f"unsupported Pisi target architecture: {target_arch!r}; "
            f"supported values: {', '.join(sorted(SUPPORTED_TARGET_ARCHES))}"
        )
    for label, value in (("package name", package.name), ("package version", package.version),
                         ("package release", package.release), ("distribution id", distribution_id),
                         ("target architecture", target_arch)):
        if (not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value
                or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ConversionRefused(f"unsafe {label}: {value!r}")
    if not is_pisi_version(package.version):
        raise ConversionRefused(
            f"package version is not valid Pisi syntax: {package.version!r}; "
            "normalize it in a native rebuild before conversion"
        )
    all_relations = list(package.dependencies)
    all_relations.extend(parse_dependency_group(raw, "conflict") for raw in package.conflicts)
    all_relations.extend(parse_dependency_group(raw, "replace") for raw in package.replaces)
    invalid_releases = _invalid_release_relations([group for group in all_relations if group])
    if not is_pisi_release(package.release) or invalid_releases:
        detail = invalid_releases or [f"package release={package.release!r}"]
        raise ConversionRefused("invalid Pisi numeric release relation: " + ", ".join(detail))
    source_arch = pisi_architecture(package.architecture)
    if source_arch not in ("any", target_arch):
        raise ConversionRefused(f"architecture mismatch: source={source_arch}, target={target_arch}")
    elf_mismatches = [
        f"{code}:{detail}"
        for elf in package.elf_files
        for code, detail in elf_compatibility_issues(elf, target_arch)
    ]
    if elf_mismatches:
        raise ConversionRefused("ELF ABI is incompatible with target: " + ", ".join(elf_mismatches))
    incompatible_dependency_arches = _incompatible_dependency_architectures(package, target_arch)
    if incompatible_dependency_arches and not allow_unsupported_metadata:
        raise ConversionRefused(
            "Pisi 1.2 cannot encode foreign architecture-qualified runtime dependencies: " +
            ", ".join(incompatible_dependency_arches) +
            "; use --allow-unsupported-metadata only after review"
        )
    if package.scripts and not allow_foreign_scripts:
        names = ", ".join(script.name for script in package.scripts)
        raise ConversionRefused(
            f"foreign install hooks are not portable to Pisi and are disabled: {names}; "
            "review/rebuild the package or use --allow-foreign-scripts to acknowledge the risk"
        )
    privileged = [flag for flag in package.file_flags if flag.startswith(("setuid:", "setgid:"))]
    if privileged and not allow_privileged_files:
        raise ConversionRefused(
            "privileged files are disabled by default: " + ", ".join(privileged) +
            "; review the package or use --allow-privileged-files to acknowledge the risk"
        )
    if package.metadata_flags and not allow_unsupported_metadata:
        raise ConversionRefused(
            "source metadata or relations cannot be retained by Pisi 1.2: " + ", ".join(package.metadata_flags) +
            "; use --allow-unsupported-metadata only after review"
        )
    omitted_runtime_relations = [
        flag for flag in package.metadata_flags
        if flag.startswith("rpm-requires-not-supported:")
    ]
    if omitted_runtime_relations and not allow_unresolved:
        raise ConversionRefused(
            "RPM runtime capability relations would be omitted: " + ", ".join(omitted_runtime_relations) +
            "; use --allow-unresolved together with --allow-unsupported-metadata only after review"
        )
    has_verified_package_signature = any(
        package.source_integrity.get(name) == "verified"
        for name in ("detached-openpgp", "debian-embedded-signature")
    )
    unverified_signatures = [name for name, status in package.source_integrity.items()
                             if status == "present-unverified" and not has_verified_package_signature]
    if unverified_signatures and not allow_unverified_signatures:
        raise ConversionRefused(
            "source signature is present but not keyring-verified: " + ", ".join(unverified_signatures) +
            "; verify it externally or use --allow-unverified-signature to acknowledge the risk"
        )
    resolved, unresolved = resolve_runtime_dependencies(package, repository)
    transitive_resolved: list[str] = []
    transitive_unresolved: list[str] = []
    if repository and not unresolved:
        roots = [atom.name for group in resolved for atom in group.alternatives]
        transitive_resolved, transitive_unresolved = repository.dependency_closure(roots)
        if transitive_unresolved and not allow_unresolved:
            raise ConversionRefused(
                "unresolved transitive runtime dependencies: " + ", ".join(transitive_unresolved)
            )
    conflicts, unresolved_conflicts = resolve_conflicts(package, repository)
    replaces, unresolved_replaces = resolve_replaces(package, repository)
    lossy_relations = find_lossy_relations(resolved + conflicts + replaces)
    if lossy_relations and not allow_lossy_relations:
        raise ConversionRefused(
            "Pisi metadata cannot represent strict version relations exactly: " + ", ".join(lossy_relations) +
            "; use --allow-lossy-relations only after review"
        )
    if unresolved and not allow_unresolved:
        raise ConversionRefused("unresolved runtime dependencies: " + ", ".join(unresolved))
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_version = package.version.replace(":", "_").replace("/", "_")
    filename = f"{package.name}-{safe_version}-{package.release}-{distribution_id}-{target_arch}.pisi"
    final_path = output_dir / filename
    with tempfile.TemporaryDirectory(prefix="everypisi-build-") as temp:
        install_tar = Path(temp) / "install.tar.xz"
        build_install_archive(package.payload_root, install_tar, package.files, package.payload_metadata)
        install_tar_hash = hashlib.sha1(install_tar.read_bytes()).hexdigest()
        metadata = build_metadata(package, resolved, distribution_release, distribution_id, target_arch,
                                   install_tar_hash, conflicts, replaces)
        files_xml = build_files_xml(package.files)
        temporary_fd, temporary_name = tempfile.mkstemp(prefix=".everypisi-output-",
                                                        suffix=".tmp", dir=output_dir)
        os.close(temporary_fd)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(_deterministic_zip_info("metadata.xml", zipfile.ZIP_DEFLATED), metadata)
                archive.writestr(_deterministic_zip_info("files.xml", zipfile.ZIP_DEFLATED), files_xml)
                archive.writestr(_deterministic_zip_info("install.tar.xz", zipfile.ZIP_STORED), install_tar.read_bytes())
            os.replace(temporary, final_path)
        finally:
            temporary.unlink(missing_ok=True)
    validation_errors = validate_pisi_package(final_path, strict_install_tar_hash=True)
    if validation_errors:
        final_path.unlink(missing_ok=True)
        raise ConversionRefused("generated Pisi package failed validation: " + "; ".join(validation_errors))
    return final_path


def _deterministic_zip_info(name: str, compression: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (0o100644 << 16)
    info.compress_type = compression
    return info


def resolve_runtime_dependencies(package: ParsedPackage, repository: PisiRepository | None = None) -> tuple[list[DependencyGroup], list[str]]:
    unresolved: list[str] = []
    resolved: list[DependencyGroup] = []
    for group in package.dependencies:
        if group.scope != "runtime":
            continue
        chosen = repository.resolve_atom(group) if repository else None
        if repository and chosen:
            resolved.append(DependencyGroup((chosen,), group.scope))
        elif repository and not chosen:
            unresolved.append(" | ".join(atom.raw or atom.name for atom in group.alternatives))
            resolved.append(group)
        else:
            resolved.append(group)
            unresolved.append(" | ".join(atom.raw or atom.name for atom in group.alternatives))
    return _deduplicate_dependencies(resolved), unresolved


def resolve_conflicts(package: ParsedPackage, repository: PisiRepository | None = None) -> tuple[list[DependencyGroup], list[str]]:
    resolved: list[DependencyGroup] = []
    unresolved: list[str] = []
    for raw in package.conflicts:
        group = parse_dependency_group(raw, "conflict")
        if not group:
            continue
        chosen = repository.resolve_atom(group) if repository else None
        if repository and chosen:
            resolved.append(DependencyGroup((chosen,), "conflict"))
        elif repository:
            unresolved.append(" | ".join(atom.raw or atom.name for atom in group.alternatives))
            resolved.append(group)
        else:
            resolved.append(group)
    return _deduplicate_dependencies(resolved), unresolved


def resolve_replaces(package: ParsedPackage, repository: PisiRepository | None = None) -> tuple[list[DependencyGroup], list[str]]:
    resolved: list[DependencyGroup] = []
    unresolved: list[str] = []
    for raw in package.replaces:
        group = parse_dependency_group(raw, "replace")
        if not group:
            continue
        chosen = repository.resolve_atom(group) if repository else None
        if repository and chosen:
            resolved.append(DependencyGroup((chosen,), group.scope))
        elif repository:
            unresolved.append(" | ".join(atom.raw or atom.name for atom in group.alternatives))
            resolved.append(group)
        else:
            resolved.append(group)
    return _deduplicate_dependencies(resolved), unresolved


def _deduplicate_dependencies(groups: list[DependencyGroup]) -> list[DependencyGroup]:
    """Deduplicate without weakening multiple constraints for one package."""
    result: list[DependencyGroup] = []
    for group in groups:
        if len(group.alternatives) != 1:
            result.append(group)
            continue
        atom = group.alternatives[0]
        match_index = next((index for index, previous in enumerate(result)
                            if len(previous.alternatives) == 1
                            and previous.scope == group.scope
                            and previous.alternatives[0].name == atom.name), None)
        if match_index is None:
            result.append(group)
            continue
        old = result[match_index].alternatives[0]
        release_signature = (atom.release, atom.release_from, atom.release_to)
        old_release_signature = (old.release, old.release_from, old.release_to)
        if release_signature != old_release_signature:
            result.append(group)
            continue
        if old.operator is None:
            if atom.operator is not None:
                result[match_index] = group
            continue
        if atom.operator is None:
            continue
        if old.operator != atom.operator or not old.version or not atom.version:
            result.append(group)
            continue
        comparison = _version_compare(old.version, atom.version)
        stronger = atom if (
            atom.operator in (">=", ">") and comparison < 0
        ) or (
            atom.operator in ("<=", "<") and comparison > 0
        ) else old
        result[match_index] = DependencyGroup((stronger,), group.scope)
    return result


def find_lossy_relations(groups: list[DependencyGroup]) -> list[str]:
    """Return strict foreign bounds that Pisi 1.2 cannot represent exactly."""
    return sorted({
        f"{atom.name} {atom.operator} {atom.version}"
        for group in groups
        for atom in group.alternatives
        if atom.operator in ("<", ">") and atom.version
    })
