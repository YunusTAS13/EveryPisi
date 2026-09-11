from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .errors import UnsupportedFormatError
from .elf import analyze_payload
from .compatibility import assess
from .formats import ArchParser, DebParser, RpmParser
from .model import DependencyAtom, DependencyGroup, ParsedPackage
from .signatures import verify_debsig_signature, verify_detached_signature
from .util import file_hashes


PARSERS = (DebParser(), RpmParser(), ArchParser())


def detect_format(path: Path) -> str:
    with path.open("rb") as stream:
        magic = stream.read(8)
    if magic.startswith(b"!<arch>"):
        return "deb"
    if magic.startswith(bytes.fromhex("ed ab ee db")):
        return "rpm"
    if path.name.endswith((".pkg.tar", ".pkg.tar.gz", ".pkg.tar.bz2", ".pkg.tar.xz", ".pkg.tar.zst")):
        return "arch"
    if magic[:2] == b"\x1f\x8b" or magic[:3] == b"BZh" or magic[:6] == bytes.fromhex("fd 37 7a 58 5a 00") or magic[:4] == bytes.fromhex("28 b5 2f fd"):
        return "arch"
    try:
        import tarfile
        if tarfile.is_tarfile(path):
            return "arch"
    except (OSError, tarfile.TarError):
        pass
    raise UnsupportedFormatError(f"unsupported package format: {path}")


def parse_package(path: str | Path, keep_workdir: bool = False, *, signature_keyring: Path | None = None,
                  detached_signature: Path | None = None, debsig_policies_dir: Path | None = None,
                  debsig_keyrings_dir: Path | None = None, debsig_root: Path | None = None
                  ) -> tuple[ParsedPackage, tempfile.TemporaryDirectory | None]:
    package = Path(path).expanduser().resolve()
    if not package.is_file():
        raise FileNotFoundError(package)
    fmt = detect_format(package)
    detached_integrity = None
    if detached_signature:
        if not signature_keyring:
            raise UnsupportedFormatError("a keyring is required with --detached-signature")
        detached_integrity = verify_detached_signature(package, detached_signature, signature_keyring)
    if (debsig_policies_dir is None) != (debsig_keyrings_dir is None):
        raise UnsupportedFormatError("--debsig-policies-dir and --debsig-keyrings-dir must be used together")
    if (debsig_policies_dir or debsig_keyrings_dir or debsig_root) and fmt != "deb":
        raise UnsupportedFormatError("Debian debsig options can only be used with a .deb package")
    work = tempfile.TemporaryDirectory(prefix="everypisi-parse-")
    parser = next(parser for parser in PARSERS if parser.format_name == fmt)
    try:
        parsed = parser.parse(package, Path(work.name), signature_keyring=signature_keyring)
        if debsig_policies_dir and debsig_keyrings_dir:
            parsed.source_integrity["debian-embedded-signature"] = verify_debsig_signature(
                package, debsig_policies_dir, debsig_keyrings_dir, debsig_root
            )
            parsed.warnings = [
                warning for warning in parsed.warnings
                if not warning.startswith("Debian embedded signature requires")
            ]
        if detached_integrity:
            parsed.source_integrity["detached-openpgp"] = detached_integrity
    except Exception:
        work.cleanup()
        raise
    try:
        if parsed.payload_root:
            elf_files, script_interpreters, file_flags = analyze_payload(parsed.payload_root)
            parsed.elf_files = [item.__dict__ for item in elf_files]
            parsed.script_interpreters = script_interpreters
            parsed.file_flags = file_flags
            parsed.metadata_flags = sorted(set(parsed.metadata_flags))
            existing = {(atom.name, atom.operator, atom.version)
                        for group in parsed.dependencies for atom in group.alternatives}
            for elf in elf_files:
                for library in elf.needed:
                    key = (library, None, None)
                    if key not in existing:
                        parsed.dependencies.append(DependencyGroup((DependencyAtom(library, raw=library),), "runtime"))
                        existing.add(key)
                for library, version in elf.version_requirements.items():
                    key = (library, ">=", version)
                    if key not in existing:
                        parsed.dependencies.append(DependencyGroup((DependencyAtom(library, ">=", version, raw=f"{library} >= {version}"),), "runtime"))
                        existing.add(key)
    except Exception:
        work.cleanup()
        raise
    return parsed, work if keep_workdir else _cleanup(work)


def _cleanup(work: tempfile.TemporaryDirectory):
    work.cleanup()
    return None


def report(package: ParsedPackage, target_arch: str = "x86_64") -> dict:
    return {
        "source": str(package.source_path),
        "source_size": package.source_path.stat().st_size,
        "source_hashes": file_hashes(package.source_path),
        "format": package.source_format,
        "name": package.name,
        "version": package.version,
        "release": package.release,
        "architecture": package.architecture,
        "summary": package.summary,
        "payload_files": len(package.files),
        "payload_bytes": sum(item.size for item in package.files),
        "dependencies": [
            {"scope": group.scope, "alternatives": [atom.__dict__ for atom in group.alternatives]}
            for group in package.dependencies
        ],
        "scripts": [
            {"name": script.name, "interpreter": script.interpreter, "risk_flags": script.risk_flags}
            for script in package.scripts
        ],
        "elf_files": package.elf_files,
        "script_interpreters": package.script_interpreters,
        "file_flags": package.file_flags,
        "metadata_flags": package.metadata_flags,
        "source_integrity": package.source_integrity,
        "compatibility": assess(package, target_arch),
        "warnings": package.warnings,
        "errors": package.errors,
        "replaces": package.replaces,
    }


def report_json(package: ParsedPackage, target_arch: str = "x86_64") -> str:
    return json.dumps(report(package, target_arch), ensure_ascii=False, indent=2)
