from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .analyzer import parse_package, report, report_json
from .compatibility import assess
from .errors import EveryPisiError
from .pisi_builder import (convert_to_pisi, find_lossy_relations, resolve_conflicts,
                            resolve_replaces, resolve_runtime_dependencies)
from .rebuild import rebuild_recipe
from .repository import DEFAULT_PISI_INDEX, PisiRepository
from .validator import validate_pisi_package


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="everypisi", description="Analyze and convert Debian, RPM and Arch packages for Pisi Linux")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="analyze a foreign package without installing or executing it")
    inspect.add_argument("package", type=Path)
    inspect.add_argument("--json", action="store_true")
    inspect.add_argument("--rpm-keyring", type=Path,
                         help="trusted GPG keyring for verifying embedded RPM OpenPGP signatures")
    inspect.add_argument("--detached-signature", type=Path,
                         help="detached OpenPGP signature for the source package")
    inspect.add_argument("--keyring", type=Path,
                         help="trusted GPG keyring for --detached-signature")
    inspect.add_argument("--debsig-policies-dir", type=Path,
                         help="debsig-verify policy directory for embedded Debian signatures")
    inspect.add_argument("--debsig-keyrings-dir", type=Path,
                         help="debsig-verify keyrings directory for embedded Debian signatures")
    inspect.add_argument("--debsig-root", type=Path,
                         help="optional debsig-verify root directory")
    validate = sub.add_parser("validate", help="validate a Pisi 1.2 package archive")
    validate.add_argument("package", type=Path)
    validate.add_argument("--strict-install-tar-hash", action="store_true")
    convert = sub.add_parser("convert", help="create a Pisi-compatible .pisi package")
    convert.add_argument("package", type=Path)
    convert.add_argument("--output-dir", type=Path, required=True)
    repository_source = convert.add_mutually_exclusive_group()
    repository_source.add_argument("--repo-index", help="local path or URL to a Pisi pisi-index.xml")
    repository_source.add_argument("--offline", action="store_true", help="do not download the official Pisi index")
    convert.add_argument("--repo-index-sha1", metavar="HEX",
                         help="expected SHA-1 of --repo-index (compressed bytes when .xz)")
    convert.add_argument("--allow-unverified-repository", action="store_true",
                         help="use a custom repository index without an expected SHA-1; review the risk")
    convert.add_argument("--dependency-map", type=Path, help="JSON map of foreign dependency names to Pisi names")
    convert.add_argument("--allow-unresolved", action="store_true")
    convert.add_argument("--allow-foreign-scripts", action="store_true",
                         help="convert despite disabled foreign maintainer scripts; review the report")
    convert.add_argument("--allow-privileged-files", action="store_true",
                         help="convert SUID/SGID files; review the report")
    convert.add_argument("--allow-unsupported-metadata", action="store_true",
                         help="convert despite xattr/ACL/capability metadata loss; review the report")
    convert.add_argument("--allow-unverified-signature", action="store_true",
                         help="convert a package whose embedded signature is present but not keyring-verified")
    convert.add_argument("--rpm-keyring", type=Path,
                         help="trusted GPG keyring for verifying embedded RPM OpenPGP signatures")
    convert.add_argument("--detached-signature", type=Path,
                         help="detached OpenPGP signature for the source package")
    convert.add_argument("--keyring", type=Path,
                         help="trusted GPG keyring for --detached-signature")
    convert.add_argument("--debsig-policies-dir", type=Path,
                         help="debsig-verify policy directory for embedded Debian signatures")
    convert.add_argument("--debsig-keyrings-dir", type=Path,
                         help="debsig-verify keyrings directory for embedded Debian signatures")
    convert.add_argument("--debsig-root", type=Path,
                         help="optional debsig-verify root directory")
    convert.add_argument("--allow-lossy-relations", action="store_true",
                         help="allow strict < or > relations to be approximated by Pisi bounds")
    convert.add_argument("--distribution-release", default="2.0")
    convert.add_argument("--distribution-id", default="p2")
    convert.add_argument("--target-arch", default="x86_64")
    convert.add_argument("--report", type=Path, help="write conversion report JSON")
    rebuild = sub.add_parser("rebuild", help="build a Pisi-native pspec.xml/actions.py recipe")
    rebuild.add_argument("recipe_dir", type=Path)
    rebuild.add_argument("--output-dir", type=Path, required=True)
    rebuild.add_argument("--pisi-command", default="pisi")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            errors = validate_pisi_package(args.package, strict_install_tar_hash=args.strict_install_tar_hash)
            if errors:
                for error in errors:
                    print(f"ERROR: {error}", file=sys.stderr)
                return 1
            print(f"valid: {args.package}")
            return 0
        if args.command == "inspect":
            package, work = parse_package(args.package, keep_workdir=False,
                                          signature_keyring=args.rpm_keyring or args.keyring,
                                          detached_signature=args.detached_signature,
                                          debsig_policies_dir=args.debsig_policies_dir,
                                          debsig_keyrings_dir=args.debsig_keyrings_dir,
                                          debsig_root=args.debsig_root)
            print(report_json(package) if args.json else _human_report(package))
            return 0 if not package.errors else 2
        if args.command == "rebuild":
            result = rebuild_recipe(args.recipe_dir, args.output_dir, pisi_command=args.pisi_command)
            for output in result.output_packages:
                print(output)
            return 0
        package, work = parse_package(args.package, keep_workdir=True,
                                      signature_keyring=args.rpm_keyring or args.keyring,
                                      detached_signature=args.detached_signature,
                                      debsig_policies_dir=args.debsig_policies_dir,
                                      debsig_keyrings_dir=args.debsig_keyrings_dir,
                                      debsig_root=args.debsig_root)
        try:
            if args.repo_index:
                repository = PisiRepository.load(args.repo_index, expected_sha1=args.repo_index_sha1)
            elif args.offline:
                if args.repo_index_sha1:
                    raise ValueError("--repo-index-sha1 requires --repo-index")
                repository = PisiRepository()
            else:
                repository = PisiRepository.load_cached(DEFAULT_PISI_INDEX)
            if (args.repo_index and repository.integrity != "sha1-verified"
                    and not args.allow_unverified_repository):
                raise ValueError(
                    "custom repository index is not checksum-verified; pass --repo-index-sha1 "
                    "or explicitly use --allow-unverified-repository"
                )
            target_errors = repository.target_errors("PisiLinux", args.distribution_release, args.target_arch)
            if target_errors:
                raise ValueError("repository does not match requested target: " + "; ".join(target_errors))
            if args.dependency_map:
                mapping = json.loads(args.dependency_map.read_text(encoding="utf-8"))
                if not isinstance(mapping, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in mapping.items()):
                    raise ValueError("dependency map must be a JSON object of string names")
                repository.aliases.update(mapping)
                repository.packages.update(mapping.values())
            result = convert_to_pisi(package, args.output_dir, repository=repository,
                                     allow_unresolved=args.allow_unresolved,
                                     distribution_release=args.distribution_release,
                                     distribution_id=args.distribution_id,
                                     target_arch=args.target_arch,
                                     allow_foreign_scripts=args.allow_foreign_scripts,
                                     allow_privileged_files=args.allow_privileged_files,
                                     allow_unsupported_metadata=args.allow_unsupported_metadata,
                                     allow_lossy_relations=args.allow_lossy_relations,
                                     allow_unverified_signatures=args.allow_unverified_signature)
            report_path = args.report or result.with_suffix(result.suffix + ".json")
            conversion_report = report(package, args.target_arch)
            resolved, unresolved = resolve_runtime_dependencies(package, repository)
            transitive_resolved, transitive_unresolved = repository.dependency_closure(
                [atom.name for group in resolved for atom in group.alternatives]
            ) if not unresolved else ([], [])
            resolved_conflicts, unresolved_conflicts = resolve_conflicts(package, repository)
            resolved_replaces, unresolved_replaces = resolve_replaces(package, repository)
            conversion_report["conversion"] = {
                "output": str(result),
                "output_size": result.stat().st_size,
                "output_hashes": _file_hashes(result),
                "target_architecture": args.target_arch,
                "repository_identity": {
                    "distribution": repository.distribution,
                    "release": repository.distribution_release,
                    "architectures": sorted(repository.architectures),
                    "integrity": repository.integrity,
                    "unverified_repository_acknowledged": args.allow_unverified_repository,
                },
                "resolved_dependencies": [
                    {"scope": group.scope, "alternatives": [atom.__dict__ for atom in group.alternatives]}
                    for group in resolved
                ],
                "unresolved_dependencies": unresolved,
                "omitted_runtime_relations": [
                    flag for flag in package.metadata_flags
                    if flag.startswith("rpm-requires-not-supported:")
                ],
                "transitive_dependencies": transitive_resolved,
                "unresolved_transitive_dependencies": transitive_unresolved,
                "resolved_conflicts": [
                    {"scope": group.scope, "alternatives": [atom.__dict__ for atom in group.alternatives]}
                    for group in resolved_conflicts
                ],
                "unresolved_conflicts": unresolved_conflicts,
                "resolved_replaces": [
                    {"scope": group.scope, "alternatives": [atom.__dict__ for atom in group.alternatives]}
                    for group in resolved_replaces
                ],
                "unresolved_replaces": unresolved_replaces,
                "lossy_relations": find_lossy_relations(resolved + resolved_conflicts + resolved_replaces),
                "omitted_non_runtime_dependencies": [
                    {"scope": group.scope, "alternatives": [atom.__dict__ for atom in group.alternatives]}
                    for group in package.dependencies if group.scope != "runtime"
                ],
                "foreign_scripts_copied": False,
                "unverified_signature_acknowledged": args.allow_unverified_signature,
            }
            report_path.write_text(json.dumps(conversion_report, ensure_ascii=False, indent=2), encoding="utf-8")
            print(result)
            return 0
        finally:
            work.cleanup()
    except (EveryPisiError, OSError, ValueError) as exc:
        print(f"everypisi: error: {exc}", file=sys.stderr)
        return 1


def _human_report(package) -> str:
    compatibility = assess(package)
    lines = [f"Package: {package.name}", f"Version: {package.version}",
             f"Format: {package.source_format}", f"Architecture: {package.architecture}",
             f"Payload entries: {len(package.files)}", f"Scripts: {len(package.scripts)}",
             f"Compatibility: {compatibility['level']} ({compatibility['recommendation']})"]
    if package.scripts:
        lines.append("Script policy: disabled; review before Pisi-native porting")
    if package.warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in package.warnings)
    return "\n".join(lines)


def _file_hashes(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("sha256", "sha512")}
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}
