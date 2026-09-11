from __future__ import annotations

from typing import Any

from .elf import elf_compatibility_issues
from .model import ParsedPackage
from .pisi_builder import pisi_architecture


def assess(package: ParsedPackage, target_arch: str = "x86_64") -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    source_arch = pisi_architecture(package.architecture)
    if source_arch not in ("any", target_arch):
        issues.append({"severity": "critical", "code": "architecture-mismatch", "detail": f"{source_arch} cannot run on {target_arch}"})
    for flag in package.file_flags:
        if flag.startswith(("setuid:", "setgid:")):
            issues.append({"severity": "high", "code": "privileged-file", "detail": flag})
    for flag in package.metadata_flags:
        issues.append({"severity": "high", "code": "unsupported-file-metadata", "detail": flag})
    for name, status in package.source_integrity.items():
        if status == "present-unverified":
            issues.append({"severity": "high", "code": "unverified-source-signature",
                           "detail": f"{name}: embedded signature was not verified against a trusted keyring"})
    if package.scripts:
        issues.append({"severity": "high", "code": "foreign-install-hooks", "detail": "foreign install/remove scripts are disabled in the Pisi output"})
    for elf in package.elf_files:
        for code, detail in elf_compatibility_issues(elf, target_arch):
            issues.append({"severity": "critical", "code": code,
                           "detail": f"{elf.get('path')}: {detail}"})
        for path in elf.get("rpath", []) + elf.get("runpath", []):
            if path and not path.startswith(("$ORIGIN", "/usr/", "/lib", "/opt/")):
                issues.append({"severity": "medium", "code": "nonstandard-runtime-path", "detail": f"{elf.get('path')}: {path}"})
        for library, version in elf.get("version_requirements", {}).items():
            issues.append({"severity": "medium", "code": "versioned-runtime-symbol",
                           "detail": f"{elf.get('path')}: {library} >= {version}"})
    if package.script_interpreters:
        issues.append({"severity": "medium", "code": "script-interpreter", "detail": ", ".join(package.script_interpreters)})
    if package.warnings:
        issues.append({"severity": "medium", "code": "parser-warning", "detail": package.warnings[0]})
    severities = {item["severity"] for item in issues}
    if "critical" in severities:
        level, recommendation = "critical", "rebuild"
    elif "high" in severities:
        level, recommendation = "high", "rebuild-or-review"
    elif "medium" in severities:
        level, recommendation = "review", "review-before-install"
    else:
        level, recommendation = "low", "binary-repackaging-possible"
    return {"level": level, "recommendation": recommendation, "issues": issues}
