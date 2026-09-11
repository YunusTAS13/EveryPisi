from __future__ import annotations

import hashlib
import lzma
import io
import os
import re
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path

from .compression import decompress
from .formats.base import is_pisi_version
from .model import DependencyAtom, DependencyGroup
from .util import MAX_EXPANDED_BYTES


DEFAULT_PISI_INDEX = "https://stable2.pisilinux.org/pisi-index.xml.xz"
DEFAULT_ALIASES = {
    "libc6": "glibc",
    "libgcc-s1": "libgcc",
    "libstdc++6": "gcc",
    "zlib1g": "zlib",
    "libssl3": "openssl",
    "libssl1.1": "openssl",
    "libx11-6": "libX11",
    "libxext6": "libXext",
    "libxrender1": "libXrender",
    "libxrandr2": "libXrandr",
    "libfreetype6": "freetype",
    "libfontconfig1": "fontconfig",
    "libglib2.0-0": "glib2",
    "libgtk-3-0": "gtk3",
    "libgtk-4-1": "gtk4",
    "libpango-1.0-0": "pango",
    "libcairo2": "cairo",
    "libdbus-1-3": "dbus",
    "libexpat1": "expat",
    "libzstd1": "zstd",
    "libc.so.6": "glibc",
    "libm.so.6": "glibc",
    "libpthread.so.0": "glibc",
    "libdl.so.2": "glibc",
    "librt.so.1": "glibc",
    "libstdc++.so.6": "gcc",
    "libgcc_s.so.1": "libgcc",
    "libz.so.1": "zlib",
    "libzstd.so.1": "zstd",
    "libssl.so.3": "openssl",
    "libcrypto.so.3": "openssl",
    "libacl.so.1": "acl",
}


class PisiRepository:
    """Small streaming view of a Pisi pisi-index.xml file."""

    def __init__(self, packages: set[str] | None = None, aliases: dict[str, str] | None = None,
                 versions: dict[str, str] | None = None,
                 dependencies: dict[str, list[DependencyGroup]] | None = None,
                 distribution: str | None = None, distribution_release: str | None = None,
                 architectures: set[str] | None = None, integrity: str = "unverified",
                 releases: dict[str, str] | None = None):
        self.packages = packages or set()
        self.aliases = {**DEFAULT_ALIASES, **(aliases or {})}
        self.versions = versions or {}
        self.dependencies = dependencies or {}
        self.releases = releases or {}
        self.distribution = distribution or ""
        self.distribution_release = distribution_release or ""
        self.architectures = architectures or set()
        self.integrity = integrity

    @classmethod
    def load(cls, source: str | Path, *, expected_sha1: str | None = None) -> "PisiRepository":
        if str(source).lower().startswith("http://"):
            raise ValueError("repository index must be fetched over HTTPS")
        if expected_sha1 is not None:
            expected_sha1 = expected_sha1.strip().lower()
            if not re.fullmatch(r"[0-9a-f]{40}", expected_sha1):
                raise ValueError("repository SHA-1 must be exactly 40 hexadecimal characters")
        if str(source).startswith(("http://", "https://")):
            with urllib.request.urlopen(str(source), timeout=60) as response:
                data = response.read()
            compressed = data
            source_name = str(source).split("?", 1)[0]
        else:
            source_path = Path(source)
            compressed = source_path.read_bytes()
            source_name = str(source_path)
        if expected_sha1 and hashlib.sha1(compressed).hexdigest() != expected_sha1:
            raise ValueError("Pisi repository index SHA-1 verification failed")
        if len(compressed) > MAX_EXPANDED_BYTES:
            raise ValueError("repository index exceeds the safety limit")
        data = (decompress(compressed, hint=source_name, max_output=MAX_EXPANDED_BYTES)
                if source_name.endswith(".xz") else compressed)
        if len(data) > MAX_EXPANDED_BYTES:
            raise ValueError("expanded repository index exceeds the safety limit")
        return cls._from_stream(data, integrity="sha1-verified" if expected_sha1 else "unverified")

    @classmethod
    def load_cached(cls, source: str = DEFAULT_PISI_INDEX, max_age_seconds: int = 86400) -> "PisiRepository":
        """Load a repository index, caching the compressed official index locally."""
        if source.lower().startswith("http://"):
            raise ValueError("repository index must be fetched over HTTPS")
        cache_dir = Path.home() / ".cache" / "everypisi"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "pisi-index.xml.xz"
        cache_checksum = cache_dir / "pisi-index.xml.xz.sha1"
        if (cache_file.is_file() and cache_checksum.is_file()
                and time.time() - cache_file.stat().st_mtime < max_age_seconds):
            try:
                expected = cache_checksum.read_text(encoding="ascii").strip().split()[0]
                return cls.load(cache_file, expected_sha1=expected)
            except (OSError, IndexError, ValueError, lzma.LZMAError):
                # A tampered, truncated, or incomplete cache must never be
                # used for dependency resolution; fetch and verify afresh.
                pass
        with urllib.request.urlopen(source, timeout=90) as response:
            data = response.read()
        checksum_source = source.split("?", 1)[0] + ".sha1sum"
        with urllib.request.urlopen(checksum_source, timeout=30) as response:
            checksum_text = response.read().decode("ascii", "replace").strip()
        expected = checksum_text.split()[0] if checksum_text else ""
        if not expected or hashlib.sha1(data).hexdigest() != expected:
            raise ValueError("Pisi repository index SHA-1 verification failed")
        if source.split("?", 1)[0].endswith(".xz"):
            decompress(data, hint=source, max_output=MAX_EXPANDED_BYTES)  # validate before replacing cache
        fd, temporary_name = tempfile.mkstemp(prefix="pisi-index-", dir=cache_dir)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, cache_file)
        finally:
            Path(temporary_name).unlink(missing_ok=True)
        checksum_fd, checksum_temporary = tempfile.mkstemp(prefix="pisi-index-sha1-", dir=cache_dir,
                                                           text=True)
        try:
            with os.fdopen(checksum_fd, "w", encoding="ascii") as stream:
                stream.write(hashlib.sha1(data).hexdigest() + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(checksum_temporary, cache_checksum)
        finally:
            Path(checksum_temporary).unlink(missing_ok=True)
        return cls.load(cache_file, expected_sha1=hashlib.sha1(data).hexdigest())

    @classmethod
    def _from_stream(cls, stream, *, integrity: str = "unverified") -> "PisiRepository":
        packages: set[str] = set()
        versions: dict[str, str] = {}
        releases: dict[str, str] = {}
        dependencies: dict[str, list[DependencyGroup]] = {}
        distribution = ""
        distribution_release = ""
        architectures: set[str] = set()
        if isinstance(stream, (bytes, bytearray)):
            stream = io.BytesIO(stream)
        for _, element in ET.iterparse(stream, events=("end",)):
            if element.tag == "Distribution":
                declared_name = (element.findtext("BinaryName") or element.findtext("SourceName") or "").strip()
                declared_release = (element.findtext("Version") or "").strip()
                # Package metadata also contains a leaf named Distribution;
                # only the top-level element has BinaryName/SourceName.
                if declared_name:
                    distribution = declared_name
                    distribution_release = declared_release
            elif element.tag == "Package":
                name = element.findtext("Name")
                if name:
                    name = name.strip()
                    packages.add(name)
                    architecture = (element.findtext("Architecture") or "").strip()
                    if architecture:
                        architectures.add(architecture)
                    updates = element.findall("./History/Update")
                    if updates:
                        def release_number(update):
                            try:
                                return int(update.attrib.get("release", "0"))
                            except ValueError:
                                return -1
                        latest = max(updates, key=release_number)
                        version = latest.findtext("Version")
                        if version:
                            versions[name] = version.strip()
                        release = latest.attrib.get("release")
                        if release and release.isdigit():
                            releases[name] = release
                    package_dependencies = _parse_pisi_dependencies(element)
                    if package_dependencies:
                        dependencies[name] = package_dependencies
                element.clear()
        return cls(packages, versions=versions, dependencies=dependencies, releases=releases,
                   distribution=distribution, distribution_release=distribution_release,
                   architectures=architectures, integrity=integrity)

    def resolve_atom(self, group: DependencyGroup):
        for atom in group.alternatives:
            candidates = [self.aliases.get(atom.name, atom.name)]
            candidates.extend(_safe_aliases(atom.name))
            matches = {
                candidate for candidate in candidates
                if candidate in self.packages and self._satisfies(candidate, atom)
            }
            if len(matches) == 1:
                return replace(atom, name=next(iter(matches)))
        return None

    def _satisfies(self, name: str, atom) -> bool:
        """Apply a constraint when the index provides a Pisi version.

        If a caller constructed a name-only repository (as in an offline
        dependency map), there is no version evidence and resolution remains
        name-based rather than inventing compatibility information.
        """
        available = self.versions.get(name)
        if available:
            if atom.operator and atom.version:
                relation = _version_compare(available, atom.version)
                if not {"<": relation < 0, "<=": relation <= 0, "=": relation == 0,
                        ">=": relation >= 0, ">": relation > 0}.get(atom.operator, False):
                    return False
            if atom.version_to and _version_compare(available, atom.version_to) > 0:
                return False
        available_release = self.releases.get(name)
        for release_bound in (atom.release, atom.release_from, atom.release_to):
            if release_bound is not None and not str(release_bound).isdigit():
                return False
        if available_release and atom.release:
            if available_release != atom.release:
                return False
        if available_release and atom.release_from:
            if not str(available_release).isdigit() or int(available_release) < int(atom.release_from):
                return False
        if available_release and atom.release_to:
            if not str(available_release).isdigit() or int(available_release) > int(atom.release_to):
                return False
        return True

    def resolve(self, group: DependencyGroup) -> str | None:
        atom = self.resolve_atom(group)
        return atom.name if atom else None

    def dependency_closure(self, roots: list[str] | set[str]) -> tuple[list[str], list[str]]:
        """Resolve the indexed transitive runtime dependency graph."""
        visited: set[str] = set()
        unresolved: set[str] = set()
        queue = list(dict.fromkeys(roots))
        while queue:
            name = queue.pop(0)
            if name in visited:
                continue
            if name not in self.packages:
                unresolved.add(name)
                continue
            visited.add(name)
            for group in self.dependencies.get(name, []):
                chosen = self.resolve_atom(group)
                if not chosen:
                    raw = " | ".join(atom.raw or atom.name for atom in group.alternatives)
                    unresolved.add(f"{name}: {raw}")
                elif chosen.name not in visited:
                    queue.append(chosen.name)
        return sorted(visited), sorted(unresolved)

    def target_errors(self, distribution: str, distribution_release: str, architecture: str) -> list[str]:
        """Return mismatches between a declared index identity and the target.

        Hand-written or legacy indexes may omit identity fields; those remain
        usable for explicit workflows.  A declared mismatch is rejected so a
        package is not resolved against a different ABI or distribution.
        """
        errors: list[str] = []
        if self.distribution and self.distribution != distribution:
            errors.append(f"repository distribution={self.distribution!r}, target={distribution!r}")
        if self.distribution_release and self.distribution_release != distribution_release:
            errors.append(
                f"repository release={self.distribution_release!r}, target={distribution_release!r}"
            )
        if self.architectures and architecture not in self.architectures and "any" not in self.architectures:
            errors.append(
                f"repository architectures={','.join(sorted(self.architectures))}, target={architecture!r}"
            )
        return errors


def _safe_aliases(name: str) -> list[str]:
    """Generate only conservative aliases; ambiguous aliases are rejected."""
    aliases: list[str] = []
    if name.endswith("-dev"):
        aliases.append(name[:-4] + "-devel")
    if name.endswith("-devel"):
        aliases.append(name[:-6] + "-dev")
    if name.endswith("-libs"):
        aliases.append(name[:-5])
    else:
        aliases.append(name + "-libs")
    soname = re.match(r"^(lib[^.]+)\.so(?:\..*)?$", name)
    if soname:
        aliases.append(soname.group(1))
    return aliases


def _parse_pisi_dependencies(package: ET.Element) -> list[DependencyGroup]:
    result: list[DependencyGroup] = []
    runtime = package.find("RuntimeDependencies")
    if runtime is None:
        return result
    for node in runtime:
        if node.tag == "Dependency":
            group = _parse_pisi_dependency(node, "runtime")
            if group:
                result.append(group)
        elif node.tag == "AnyDependency":
            alternatives = []
            for dependency in node.findall("Dependency"):
                group = _parse_pisi_dependency(dependency, "runtime")
                if group:
                    alternatives.extend(group.alternatives)
            if alternatives:
                result.append(DependencyGroup(tuple(alternatives), "runtime"))
    return result


def _parse_pisi_dependency(node: ET.Element, scope: str) -> DependencyGroup | None:
    name = (node.text or "").strip()
    if not name:
        return None
    common = {
        "raw": name,
        "release": node.get("release"),
        "release_from": node.get("releaseFrom"),
        "release_to": node.get("releaseTo"),
    }
    if node.get("version"):
        atom = DependencyAtom(name, "=", node.get("version"), **common)
    elif node.get("versionFrom"):
        atom = DependencyAtom(name, ">=", node.get("versionFrom"),
                              version_to=node.get("versionTo"), **common)
    elif node.get("versionTo"):
        atom = DependencyAtom(name, version_to=node.get("versionTo"), **common)
    else:
        atom = DependencyAtom(name, **common)
    return DependencyGroup((atom,), scope)


def _version_compare(left: str, right: str) -> int:
    """Conservative Pisi/RPM-like comparison for common package versions."""
    if is_pisi_version(left) and is_pisi_version(right):
        return _pisi_version_compare(left, right)
    def tokens(value: str):
        return [int(part) if part.isdigit() else part.lower()
                for part in re.findall(r"[0-9]+|[A-Za-z]+", value)]

    a, b = tokens(left), tokens(right)
    for left_token, right_token in zip(a, b):
        if left_token == right_token:
            continue
        if isinstance(left_token, int) and isinstance(right_token, int):
            return -1 if left_token < right_token else 1
        if isinstance(left_token, int) != isinstance(right_token, int):
            return 1 if isinstance(left_token, int) else -1
        return -1 if left_token < right_token else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def _pisi_version_compare(left: str, right: str) -> int:
    """Compare versions using Pisi's numeric base/suffix ordering."""
    ranks = {"alpha": -5, "beta": -4, "pre": -3, "rc": -2, "m": -1, "p": 1}

    def parse(value: str):
        base, _, suffix = value.partition("_")
        base_items = []
        for item in base.split("."):
            match = re.fullmatch(r"(\d+)([A-Za-z]?)", item)
            if not match:
                return None
            base_items.append((int(match.group(1)), match.group(2)))
        if not suffix:
            return base_items, 0, []
        keyword = next((name for name in sorted(ranks, key=len, reverse=True) if suffix.startswith(name)), None)
        if keyword is None:
            return None
        tail = suffix[len(keyword):]
        suffix_items = []
        for item in tail.split("."):
            if not item.isdigit():
                return None
            suffix_items.append((int(item), ""))
        return base_items, ranks[keyword], suffix_items

    def compare_items(a, b):
        for left_item, right_item in zip(a, b):
            if left_item[0] != right_item[0]:
                return -1 if left_item[0] < right_item[0] else 1
            if left_item[1] != right_item[1]:
                if not left_item[1]:
                    return 1
                if not right_item[1]:
                    return -1
                return -1 if left_item[1] < right_item[1] else 1
        return (len(a) > len(b)) - (len(a) < len(b))

    parsed_left, parsed_right = parse(left), parse(right)
    if parsed_left is None or parsed_right is None:
        return 0
    result = compare_items(parsed_left[0], parsed_right[0])
    if result:
        return result
    if parsed_left[1] != parsed_right[1]:
        return -1 if parsed_left[1] < parsed_right[1] else 1
    return compare_items(parsed_left[2], parsed_right[2])
