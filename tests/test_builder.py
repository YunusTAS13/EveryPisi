from __future__ import annotations

import io
import tarfile
import unittest
import zipfile
from xml.etree import ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory

from everypisi.analyzer import parse_package
from everypisi.pisi_builder import _deduplicate_dependencies, convert_to_pisi
from everypisi.repository import PisiRepository
from everypisi.model import FileEntry, Script
from everypisi.errors import ConversionRefused


class BuilderTests(unittest.TestCase):
    def test_pisi_archive_layout(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            (payload / "usr/bin").mkdir(parents=True)
            executable = payload / "usr/bin/demo"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            from everypisi.model import ParsedPackage
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64",
                                    "Demo", "Demo", payload_root=payload)
            from everypisi.util import scan_payload
            package.files = scan_payload(payload)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {"metadata.xml", "files.xml", "install.tar.xz"})
                metadata = archive.read("metadata.xml")
                self.assertIn(b"<PackageFormat>1.2</PackageFormat>", metadata)
                self.assertIn(b"<DistributionRelease>2.0</DistributionRelease>", metadata)
                self.assertIn(b"<Hash>", archive.read("files.xml"))
                self.assertIn(b"<InstallTarHash>", metadata)
                with archive.open("install.tar.xz") as stream:
                    with tarfile.open(fileobj=stream, mode="r:xz") as install:
                        self.assertIn("usr/bin/demo", install.getnames())

    def test_install_archive_preserves_file_metadata(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            (payload / "usr/bin").mkdir(parents=True)
            executable = payload / "usr/bin/demo"
            executable.write_text("demo\n", encoding="utf-8")
            executable.chmod(0o751)
            from everypisi.model import ParsedPackage
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64", "Demo", "Demo", payload_root=payload)
            package.files = [FileEntry("usr/bin/demo", "file", 5, 0o751, 123, 456)]
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            with zipfile.ZipFile(output) as archive:
                with archive.open("install.tar.xz") as stream:
                    with tarfile.open(fileobj=stream, mode="r:xz") as install:
                        info = install.getmember("usr/bin/demo")
                        self.assertEqual((info.uid, info.gid, info.mode), (123, 456, 0o751))

    def test_install_archive_preserves_links(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            target = payload / "a"
            target.write_bytes(b"same inode\n")
            hardlink = payload / "b"
            hardlink.hardlink_to(target)
            symlink = payload / "c"
            symlink.symlink_to("a")
            from everypisi.model import ParsedPackage
            from everypisi.util import scan_payload
            package = ParsedPackage("arch", root / "links.pkg.tar", "links", "1.0", "x86_64",
                                    "Links", "Links", payload_root=payload)
            package.files = scan_payload(payload)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            with zipfile.ZipFile(output) as archive:
                with archive.open("install.tar.xz") as stream:
                    with tarfile.open(fileobj=stream, mode="r:xz") as install:
                        self.assertTrue(install.getmember("b").islnk())
                        self.assertEqual(install.getmember("b").linkname, "a")
                        self.assertTrue(install.getmember("c").issym())
                        self.assertEqual(install.getmember("c").linkname, "a")

    def test_foreign_hooks_require_explicit_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.scripts = [Script("postinst", b"#!/bin/sh\n")]
            from everypisi.errors import ConversionRefused
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)

    def test_output_name_cannot_escape_destination(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "../escape", "1.0", "x86_64", payload_root=payload)
            from everypisi.errors import ConversionRefused
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)

    def test_existing_output_symlink_is_replaced_without_following_it(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            output_dir = root / "out"
            output_dir.mkdir()
            outside = root / "outside"
            outside.write_bytes(b"sentinel")
            destination = output_dir / "demo-1.0-1-p2-x86_64.pisi"
            destination.symlink_to(outside)
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            output = convert_to_pisi(package, output_dir, allow_unresolved=True)
            self.assertTrue(output.is_file())
            self.assertFalse(output.is_symlink())
            self.assertEqual(outside.read_bytes(), b"sentinel")

    def test_invalid_pisi_version_is_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("rpm", root / "demo.rpm", "demo", "1.0-raw", "x86_64",
                                    payload_root=payload)
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)

    def test_conflicts_are_emitted_as_pisi_relations(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.conflicts = ["old-demo (>= 2.0)"]
            output = convert_to_pisi(package, root / "out", repository=PisiRepository({"old-demo"}))
            with zipfile.ZipFile(output) as archive:
                metadata = ET.fromstring(archive.read("metadata.xml"))
                conflict = metadata.find("./Package/Conflicts/Package")
                self.assertIsNotNone(conflict)
                self.assertEqual(conflict.text, "old-demo")
                self.assertEqual(conflict.attrib["versionFrom"], "2.0")

    def test_replaces_are_emitted_as_pisi_relations(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.replaces = ["old-demo (>= 2.0)"]
            output = convert_to_pisi(package, root / "out", repository=PisiRepository({"old-demo"}))
            with zipfile.ZipFile(output) as archive:
                metadata = ET.fromstring(archive.read("metadata.xml"))
                replacement = metadata.find("./Package/Replaces/Package")
                self.assertIsNotNone(replacement)
                self.assertEqual(replacement.text, "old-demo")
                self.assertEqual(replacement.attrib["versionFrom"], "2.0")

    def test_alternative_dependency_versions_are_preserved(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import DependencyAtom, DependencyGroup, ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.dependencies = [DependencyGroup((
                DependencyAtom("one", ">=", "1.0"),
                DependencyAtom("two", "=", "2.0"),
            ), "runtime")]
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            with zipfile.ZipFile(output) as archive:
                metadata = ET.fromstring(archive.read("metadata.xml"))
                dependencies = metadata.findall("./Package/RuntimeDependencies/AnyDependency/Dependency")
                self.assertEqual([(node.text, node.attrib) for node in dependencies], [
                    ("one", {"versionFrom": "1.0"}),
                    ("two", {"version": "2.0"}),
                ])

    def test_dependency_version_range_is_preserved(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import DependencyAtom, DependencyGroup, ParsedPackage
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64", payload_root=payload)
            package.dependencies = [DependencyGroup((DependencyAtom("lib", ">=", "1.0", raw="lib",
                                                                       version_to="2.0"),), "runtime")]
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            with zipfile.ZipFile(output) as archive:
                metadata = ET.fromstring(archive.read("metadata.xml"))
                node = metadata.find("./Package/RuntimeDependencies/Dependency")
                self.assertEqual(node.text, "lib")
                self.assertEqual(node.attrib, {"versionFrom": "1.0", "versionTo": "2.0"})

    def test_dependency_release_range_is_preserved(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import DependencyAtom, DependencyGroup, ParsedPackage
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64", payload_root=payload)
            package.dependencies = [DependencyGroup((DependencyAtom("lib", ">=", "1.0",
                                                                       raw="lib", version_to="2.0",
                                                                       release_from="2", release_to="3"),), "runtime")]
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            with zipfile.ZipFile(output) as archive:
                metadata = ET.fromstring(archive.read("metadata.xml"))
                node = metadata.find("./Package/RuntimeDependencies/Dependency")
                self.assertEqual(node.attrib, {"versionFrom": "1.0", "versionTo": "2.0",
                                               "releaseFrom": "2", "releaseTo": "3"})

    def test_strict_relation_requires_explicit_lossy_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.replaces = ["old-demo (< 2.0)"]
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True, allow_lossy_relations=True)
            self.assertTrue(output.is_file())

    def test_invalid_release_is_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.release = "not-a-number"
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)

    def test_incompatible_elf_abi_is_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64", payload_root=payload)
            package.elf_files = [{"path": "usr/bin/demo", "machine": "x86-64", "bits": 32,
                                  "interpreter": "/lib/ld-linux.so.2"}]
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)

    def test_dependency_dedup_keeps_strongest_bound(self):
        from everypisi.model import DependencyAtom, DependencyGroup
        groups = _deduplicate_dependencies([
            DependencyGroup((DependencyAtom("glibc", ">=", "2.38"),)),
            DependencyGroup((DependencyAtom("glibc", ">=", "2.43"),)),
        ])
        self.assertEqual(groups[0].alternatives[0].version, "2.43")

    def test_privileged_files_require_explicit_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            (payload / "usr/bin").mkdir(parents=True)
            executable = payload / "usr/bin/demo"
            executable.write_text("demo\n", encoding="utf-8")
            executable.chmod(0o4755)
            from everypisi.model import ParsedPackage
            from everypisi.util import scan_payload
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64", payload_root=payload)
            package.files = scan_payload(payload)
            package.file_flags = ["setuid:usr/bin/demo"]
            from everypisi.errors import ConversionRefused
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)

    def test_unsupported_metadata_requires_explicit_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.metadata_flags = ["security.capability:usr/bin/demo"]
            from everypisi.errors import ConversionRefused
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)

    def test_unverified_signature_requires_explicit_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("rpm", root / "demo.rpm", "demo", "1.0", "x86_64", payload_root=payload)
            package.source_integrity = {"openpgp-signature": "present-unverified"}
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True,
                                     allow_unverified_signatures=True)
            self.assertTrue(output.is_file())

    def test_foreign_architecture_dependency_requires_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import DependencyAtom, DependencyGroup, ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.dependencies = [DependencyGroup((DependencyAtom("legacy", None, None, "i386", "legacy:i386"),), "runtime")]
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unresolved=True)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True,
                                     allow_unsupported_metadata=True)
            self.assertTrue(output.is_file())

    def test_omitted_rpm_runtime_relation_requires_unresolved_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import ParsedPackage
            package = ParsedPackage("rpm", root / "demo.rpm", "demo", "1.0", "x86_64", payload_root=payload)
            package.metadata_flags = ["rpm-requires-not-supported:(foo or bar)"]
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", allow_unsupported_metadata=True)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True,
                                     allow_unsupported_metadata=True)
            self.assertTrue(output.is_file())

    def test_offline_conversion_requires_unresolved_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import DependencyAtom, DependencyGroup, ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.dependencies = [DependencyGroup((DependencyAtom("missing-lib"),), "runtime")]
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out")

    def test_transitive_repository_dependency_requires_acknowledgement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            from everypisi.model import DependencyAtom, DependencyGroup, ParsedPackage
            package = ParsedPackage("deb", root / "demo.deb", "demo", "1.0", "x86_64", payload_root=payload)
            package.dependencies = [DependencyGroup((DependencyAtom("provider"),), "runtime")]
            repository = PisiRepository(
                {"provider"},
                dependencies={
                    "provider": [DependencyGroup((DependencyAtom("missing-transitive"),), "runtime")]
                },
            )
            with self.assertRaises(ConversionRefused):
                convert_to_pisi(package, root / "out", repository=repository)
            output = convert_to_pisi(package, root / "out", repository=repository,
                                     allow_unresolved=True)
            self.assertTrue(output.is_file())
