from __future__ import annotations

import unittest
import hashlib
from tempfile import TemporaryDirectory
from pathlib import Path

from everypisi.model import DependencyAtom, DependencyGroup
from everypisi.repository import PisiRepository


class RepositoryTests(unittest.TestCase):
    def test_streaming_index_loader(self):
        from io import BytesIO
        index = b"<PISI><Distribution><BinaryName>PisiLinux</BinaryName><Version>2.0</Version></Distribution><SpecFile><Package><Name>openssl</Name><Architecture>x86_64</Architecture></Package><Package><Name>glibc</Name><Architecture>x86_64</Architecture><History><Update release=\"2\"><Version>2.42</Version></Update><Update release=\"1\"><Version>2.23</Version></Update></History></Package></SpecFile></PISI>"
        repository = PisiRepository._from_stream(BytesIO(index))
        self.assertEqual(repository.packages, {"openssl", "glibc"})
        self.assertEqual(repository.versions["glibc"], "2.42")
        self.assertEqual(repository.distribution, "PisiLinux")
        self.assertEqual(repository.distribution_release, "2.0")
        self.assertEqual(repository.architectures, {"x86_64"})

    def test_target_identity_rejects_wrong_repository(self):
        repo = PisiRepository({"pkg"}, distribution="PisiLinux", distribution_release="2.0",
                              architectures={"x86_64"})
        self.assertEqual(repo.target_errors("PisiLinux", "2.0", "x86_64"), [])
        self.assertEqual(len(repo.target_errors("PisiLinux", "1.0", "x86_64")), 1)
        self.assertEqual(len(repo.target_errors("PisiLinux", "2.0", "aarch64")), 1)

    def test_index_sha1_is_required_when_requested(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "pisi-index.xml"
            payload = b"<PISI><Distribution><BinaryName>PisiLinux</BinaryName><Version>2.0</Version></Distribution></PISI>"
            path.write_bytes(payload)
            digest = hashlib.sha1(payload).hexdigest()
            self.assertEqual(PisiRepository.load(path, expected_sha1=digest).integrity, "sha1-verified")
            with self.assertRaises(ValueError):
                PisiRepository.load(path, expected_sha1="0" * 40)

    def test_repository_http_is_rejected(self):
        with self.assertRaises(ValueError):
            PisiRepository.load("http://example.invalid/pisi-index.xml")

    def test_exact_and_conservative_alias_resolution(self):
        repo = PisiRepository({"openssl", "glibc", "foo-devel", "bar-libs"})
        exact = repo.resolve_atom(DependencyGroup((DependencyAtom("openssl"),)))
        self.assertEqual(exact.name, "openssl")
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("libc6"),))), "glibc")
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("foo-dev"),))), "foo-devel")
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("bar"),))), "bar-libs")

    def test_soname_alias_resolution(self):
        repo = PisiRepository({"libfoo", "libfoo-libs"})
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("libfoo.so.1"),))), "libfoo")
        repo = PisiRepository({"zlib", "gcc", "acl"})
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("libz.so.1"),))), "zlib")
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("libstdc++.so.6"),))), "gcc")
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("libacl.so.1"),))), "acl")

    def test_version_constraint_uses_index_version_when_available(self):
        repo = PisiRepository({"glibc"}, versions={"glibc": "2.39"})
        self.assertEqual(repo.resolve(DependencyGroup((DependencyAtom("libc6", ">=", "2.34"),))), "glibc")
        self.assertIsNone(repo.resolve(DependencyGroup((DependencyAtom("libc6", ">=", "2.40"),))))

    def test_pisi_prerelease_order_is_respected(self):
        prerelease = PisiRepository({"lib"}, versions={"lib": "1.0_rc1"})
        self.assertIsNone(prerelease.resolve(DependencyGroup((DependencyAtom("lib", ">=", "1.0"),))))
        final = PisiRepository({"lib"}, versions={"lib": "1.0"})
        self.assertIsNone(final.resolve(DependencyGroup((DependencyAtom("lib", "<=", "1.0_rc1"),))))

    def test_transitive_dependency_closure(self):
        index = b"""<PISI><Package><Name>app</Name><RuntimeDependencies><Dependency>lib</Dependency></RuntimeDependencies></Package><Package><Name>lib</Name><RuntimeDependencies><Dependency versionFrom=\"1.0\">base</Dependency></RuntimeDependencies></Package><Package><Name>base</Name><History><Update release=\"1\"><Version>2.0</Version></Update></History></Package></PISI>"""
        repo = PisiRepository._from_stream(index)
        self.assertEqual(repo.dependency_closure(["app"]), (["app", "base", "lib"], []))

    def test_pisi_dependency_range_is_preserved_and_checked(self):
        index = b"""<PISI><Package><Name>app</Name><RuntimeDependencies><Dependency versionFrom=\"1.0\" versionTo=\"2.0\" releaseFrom=\"2\" releaseTo=\"3\">lib</Dependency></RuntimeDependencies></Package><Package><Name>lib</Name><History><Update release=\"2\"><Version>1.5</Version></Update></History></Package></PISI>"""
        repo = PisiRepository._from_stream(index)
        atom = repo.dependencies["app"][0].alternatives[0]
        self.assertEqual((atom.operator, atom.version, atom.version_to), (">=", "1.0", "2.0"))
        self.assertEqual((atom.release_from, atom.release_to), ("2", "3"))
        self.assertEqual(repo.dependency_closure(["app"]), (["app", "lib"], []))
        repo.versions["lib"] = "2.1"
        self.assertEqual(repo.dependency_closure(["app"]), (["app"], ["app: lib"]))
        repo.versions["lib"] = "1.5"
        repo.releases["lib"] = "4"
        self.assertEqual(repo.dependency_closure(["app"]), (["app"], ["app: lib"]))

    def test_transitive_dependency_closure_reports_missing_package(self):
        index = b"<PISI><Package><Name>app</Name><RuntimeDependencies><Dependency>missing</Dependency></RuntimeDependencies></Package></PISI>"
        repo = PisiRepository._from_stream(index)
        self.assertEqual(repo.dependency_closure(["app"]), (["app"], ["app: missing"]))

    def test_invalid_release_constraint_is_not_satisfied(self):
        repo = PisiRepository({"lib"}, versions={"lib": "1.0"}, releases={"lib": "1"})
        self.assertIsNone(repo.resolve(DependencyGroup((DependencyAtom("lib", release_from="oops"),))))
