from __future__ import annotations

import io
import hashlib
import base64
import gzip
import shutil
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from everypisi.analyzer import detect_format, parse_package
from everypisi.formats.deb import extract_tar, verify_md5sums
from everypisi.formats.rpm import (RpmHeader, _read_newc, _read_stripped,
                                    _verify_rpm_digests, _verify_rpm_file_digests,
                                    _verify_rpm_openpgp, _dependency_atoms,
                                    _unsupported_rpm_relation)
from everypisi.compression import decompress
from everypisi.errors import ResourceLimitError, UnsafeArchiveError, UnsupportedFormatError
from everypisi.formats.base import normalize_pisi_release, normalize_pisi_version
from everypisi.signatures import verify_debsig_signature, verify_detached_signature
from everypisi.util import safe_relative_path


def make_tar(entries: dict[str, bytes], mode: str = "w") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode=mode) as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name.endswith("/bin/demo") else 0o644
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def make_ar(members: list[tuple[str, bytes]]) -> bytes:
    output = bytearray(b"!<arch>\n")
    for name, data in members:
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{0:<8}{len(data):<10}`\n".encode()
        output.extend(header)
        output.extend(data)
        if len(data) % 2:
            output.extend(b"\n")
    return bytes(output)


class ParserTests(unittest.TestCase):
    def test_decompression_limit_rejects_expanded_payload(self):
        with self.assertRaises(ResourceLimitError):
            decompress(gzip.compress(b"x" * 4096), max_output=1024)

    def test_archive_path_limit_rejects_oversized_member_name(self):
        with self.assertRaises(ResourceLimitError):
            safe_relative_path("a" * 4097)

    def test_foreign_version_normalization_matches_pisi_grammar(self):
        self.assertEqual(normalize_pisi_version("2.12.2-2.fc43"), "2.12.2")
        self.assertEqual(normalize_pisi_version("1.2~rc1"), "1.2_rc1")
        self.assertEqual(normalize_pisi_release("2.fc43"), "2")

    def test_detached_openpgp_signature_with_supplied_keyring(self):
        if not shutil.which("gpg") or not shutil.which("gpgv"):
            self.skipTest("gpg and gpgv are not installed")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "gnupg"
            home.mkdir(mode=0o700)
            batch = root / "key.batch"
            batch.write_text(
                "Key-Type: RSA\nKey-Length: 2048\nName-Real: EveryPisi Detached\n"
                "Name-Email: everypisi-detached@localhost\nExpire-Date: 0\n"
                "%no-protection\n%commit\n",
                encoding="ascii",
            )
            subprocess.run(["gpg", "--batch", "--homedir", str(home), "--generate-key", str(batch)],
                           check=True, capture_output=True)
            package = root / "package.bin"
            package.write_bytes(b"detached package\n")
            signature = root / "package.bin.sig"
            subprocess.run(["gpg", "--batch", "--homedir", str(home), "--detach-sign",
                            "--output", str(signature), str(package)], check=True, capture_output=True)
            keyring = root / "trusted.gpg"
            exported = subprocess.run(["gpg", "--batch", "--homedir", str(home), "--export"],
                                      check=True, capture_output=True)
            keyring.write_bytes(exported.stdout)
            self.assertEqual(verify_detached_signature(package, signature, keyring), "verified")

    def test_rpm_openpgp_signature_with_supplied_keyring(self):
        if not shutil.which("gpg") or not shutil.which("gpgv"):
            self.skipTest("gpg and gpgv are not installed")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "gnupg"
            home.mkdir(mode=0o700)
            batch = root / "key.batch"
            batch.write_text(
                "Key-Type: RSA\nKey-Length: 2048\nName-Real: EveryPisi Test\n"
                "Name-Email: everypisi-test@localhost\nExpire-Date: 0\n"
                "%no-protection\n%commit\n",
                encoding="ascii",
            )
            subprocess.run(["gpg", "--batch", "--homedir", str(home), "--generate-key", str(batch)],
                           check=True, capture_output=True)
            data = b"immutable rpm header\n"
            data_path = root / "data"
            data_path.write_bytes(data)
            signature_path = root / "signature.pgp"
            subprocess.run(["gpg", "--batch", "--homedir", str(home), "--detach-sign",
                            "--output", str(signature_path), str(data_path)], check=True, capture_output=True)
            keyring = root / "trusted.gpg"
            with keyring.open("wb") as stream:
                exported = subprocess.run(["gpg", "--batch", "--homedir", str(home), "--export"],
                                          check=True, capture_output=True)
                stream.write(exported.stdout)
            signature = RpmHeader({268: signature_path.read_bytes()}, len(data), 0)
            header = RpmHeader({}, len(data), 0)
            self.assertEqual(_verify_rpm_openpgp(data, signature, header, keyring), "verified")

            legacy_payload_signature = RpmHeader({1002: signature_path.read_bytes()}, len(data), 0)
            self.assertEqual(_verify_rpm_openpgp(data, legacy_payload_signature, header, keyring), "verified")

            v6_signature = RpmHeader({278: [base64.b64encode(signature_path.read_bytes()).decode("ascii")]}, len(data), 0)
            self.assertEqual(_verify_rpm_openpgp(data, v6_signature, header, keyring), "verified")

    def test_rpm_legacy_header_payload_md5_digest(self):
        payload = b"signed header and payload\n"
        signature = RpmHeader({1004: hashlib.md5(payload).digest()}, len(payload), 0)
        header = RpmHeader({}, len(payload), 0)
        self.assertEqual(_verify_rpm_digests(payload, signature, header, b""),
                         {"header-payload-md5": "verified"})

    def test_archive_rejects_symlinked_parent_write(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            link = tarfile.TarInfo("usr/share/doc")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            archive.addfile(link)
            payload = b"must not be redirected\n"
            member = tarfile.TarInfo("usr/share/doc/owned")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "payload"
            destination.mkdir()
            with self.assertRaises(UnsafeArchiveError):
                extract_tar(output.getvalue(), destination, [])

    def test_debian_md5sums_manifest(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "usr/bin/demo"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"demo\n")
            digest = hashlib.md5(b"demo\n").hexdigest()
            self.assertEqual(verify_md5sums(f"{digest}  usr/bin/demo\n".encode(), root), "verified:1")

    def test_debian_embedded_signature_is_not_silently_ignored(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            control = make_tar({"control": b"Package: signed\nVersion: 1.0\nArchitecture: amd64\nDescription: Signed\n"})
            data = make_tar({"usr/bin/signed": b"signed\n"})
            package = root / "signed.deb"
            package.write_bytes(make_ar([
                ("debian-binary", b"2.0\n"), ("_gpgorigin", b"signature"),
                ("control.tar", control), ("data.tar", data),
            ]))
            parsed, work = parse_package(package, keep_workdir=True)
            try:
                self.assertEqual(parsed.source_integrity["debian-embedded-signature"], "present-unverified")
            finally:
                work.cleanup()

    def test_debsig_verifier_uses_explicit_policy_and_keyring_dirs(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "signed.deb"
            package.write_bytes(b"deb")
            policies = root / "policies"
            keyrings = root / "keyrings"
            policies.mkdir()
            keyrings.mkdir()
            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch("everypisi.signatures.shutil.which", return_value="/usr/bin/debsig-verify"), \
                    patch("everypisi.signatures.subprocess.run", return_value=completed) as run:
                self.assertEqual(verify_debsig_signature(package, policies, keyrings), "verified")
            command = run.call_args.args[0]
            self.assertEqual(command[:5], ["/usr/bin/debsig-verify", "--quiet", "--policies-dir", str(policies), "--keyrings-dir"])
            self.assertEqual(command[-1], str(package))

    def test_arch_mtree_must_cover_every_payload_path(self):
        from everypisi.formats.arch import verify_mtree
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "usr/bin/demo"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"demo\n")
            mtree = gzip.compress(b"./usr type=dir\n./usr/bin type=dir\n")
            with self.assertRaises(UnsupportedFormatError):
                verify_mtree(mtree, root, {
                    "usr": {"uid": 0, "gid": 0, "mode": 0o755},
                    "usr/bin": {"uid": 0, "gid": 0, "mode": 0o755},
                    "usr/bin/demo": {"uid": 0, "gid": 0, "mode": 0o644},
                })

    def test_deb_zstd_tar_members(self):
        if not shutil.which("zstd"):
            self.skipTest("zstd is not installed")
        with TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            control = make_tar({"control": b"Package: zstd-demo\nVersion: 1.0-1\nArchitecture: amd64\nDescription: Demo\n"})
            data = make_tar({"usr/bin/zstd-demo": b"demo\n"})
            control_zst = subprocess.run(["zstd", "-q", "-c"], input=control, capture_output=True, check=True).stdout
            data_zst = subprocess.run(["zstd", "-q", "-c"], input=data, capture_output=True, check=True).stdout
            deb = tmp_path / "zstd-demo.deb"
            deb.write_bytes(make_ar([("debian-binary", b"2.0\n"), ("control.tar.zst", control_zst), ("data.tar.zst", data_zst)]))
            parsed, work = parse_package(deb, keep_workdir=True)
            try:
                self.assertEqual(parsed.name, "zstd-demo")
                self.assertEqual(parsed.release, "1")
                self.assertEqual(parsed.files[0].path, "usr/bin/zstd-demo")
            finally:
                work.cleanup()

    def test_rpm_newc_payload_reader(self):
        def entry(name: str, mode: int, data: bytes, inode: int) -> bytes:
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0]
            header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
            result = header + name.encode() + b"\0"
            result += b"\0" * ((-len(result)) % 4)
            result += data
            result += b"\0" * ((-len(result)) % 4)
            return result

        payload = entry("usr", 0o040755, b"", 1)
        payload += entry("usr/bin", 0o040755, b"", 2)
        payload += entry("usr/bin/demo", 0o100755, b"demo\n", 3)
        payload += entry("TRAILER!!!", 0, b"", 0)
        with self.subTest(format="rpm-newc"):
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as directory:
                destination = Path(directory) / "payload"
                destination.mkdir()
                _read_newc(payload, destination, [])
                self.assertEqual((destination / "usr/bin/demo").read_text(), "demo\n")
                self.assertEqual((destination / "usr/bin/demo").stat().st_mode & 0o777, 0o755)

    def test_rpm_crc_newc_payload_reader(self):
        data = b"crc data\n"
        def entry(name: str, mode: int, content: bytes, check: int = 0) -> bytes:
            fields = [1, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(name) + 1, check]
            header = b"070702" + b"".join(f"{value:08x}".encode() for value in fields)
            result = header + name.encode() + b"\0"
            result += b"\0" * ((-len(result)) % 4) + content
            return result + b"\0" * ((-len(result)) % 4)
        payload = entry("usr", 0o040755, b"")
        payload += entry("usr/bin", 0o040755, b"")
        payload += entry("usr/bin/demo", 0o100755, data, sum(data))
        payload += entry("TRAILER!!!", 0, b"")
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "payload"
            destination.mkdir()
            _read_newc(payload, destination, [])
            self.assertEqual((destination / "usr/bin/demo").read_bytes(), data)

    def test_rpm_newc_hardlink_can_precede_content(self):
        def entry(name: str, content: bytes, inode: int) -> bytes:
            fields = [inode, 0o100644, 0, 0, 2, 0, len(content), 0, 0, 0, 0, len(name) + 1, 0]
            header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
            result = header + name.encode() + b"\0"
            result += b"\0" * ((-len(result)) % 4) + content
            return result + b"\0" * ((-len(result)) % 4)
        payload = entry("first", b"", 7) + entry("second", b"shared\n", 7)
        payload += entry("TRAILER!!!", b"", 0)
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "payload"
            destination.mkdir()
            _read_newc(payload, destination, [])
            self.assertEqual((destination / "first").read_bytes(), b"shared\n")
            self.assertEqual((destination / "first").stat().st_ino, (destination / "second").stat().st_ino)

    def test_rpm_stripped_payload_reader(self):
        def entry(index: int, data: bytes = b"") -> bytes:
            header = b"07070X" + f"{index & 0xffffffff:08x}".encode()
            result = header + b"\0" * ((-len(header)) % 4) + data
            return result + b"\0" * ((-len(result)) % 4)

        payload = entry(0, b"demo\n") + entry(0xffffffff)
        header = RpmHeader({
            1118: ["usr/bin/"],
            1117: ["demo"],
            1116: [0],
            1030: [0o100755],
            1028: [5],
            1031: [123],
            1032: [456],
            1096: [7],
        }, 0, 0)
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "payload"
            destination.mkdir()
            metadata = {}
            _read_stripped(payload, destination, [], metadata, header)
            self.assertEqual((destination / "usr/bin/demo").read_text(), "demo\n")
            self.assertEqual((destination / "usr/bin/demo").stat().st_mode & 0o777, 0o755)
            self.assertEqual(metadata["usr/bin/demo"]["uid"], 123)

    def test_rpm_per_file_digest_manifest(self):
        payload = b"demo\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "usr/bin/demo"
            target.parent.mkdir(parents=True)
            target.write_bytes(payload)
            header = RpmHeader({
                1035: [hashlib.sha256(payload).hexdigest()],
                5011: [8],
                1118: ["/usr/bin/"],
                1117: ["demo"],
                1116: [0],
            }, 0, 0)
            self.assertEqual(_verify_rpm_file_digests(header, root, {"usr/bin/demo": {}}), "verified:1")

    def test_rpm_script_dependency_is_not_runtime_dependency(self):
        groups = _dependency_atoms(["/bin/sh", "libc.so.6"],
                                   [1 << 9, 0], [None, None])
        self.assertEqual([group.scope for group in groups], ["script", "runtime"])

    def test_rpm_rich_and_capability_relations_are_not_misparsed(self):
        self.assertTrue(_unsupported_rpm_relation("(foo or bar)"))
        self.assertTrue(_unsupported_rpm_relation("libc.so.6(GLIBC_2.2.5)(64bit)"))
        self.assertFalse(_unsupported_rpm_relation("openssl"))
        self.assertEqual(_dependency_atoms(["(foo or bar)"], [0], [None]), [])

    def test_rpm_singleton_dependency_tags_remain_one_dependency(self):
        groups = _dependency_atoms("openssl", 0, None)
        self.assertEqual([group.alternatives[0].name for group in groups], ["openssl"])

    def test_deb_parser_and_format_detection(self):
        with self.subTest(format="deb"):
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as directory:
                tmp_path = Path(directory)
                control = make_tar({"control": b"Package: demo\nVersion: 1.2\nArchitecture: amd64\nDepends: libc6 (>= 2.35)\nDescription: Demo package\n"})
                data = make_tar({"usr/bin/demo": b"#!/bin/sh\nexit 0\n"})
                deb = tmp_path / "demo.deb"
                deb.write_bytes(make_ar([("debian-binary", b"2.0\n"), ("control.tar", control), ("data.tar", data)]))
                self.assertEqual(detect_format(deb), "deb")
                parsed, work = parse_package(deb, keep_workdir=True)
                try:
                    self.assertEqual(parsed.name, "demo")
                    self.assertEqual(parsed.architecture, "amd64")
                    self.assertEqual(parsed.dependencies[0].alternatives[0].name, "libc6")
                    self.assertEqual(parsed.files[0].path, "usr/bin/demo")
                    self.assertIn("/bin/sh", parsed.script_interpreters)
                finally:
                    work.cleanup()

    def test_deb_preserves_payload_metadata(self):
        with TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            control = make_tar({"control": b"Package: metadata-demo\nVersion: 1.0\nArchitecture: amd64\nDescription: Demo\n"})
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w") as archive:
                info = tarfile.TarInfo("usr/bin/metadata-demo")
                info.uid, info.gid, info.mode = 123, 456, 0o751
                data = b"demo\n"
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            deb = tmp_path / "metadata-demo.deb"
            deb.write_bytes(make_ar([("debian-binary", b"2.0\n"), ("control.tar", control), ("data.tar", output.getvalue())]))
            parsed, work = parse_package(deb, keep_workdir=True)
            try:
                entry = next(item for item in parsed.files if item.path == "usr/bin/metadata-demo")
                self.assertEqual((entry.uid, entry.gid, entry.mode), (123, 456, 0o751))
                self.assertEqual(parsed.payload_metadata["usr/bin/metadata-demo"]["uid"], 123)
            finally:
                work.cleanup()

    def test_unsupported_payload_metadata_is_reported(self):
        with TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            control = make_tar({"control": b"Package: xattr-demo\nVersion: 1.0\nArchitecture: amd64\nDescription: Demo\n"})
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
                info = tarfile.TarInfo("usr/bin/xattr-demo")
                info.pax_headers["SCHILY.xattr.security.capability"] = "cap_net_raw+ep"
                data = b"demo\n"
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            deb = tmp_path / "xattr-demo.deb"
            deb.write_bytes(make_ar([("debian-binary", b"2.0\n"), ("control.tar", control), ("data.tar", output.getvalue())]))
            parsed, work = parse_package(deb, keep_workdir=True)
            try:
                self.assertTrue(any("capability" in item.lower() for item in parsed.metadata_flags))
            finally:
                work.cleanup()


    def test_arch_parser(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            package = Path(directory) / "demo.pkg.tar"
            with tarfile.open(package, "w") as archive:
                pkginfo = b"pkgname = demo\npkgver = 1.0-1\narch = x86_64\npkgdesc = Demo\ndepend = libc\n"
                info = tarfile.TarInfo(".PKGINFO")
                info.size = len(pkginfo)
                archive.addfile(info, io.BytesIO(pkginfo))
                payload = b"#!/bin/sh\n"
                info = tarfile.TarInfo("usr/bin/demo")
                info.size = len(payload)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(payload))
            parsed, work = parse_package(package, keep_workdir=True)
            try:
                self.assertEqual(parsed.source_format, "arch")
                self.assertEqual(parsed.name, "demo")
                self.assertEqual(parsed.files[0].mode, 0o755)
            finally:
                work.cleanup()
