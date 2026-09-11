from __future__ import annotations

import unittest
import zipfile
from xml.etree import ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory

from everypisi.model import ParsedPackage
from everypisi.pisi_builder import convert_to_pisi
from everypisi.util import scan_payload
from everypisi.validator import validate_pisi_package


class ValidatorTests(unittest.TestCase):
    def test_generated_package_is_self_consistent(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            (payload / "usr/bin").mkdir(parents=True)
            (payload / "usr/bin/demo").write_bytes(b"demo\n")
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64", "Demo", "Demo", payload_root=payload)
            package.files = scan_payload(payload)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            self.assertEqual(validate_pisi_package(output), [])
            self.assertEqual(validate_pisi_package(output, strict_install_tar_hash=True), [])

    def test_validator_detects_manifest_mode_mismatch(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            (payload / "usr/bin").mkdir(parents=True)
            binary = payload / "usr/bin/demo"
            binary.write_bytes(b"demo\n")
            binary.chmod(0o755)
            package = ParsedPackage("arch", root / "demo.pkg.tar", "demo", "1.0", "x86_64",
                                   "Demo", "Demo", payload_root=payload)
            package.files = scan_payload(payload)
            output = convert_to_pisi(package, root / "out", allow_unresolved=True)
            mutated = root / "mutated.pisi"
            with zipfile.ZipFile(output) as source, zipfile.ZipFile(mutated, "w") as target:
                for name in source.namelist():
                    data = source.read(name)
                    if name == "files.xml":
                        xml = ET.fromstring(data)
                        xml.find("File/Mode").text = "0644"
                        data = ET.tostring(xml)
                    target.writestr(name, data)
            self.assertTrue(any("mode mismatch" in error for error in validate_pisi_package(mutated)))
