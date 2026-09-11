from __future__ import annotations

import unittest
from pathlib import Path

from everypisi.compatibility import assess
from everypisi.model import ParsedPackage


class CompatibilityTests(unittest.TestCase):
    def test_hooks_raise_rebuild_recommendation(self):
        package = ParsedPackage("deb", Path("demo.deb"), "demo", "1", "amd64")
        package.scripts = [object()]
        result = assess(package)
        self.assertEqual(result["level"], "high")
        self.assertEqual(result["recommendation"], "rebuild-or-review")

    def test_wrong_elf_machine_is_critical(self):
        package = ParsedPackage("arch", Path("demo.pkg.tar"), "demo", "1", "x86_64")
        package.elf_files = [{"path": "usr/bin/demo", "machine": "AArch64"}]
        result = assess(package, target_arch="x86_64")
        self.assertEqual(result["level"], "critical")

    def test_wrong_elf_bitness_and_interpreter_are_critical(self):
        package = ParsedPackage("arch", Path("demo.pkg.tar"), "demo", "1", "x86_64")
        package.elf_files = [{
            "path": "usr/bin/demo", "machine": "x86-64", "bits": 32,
            "interpreter": "/lib/ld-linux-aarch64.so.1",
        }]
        result = assess(package, target_arch="x86_64")
        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("elf-bitness", codes)
        self.assertIn("elf-interpreter", codes)
