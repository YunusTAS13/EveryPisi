from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from everypisi.errors import ConversionRefused
from everypisi.rebuild import validate_recipe_directory


class RebuildTests(unittest.TestCase):
    def test_recipe_requires_pisi_files(self):
        with TemporaryDirectory() as directory:
            recipe = Path(directory)
            with self.assertRaises(ConversionRefused):
                validate_recipe_directory(recipe)
            (recipe / "pspec.xml").write_text("<PISI />", encoding="utf-8")
            with self.assertRaises(ConversionRefused):
                validate_recipe_directory(recipe)
            (recipe / "actions.py").write_text("def install(): pass", encoding="utf-8")
            validate_recipe_directory(recipe)

