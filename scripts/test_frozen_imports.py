"""Tests for frozen_imports.py: run with python3 -m unittest scripts/test_frozen_imports.py (or python3 scripts/test_frozen_imports.py)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import frozen_imports as fi


class Imports(unittest.TestCase):
    def test_a_lazy_import_inside_a_function_is_found(self):
        src = "def f():\n    from os.path import join\n    import json\n    from collections import abc\n"
        got = fi.imports_of(src)
        self.assertTrue({"os.path", "os.path.join", "json", "collections", "collections.abc"} <= got)

    def test_relative_imports_and_star_are_ignored(self):
        got = fi.imports_of("from . import x\nfrom .y import z\nfrom os import *\n")
        self.assertEqual(got, {"os"})

    def test_only_importable_names_survive_and_parents_come_along(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.py")
            open(p, "w").write("def f():\n    from os.path import join\n    import not_a_module_anywhere\n    from json import decoder\n")
            got = fi.of_files([p])
        self.assertIn("os", got)
        self.assertIn("os.path", got)
        self.assertIn("json.decoder", got)
        self.assertNotIn("not_a_module_anywhere", got)
        self.assertNotIn("os.path.join", got)  # a function, not a module

    def test_the_cryptography_pairing_primitives_of_the_companion_are_named(self):
        # the exact lines of companion_server.py's pair-start (the finding): the list must carry every one of them when cryptography is installed
        src = ("def f():\n    from cryptography.exceptions import InvalidKey\n    from cryptography.hazmat.primitives.asymmetric import x25519\n"
               "    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat\n    from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
        got = fi.imports_of(src)
        for n in ("cryptography.hazmat.primitives.asymmetric.x25519", "cryptography.hazmat.primitives.ciphers.aead.AESGCM", "cryptography.exceptions.InvalidKey"):
            self.assertIn(n, got)


if __name__ == "__main__":
    unittest.main()
