import glob, json, os, unittest
ROOT = os.path.join(os.path.dirname(__file__), "..")
MARK = "UNCLEARED PLACEHOLDER"
# Empty since sec 331: every placeholder has its cleared line.
NO_LINE = set()

def shipped():
    pats = ["src-tauri/strings/*.json", "ui/*.html", "ui/*.js"]
    for p in pats:
        for f in sorted(glob.glob(os.path.join(ROOT, p))):
            yield os.path.relpath(f, ROOT).replace(os.sep, "/"), open(f, encoding="utf-8").read()

def strip_allowed(rel, text):
    for r, s in NO_LINE:
        if r == rel:
            text = text.replace(s, "")
    return text

def leftovers():
    return [rel for rel, text in shipped() if MARK in strip_allowed(rel, text)]

class T(unittest.TestCase):
    def test_no_shipped_string_or_ui_file_carries_a_placeholder(self):
        self.assertEqual(leftovers(), [])

    def test_rust_sources_carry_none_outside_tests(self):
        for f in glob.glob(os.path.join(ROOT, "src-tauri/src/*.rs")):
            body = open(f, encoding="utf-8").read().split("#[cfg(test)]")[0]
            self.assertNotIn(MARK, body, f)

    def test_the_allow_list_is_empty(self):
        self.assertEqual(NO_LINE, set())

if __name__ == "__main__":
    unittest.main()
