import glob, json, os, unittest
ROOT = os.path.join(os.path.dirname(__file__), "..")
MARK = "UNCLEARED PLACEHOLDER"
CA_MARK = "[CA]"  # the bracketed word of a render whose copy the copy reviewer has not cleared
MARKS = (MARK, CA_MARK)
# Empty since sec 331: every placeholder has its cleared line.
NO_LINE = set()
# The Arrowmesh pages still carry uncleared "[CA]" words. this release has no way to open them: the tray item is gone and
# open_window is never called with the mesh window (checked below). Remove this set when the copy is cleared.
NOT_RENDERED = {"ui/mesh-chat.html", "ui/mesh-peers.html", "ui/mesh-status.html", "ui/mesh-vault.html", "ui/mesh.js"}

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
    return [rel for rel, text in shipped() if rel not in NOT_RENDERED and any(m in strip_allowed(rel, text) for m in MARKS)]

class T(unittest.TestCase):
    def test_no_shipped_string_or_ui_file_carries_a_placeholder(self):
        self.assertEqual(leftovers(), [])

    def test_rust_sources_carry_none_outside_tests(self):
        for f in glob.glob(os.path.join(ROOT, "src-tauri/src/*.rs")):
            body = open(f, encoding="utf-8").read().split("#[cfg(test)]")[0]
            for m in MARKS:
                self.assertNotIn(m, body, f)

    def test_the_excluded_mesh_pages_exist_and_nothing_opens_the_mesh_window(self):
        for rel in NOT_RENDERED:
            self.assertTrue(os.path.exists(os.path.join(ROOT, rel)), rel)
        body = open(os.path.join(ROOT, "src-tauri/src/lib.rs"), encoding="utf-8").read().split("#[cfg(test)]")[0]
        self.assertNotIn('open_window(app, "mesh"', body)
        self.assertNotIn('open_window(app.handle(), "mesh"', body)
        self.assertNotIn("mesh-chat.html", body)
        self.assertNotIn('with_id("mesh"', body)

    def test_the_allow_list_is_empty(self):
        self.assertEqual(NO_LINE, set())

if __name__ == "__main__":
    unittest.main()
