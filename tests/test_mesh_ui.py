import glob, json, os, re, unittest
R = os.path.join(os.path.dirname(__file__), "..")
UI = sorted(glob.glob(os.path.join(R, "ui", "mesh*")))

def rd(p):
    return open(p, encoding="utf-8").read()

class MeshUi(unittest.TestCase):
    def test_four_pages_and_shared_files_exist(self):
        names = {os.path.basename(p) for p in UI}
        self.assertEqual(names, {"mesh-chat.html", "mesh-vault.html", "mesh-peers.html", "mesh-status.html", "mesh.css", "mesh.js", "mesh-theme.js"})

    def test_no_storage_no_direct_network_no_inline_script_no_external_url(self):
        for p in UI:
            t = rd(p)
            for bad in ("localStorage", "sessionStorage", "indexedDB", "document.cookie", "fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon"):
                self.assertNotIn(bad, t, os.path.basename(p) + " " + bad)
            if p.endswith(".html"):
                self.assertNotRegex(t, r"<script(?![^>]*\bsrc=)[^>]*>", os.path.basename(p))
                self.assertNotRegex(t, r"(?:href|src)=\"https?:", os.path.basename(p))
                self.assertIn("default-src 'self'", t, os.path.basename(p))

    def test_only_mesh_call_is_invoked_and_no_token_in_ui(self):
        js = rd(os.path.join(R, "ui", "mesh.js"))
        self.assertEqual(set(re.findall(r"invoke\('(\w+)'", js)), {"mesh_call", "mesh_export"})
        for p in UI:
            self.assertNotRegex(rd(p).lower(), r"bearer|api-token|authorization", os.path.basename(p))

    def test_no_drawn_title_bar_dots(self):
        for p in UI:
            self.assertNotIn("machine-window", rd(p), os.path.basename(p))

    def test_every_visible_word_is_a_ca_placeholder(self):
        for p in glob.glob(os.path.join(R, "ui", "mesh-*.html")):
            t = re.sub(r"<(script|style|svg)\b.*?</\1>", "", rd(p), flags=re.S)
            t = re.sub(r"<!--.*?-->", "", t, flags=re.S)
            for txt in re.findall(r">([^<>]+)<", t):
                s = txt.strip()
                if s and s != "-" and not s.isdigit():
                    self.assertTrue(s.startswith("[CA] "), os.path.basename(p) + " " + s[:40])

    def test_capability_grants_only_the_two_mesh_commands_to_the_mesh_window(self):
        c = json.loads(rd(os.path.join(R, "src-tauri", "capabilities", "mesh.json")))
        self.assertEqual(c["windows"], ["mesh"])
        self.assertEqual(c["permissions"], ["core:default", "allow-mesh-call", "allow-mesh-export"])
        self.assertIn('"mesh_call"', rd(os.path.join(R, "src-tauri", "build.rs")))
        for f in glob.glob(os.path.join(R, "src-tauri", "capabilities", "*.json")):
            if not f.endswith("mesh.json"):
                self.assertNotIn("mesh", rd(f), f)

    def test_export_ciphertext_never_reaches_the_window_and_no_dialog_grant(self):
        js = rd(os.path.join(R, "ui", "mesh.js"))
        self.assertNotIn("/v1/vault/export", js)  # the window cannot name the route; Rust owns it
        self.assertNotIn("dialog", rd(os.path.join(R, "src-tauri", "capabilities", "mesh.json")))
        self.assertIn("tauri-plugin-dialog = { version = \"=", rd(os.path.join(R, "src-tauri", "Cargo.toml")))  # pinned exact

    def test_status_counters_read_v1_2_fields_and_say_unknown_when_absent(self):
        js = rd(os.path.join(R, "ui", "mesh.js"))
        self.assertIn("s.messages_received", js)
        self.assertIn("s.gate_verdicts", js)
        self.assertRegex(js, r"function count\([^)]*\)[^\n]*'\[CA\] unknown'")

if __name__ == "__main__":
    unittest.main()
