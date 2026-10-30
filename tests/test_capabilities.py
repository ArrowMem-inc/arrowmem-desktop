import json, os, unittest

D = os.path.join(os.path.dirname(__file__), "..", "src-tauri", "capabilities")
ALL = {
    "pair_view", "status_view", "retry_firewall", "pair_state", "pair_confirm", "pair_cancel", "open_pairing",
    "uninstall_texts", "uninstall", "status_texts",
}


def load(n):
    return json.load(open(os.path.join(D, n)))


def cmds(cap):
    return {p[len("allow-"):].replace("-", "_") for p in cap["permissions"] if isinstance(p, str) and p.startswith("allow-")}


class Caps(unittest.TestCase):
    def test_each_window_has_core_only_and_its_own_capability(self):
        for w in ("pair", "status", "uninstall"):
            c = load(w + ".json")
            self.assertEqual(c["windows"], [w])
            self.assertIn("core:default", c["permissions"])
            self.assertFalse(any("shell" in str(p) for p in c["permissions"]))

    def test_pair_commands_are_granted_to_the_pair_window_only(self):
        pair_only = {"pair_confirm", "pair_cancel", "pair_state", "pair_view", "open_pairing"}
        self.assertTrue(pair_only <= cmds(load("pair.json")))
        for w in ("status.json", "uninstall.json", "default.json"):
            self.assertFalse(pair_only & cmds(load(w)), w)

    def test_every_app_command_is_granted_to_some_window_and_listed_in_build_rs(self):
        self.assertEqual(set().union(*(cmds(load(w)) for w in ("pair.json", "status.json", "uninstall.json"))), ALL)
        b = open(os.path.join(D, "..", "build.rs")).read()
        for c in ALL:
            self.assertIn('"%s"' % c, b)

    def test_main_keeps_default_and_no_window_is_in_two_capabilities(self):
        d = load("default.json")
        self.assertEqual(d["windows"], ["main"])
        self.assertEqual(d["permissions"], [])  # no shell plugin: every child is spawned by path from supervisor.rs
        seen = [load(w)["windows"][0] for w in ("pair.json", "status.json", "uninstall.json")] + d["windows"]
        self.assertEqual(len(seen), len(set(seen)))



class CommandLists(unittest.TestCase):
    def test_build_rs_commands_equal_the_invoke_handler(self):
        import re as _re
        b = open(os.path.join(os.path.dirname(__file__), "..", "src-tauri", "build.rs")).read()
        listed = _re.findall(r'"(\w+)"', b[b.index("COMMANDS"):b.index("];")])
        lib = open(os.path.join(os.path.dirname(__file__), "..", "src-tauri", "src", "lib.rs")).read()
        handler = _re.search(r"generate_handler!\[([^\]]*)\]", lib).group(1)
        self.assertEqual(sorted(listed), sorted(x.strip() for x in handler.split(",") if x.strip()))

    def test_no_shell_plugin_and_no_shell_permission(self):
        self.assertNotIn("tauri-plugin-shell", open(os.path.join(os.path.dirname(__file__), "..", "src-tauri", "Cargo.toml")).read())
        self.assertNotIn("tauri_plugin_shell", open(os.path.join(os.path.dirname(__file__), "..", "src-tauri", "src", "lib.rs")).read())
        for f in os.listdir(os.path.join(os.path.dirname(__file__), "..", "src-tauri", "capabilities")):
            self.assertNotIn("shell:", open(os.path.join(os.path.dirname(__file__), "..", "src-tauri", "capabilities", f)).read(), f)

if __name__ == "__main__":
    unittest.main()
