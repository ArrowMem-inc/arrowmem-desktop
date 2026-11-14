import os, re, unittest
R = os.path.join(os.path.dirname(__file__), "..")
SH = open(os.path.join(R, "scripts", "build-arrowmesh.sh"), encoding="utf-8").read()
SUP = open(os.path.join(R, "src-tauri", "src", "supervisor.rs"), encoding="utf-8").read()
FREEZE = open(os.path.join(R, "scripts", "arrowmesh-freeze.sha256"), encoding="utf-8").read()


class Static(unittest.TestCase):
    def test_script_pins_three_commits_and_trees_and_the_lock(self):
        for name in ("MESH", "CORE", "GATE"):
            self.assertRegex(SH, r'(?m)^%s_COMMIT="[0-9a-f]{40}"$' % name)
            self.assertRegex(SH, r'(?m)^%s_TREE="[0-9a-f]{40}"$' % name)
        self.assertRegex(SH, r'(?m)^LOCK_SHA="[0-9a-f]{64}"$')
        self.assertIn("cargo build --release --locked", SH)
        self.assertIn('git -C "$SRC/arrowmesh" archive "$MESH_COMMIT"', SH)
        self.assertIn('"$#" -eq 0', SH)
        self.assertNotRegex(SH, r"origin/|\bmaster\b|\bmain\b|HEAD|TMPDIR")

    def test_freeze_file_names_the_same_pins_and_a_hash_line(self):
        for name in ("MESH", "CORE", "GATE"):
            c = re.search(r'(?m)^%s_COMMIT="([0-9a-f]{40})"$' % name, SH).group(1)
            self.assertIn(c, FREEZE)
        self.assertRegex(FREEZE, r"(?m)^[0-9a-f]{64}  src-tauri/binaries/arrowmesh-[a-z0-9_-]+$")

    def test_the_app_never_runs_install_or_touches_the_user_unit_for_arrowmesh_r20(self):
        block = SUP.split("// ---- arrowmesh (the one-app daemon) ----")[1].split("/// Which llama-server build runs:")[0]
        self.assertNotIn('"install"', block)
        self.assertNotRegex(block, r"systemd|\.service|systemctl")
        self.assertIn('vec!["run".into(), "--config".into()', block)

    def test_no_secret_goes_in_argv_or_environment_of_the_daemon(self):
        block = SUP.split("impl Launcher for ArrowmeshLauncher")[1].split("\n}\n")[0]
        self.assertNotIn(".env(", block.replace(".env_remove(", ""))
        self.assertIn('env_remove("ARROWMESH_PASSPHRASE")', block)


if __name__ == "__main__":
    unittest.main()
