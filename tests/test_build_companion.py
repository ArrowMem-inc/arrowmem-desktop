import os, re, shutil, subprocess, sys, tempfile, unittest
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_markers

SH = open(os.path.join(ROOT, "scripts", "build-companion.sh"), encoding="utf-8").read()

class Static(unittest.TestCase):
    def test_pins_a_full_commit_and_a_tree(self):
        self.assertRegex(SH, r'(?m)^PIN_COMMIT="[0-9a-f]{40}"$')
        self.assertRegex(SH, r'(?m)^PIN_TREE="[0-9a-f]{40}"$')

    def test_refuses_without_the_object_and_the_tree(self):
        self.assertIn('cat-file -e "$PIN_COMMIT^{commit}"', SH)
        self.assertRegex(SH, r'rev-parse "\$PIN_COMMIT\^\{tree\}"\)" = "\$PIN_TREE"')

    def test_no_branch_name_and_no_override(self):
        self.assertNotRegex(SH, r"origin/|mini/|\bmain\b|\bmaster\b|HEAD")
        self.assertIn('"$#" -eq 0', SH)

    def test_exports_with_git_archive_and_checks_markers(self):
        self.assertIn('git -C "$REPO" archive "$FULL"', SH)
        self.assertIn("check_markers.py", SH)
        self.assertIn("--require-hashes --only-binary=:all:", SH)

    def test_script_markers_match_the_task(self):
        self.assertEqual(check_markers.MARKERS, ("PER_IP_MAX_CONNECTIONS", "SESSION_OPEN_BODY_MAX", "_local_owner_gate", "pair_aborted_overlap", "pair_code_mismatch", "PAIR_PROTOCOL"))

import check_lock

H = "--hash=sha256:" + "a" * 64
FULL_LOCK = "".join(f"{n}==1.0 \\\n    {H}\n" for n in check_lock.REQUIRED)

def run_script(lock_text):
    """Runs a copy of the shipped script in a scratch tree laid out as the repo is (HERE = parent of scripts/),
    with HOME and TMPDIR pointed at the scratch dir: the pinned lock path and the repo path are fixed in the
    script, so the test moves the whole tree instead of overriding anything."""
    with tempfile.TemporaryDirectory() as d:
        sd = os.path.join(d, "scripts")
        os.mkdir(sd)
        for f in ("build-companion.sh", "check_lock.py"):
            shutil.copy(os.path.join(ROOT, "scripts", f), sd)
        open(os.path.join(sd, "pyinstaller.lock"), "w").write(lock_text)
        env = dict(os.environ, HOME=d, TMPDIR=d)
        r = subprocess.run(["sh", os.path.join(sd, "build-companion.sh")], capture_output=True, text=True, env=env)
        return r.returncode, r.stderr, sorted(os.listdir(d))

class Lock(unittest.TestCase):
    def test_script_requires_hashes_only(self):
        self.assertEqual(SH.count("--require-hashes"), 2)
        self.assertNotIn("UNVERIFIED", SH)
        self.assertEqual(len(re.findall(r'pip" install .*-r "\$LOCK"', SH)), 1)
        self.assertIn("--require-hashes --only-binary=:all: -r \"$LOCK\"", SH)
        self.assertLess(SH.index("check_lock.py"), SH.index("-m venv"))

    def test_unhashed_lock_refuses_before_a_venv(self):
        rc, err, left = run_script("pyinstaller==6.11.1\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("full dependency closure", err)
        self.assertEqual(left, ["scripts"], "no venv or temp dir was created")

    def test_missing_closure_member_refuses(self):
        rc, err, _ = run_script(FULL_LOCK.replace("altgraph", "altgraxh"))
        self.assertNotEqual(rc, 0)
        self.assertIn("altgraph: not in the lock", err)

    def test_one_unhashed_entry_refuses(self):
        self.assertEqual(check_lock.problems(FULL_LOCK + "extra==1.0\n"), ["extra: no --hash"])

    def test_the_shipped_lock_passes_the_gate_without_pefile(self):
        self.assertNotIn("pefile", check_lock.REQUIRED)
        self.assertEqual([], check_lock.problems(open(os.path.join(ROOT, "scripts", "pyinstaller.lock"), encoding="utf-8").read()))

    def test_a_fully_hashed_lock_passes_the_gate(self):
        self.assertEqual(check_lock.problems(FULL_LOCK), [])
        rc, err, _ = run_script(FULL_LOCK)
        self.assertNotIn("full dependency closure", err)
        self.assertIn("pinned commit", err, "got past the lock gate to the pin check")

class FixedPaths(unittest.TestCase):
    # Env vars the shipped script may read to build a path, with the reason each is allowed.
    ALLOWED_ENV = {
        "HOME": "the fixed repo path ~/dev/companion-source and ~/.cargo/bin; the repo content is pinned by commit and tree",
        "TMPDIR": "the scratch dir for the export and the venv; it holds no input that is trusted",
    }

    def test_no_override_variables(self):
        for bad in ("PYINSTALLER_LOCK", "MVF_BACKEND_DIR", "PYTHON"):
            self.assertNotRegex(SH, r"\b" + bad + r"\b")

    def test_the_lock_and_python_are_fixed(self):
        self.assertRegex(SH, r'(?m)^LOCK="\$HERE/scripts/pyinstaller\.lock"$')
        self.assertRegex(SH, r'(?m)^PY="python3\.12"$')
        self.assertRegex(SH, r'(?m)^REPO="\$HOME/dev/companion-source"')

    def test_only_listed_env_vars_have_defaults_or_feed_paths(self):
        self.assertEqual(set(re.findall(r"\$\{(\w+):-", SH)), {"TMPDIR"})
        self.assertLessEqual(set(re.findall(r"\$\{(\w+):-", SH)), set(self.ALLOWED_ENV))
        # every $VAR the script expands but never assigns must be one of the allowed ones
        assigned = set(re.findall(r"(?m)^\s*(\w+)=", SH)) | {"W", "m", "HI", "d"}
        used = set(re.findall(r"\$\{?(\w+)", SH)) - set("0123456789#")
        self.assertLessEqual({u for u in used if u not in assigned and not u.isdigit()} - {"PATH", "TRIPLE"}, set(self.ALLOWED_ENV))

class LockRules(unittest.TestCase):
    def one(self, text):
        return check_lock.problems(text)

    def test_hash_without_a_version_pin(self):
        self.assertTrue(any("==version" in p for p in self.one(FULL_LOCK.replace("packaging==1.0", "packaging>=1.0"))))
        self.assertTrue(any("==version" in p for p in self.one(FULL_LOCK.replace("packaging==1.0", "packaging"))))
        self.assertTrue(any("==version" in p for p in self.one(FULL_LOCK.replace("packaging==1.0", "packaging==1.*"))))

    def test_hash_under_another_package(self):
        bad = FULL_LOCK.replace("packaging==1.0 \\\n    " + H + "\n", "packaging==1.0 " + H + " altgraph==1.0\n")
        self.assertTrue(any("another package" in p for p in self.one(bad)), self.one(bad))
        orphan = FULL_LOCK + "    " + H + "\n"
        self.assertTrue(any("option line" in p for p in self.one(orphan)))

    def test_index_and_include_options_are_refused(self):
        for opt in ("--index-url https://x/simple", "--extra-index-url https://x/simple", "-i https://x/simple",
                    "-r other.txt", "-c cons.txt", "-e .", "-f /wheels", "--find-links /wheels"):
            self.assertTrue(any("option" in p for p in self.one(FULL_LOCK + opt + "\n")), opt)
        inline = FULL_LOCK.replace("packaging==1.0 ", "packaging==1.0 --index-url https://x/simple ")
        self.assertTrue(any("option not allowed" in p for p in self.one(inline)))

    def test_only_pyinstaller_hashed_with_the_closure_missing(self):
        self.assertEqual(set(p.split(":")[0] for p in self.one("pyinstaller==6.11.1 \\\n    " + H + "\n")),
                         set(check_lock.REQUIRED) - {"pyinstaller"})

    def test_continuations_and_comments_parse(self):
        ok = "".join(f"{n}==1.0 \\\n    {H} \\\n    {H}\n    # via pyinstaller\n" for n in check_lock.REQUIRED)
        self.assertEqual(self.one(ok), [])

class Markers(unittest.TestCase):
    def run_check(self, blob):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob)
        try:
            return check_markers.check(f.name), subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "check_markers.py"), f.name], capture_output=True).returncode
        finally:
            os.unlink(f.name)

    def test_all_markers_pass(self):
        gone, rc = self.run_check(b"\x00junk PER_IP_MAX_CONNECTIONS=8 SESSION_OPEN_BODY_MAX def _local_owner_gate(self) pair_aborted_overlap pair_code_mismatch PAIR_PROTOCOL")
        self.assertEqual((gone, rc), ([], 0))

    def test_no_markers_fail(self):
        gone, rc = self.run_check(b"an older companion without hardening")
        self.assertEqual(sorted(gone), sorted(check_markers.MARKERS))
        self.assertEqual(rc, 1)

    def test_one_missing_marker_fails(self):
        gone, rc = self.run_check(b"PER_IP_MAX_CONNECTIONS SESSION_OPEN_BODY_MAX pair_aborted_overlap pair_code_mismatch PAIR_PROTOCOL")
        self.assertEqual((gone, rc), (["_local_owner_gate"], 1))

if __name__ == "__main__":
    unittest.main()
