import json, os, re, subprocess, unittest

R = os.path.join(os.path.dirname(__file__), "..")


class Files(unittest.TestCase):
    def test_bundle_is_appimage_only(self):
        b = json.load(open(os.path.join(R, "src-tauri", "tauri.conf.json")))["bundle"]
        self.assertEqual(b["targets"], ["appimage"])
        self.assertIn("icons/icon.png", b["icon"])

    def test_sign_script_prints_a_command_and_reads_no_key(self):
        p = os.path.join(R, "scripts", "sign-release.sh")
        out = subprocess.run(["/bin/sh", p, "/tmp/A B.AppImage"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("minisign -S -s <PATH-TO-YOUR-SECRET-KEY> -m '/tmp/A B.AppImage'", out.stdout)
        src = open(p).read()
        for bad in ("cat ", "read ", "< ", "$HOME", "minisign -S -s \"", ".key"):
            self.assertNotIn(bad, src.replace("# ", ""))
        self.assertEqual(subprocess.run(["/bin/sh", p], capture_output=True).returncode, 2)

    def test_pkgbuild_installs_the_privileged_files_with_their_modes(self):
        t = open(os.path.join(R, "packaging", "arch", "PKGBUILD")).read()
        got = {}
        for m in re.finditer(r'install -Dm(\d+) "[^"]*?([^/"]+)" "\$pkgdir(/[^"]+)"', t):
            got[m.group(3)] = (m.group(1), m.group(2))
        self.assertEqual(got["/usr/lib/arrowmem/arrowbridge-fw"], ("755", "arrowbridge-fw"))
        pol = "/usr/share/polkit-1/actions/ca.arrowmem.arrowbridge.firewall.policy"
        self.assertEqual(got[pol], ("644", "ca.arrowmem.arrowbridge.firewall.policy"))
        self.assertEqual(got["/usr/bin/arrowmem-desktop"][0], "755")
        self.assertEqual(got["/usr/share/applications/arrowmem-desktop.desktop"][0], "644")
        self.assertEqual(got["/usr/share/icons/hicolor/128x128/apps/arrowmem-desktop.png"][0], "644")
        self.assertRegex(t, r"(?m)^source=\(\)")
        self.assertNotRegex(t, r"https?://[^\s]*(\.tar|\.zip|\.git|releases)")

    def test_pkgbuild_installs_both_sidecars_where_the_app_looks(self):
        t = open(os.path.join(R, "packaging", "arch", "PKGBUILD")).read()
        rs = open(os.path.join(R, "src-tauri", "src", "supervisor.rs")).read()
        sysdir = re.search(r'SYSTEM_SIDECAR_DIR: &str = "([^"]+)"', rs).group(1)
        self.assertEqual(sysdir, "/usr/lib/arrowmem")
        self.assertIn('install -Dm755 "$_repo/src-tauri/binaries/arrowbridge-companion-$_triple" "$pkgdir%s/arrowbridge-companion"' % sysdir, t)
        self.assertRegex(rs, r'"arrowbridge-companion"')
        # llama-server: two builds, own directories and libraries, flat names the resolver looks for
        self.assertIn("for v in cpu vulkan; do", t)
        self.assertIn('install -Dm755 "$_repo/src-tauri/binaries/llama-$v/llama-server" "$pkgdir%s/llama-$v/llama-server"' % sysdir, t)
        self.assertIn('install -Dm755 "$lib" "$pkgdir%s/llama-$v/$(basename "$lib")"' % sysdir, t)
        self.assertIn('ln -s "llama-$v/llama-server" "$pkgdir%s/llama-server-$v"' % sysdir, t)
        self.assertIn('"llama-server-vulkan"', rs)
        self.assertIn('"llama-server-cpu"', rs)
        self.assertNotRegex(t, r'(?m)^\s*install .*\$pkgdir%s/[^/"]*\.so' % re.escape(sysdir), "libs must not be flat")
        # the loader is optional: the CPU build works without it
        self.assertRegex(t, r"(?m)^optdepends=\(.*vulkan-icd-loader")
        self.assertNotRegex(t, r"(?m)^depends=\(.*vulkan")
        for dep in ("'webkit2gtk-4.1'", "'gtk3'", "'libayatana-appindicator'"):
            self.assertRegex(t, r"(?m)^depends=\(.*" + re.escape(dep), "Tauri runtime library missing from depends")
        self.assertRegex(t, r"(?m)^source=\(\)")
        self.assertNotRegex(t, r"curl|wget|git clone|https?://[^\s\"]*\.(tar|zip|gz)")

    def test_fetch_both_variants_sha_checked_into_separate_dirs(self):
        import hashlib, io, shutil, sys, tarfile, tempfile
        src = open(os.path.join(R, "scripts", "fetch-sidecars.sh")).read()
        code = src.split("<<'PY'\n")[1].rsplit("PY\n", 1)[0]

        def tgz(libname):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as t:
                for name, data in (("llama-b1/llama-server", b"bin-" + libname), ("llama-b1/" + libname.decode(), b"lib")):
                    ti = tarfile.TarInfo(name); ti.size = len(data); ti.mode = 0o755
                    t.addfile(ti, io.BytesIO(data))
            return buf.getvalue()

        def run(corrupt):
            root = tempfile.mkdtemp()
            os.makedirs(os.path.join(root, "models"))
            blobs = {"cpu": tgz(b"libggml-cpu.so"), "vulkan": tgz(b"libggml-vulkan.so")}
            builds = {k: {"asset": k + ".tgz", "size_bytes": len(v), "sha256": hashlib.sha256(v).hexdigest()} for k, v in blobs.items()}
            if corrupt:
                builds["vulkan"]["sha256"] = "0" * 64
            man = {"llama_server": {"base_url": "https://github.com/ggml-org/llama.cpp/releases/download/b1/", "builds": {"t": builds}}}
            open(os.path.join(root, "models", "manifest.json"), "w").write(json.dumps(man))
            import urllib.request
            real = urllib.request.urlopen
            urllib.request.urlopen = lambda url: io.BytesIO(blobs[os.path.basename(url)[:-4]])
            argv, sys.argv = sys.argv, ["x", root, "t", "both", os.path.join(root, "out")]
            try:
                try:
                    exec(compile(code, "fetch", "exec"), {"__name__": "x"})
                    code_ = 0
                except SystemExit as e:
                    code_ = e.code
            finally:
                urllib.request.urlopen = real
                sys.argv = argv
            return root, code_

        root, rc = run(False)
        try:
            self.assertIn(rc, (None, 0))
            out = os.path.join(root, "out")
            self.assertEqual(sorted(os.listdir(out)), ["llama-cpu", "llama-vulkan"])
            self.assertEqual(sorted(os.listdir(os.path.join(out, "llama-cpu"))), ["libggml-cpu.so", "llama-server"])
            self.assertEqual(sorted(os.listdir(os.path.join(out, "llama-vulkan"))), ["libggml-vulkan.so", "llama-server"])
        finally:
            shutil.rmtree(root)
        root, rc = run(True)
        try:
            self.assertTrue(isinstance(rc, str) and "mismatch" in rc)
            self.assertFalse(os.path.exists(os.path.join(root, "out", "llama-vulkan")), "nothing extracted for a bad hash")
        finally:
            shutil.rmtree(root)

    def test_release_public_key_is_pinned_and_verify_uses_it(self):
        pub = open(os.path.join(R, "packaging", "release", "arrowmem-release.pub")).read()
        self.assertEqual(pub, "untrusted comment: minisign public key D8844FE7C32F5422\n"
                              "RWQiVC/D50+E2CLAW5DdthW358TkUOf8ifg/xK4O5gcPmUNfWrCkN/Zd\n")
        import base64
        raw = base64.b64decode(pub.splitlines()[1])
        self.assertEqual((len(raw), raw[:2]), (42, b"Ed"))
        self.assertEqual(raw[2:10][::-1].hex().upper(), "D8844FE7C32F5422")
        out = subprocess.run(["/bin/sh", os.path.join(R, "scripts", "sign-release.sh"), "x.AppImage"], capture_output=True, text=True).stdout
        self.assertIn("minisign -V -p ~/arrowmem-release.pub -m 'x.AppImage' -x 'x.AppImage.minisig'", out)
        self.assertNotIn("<PATH-TO-PUBLIC-KEY>", out)

    def test_llama_server_is_not_a_tauri_sidecar(self):
        # llama-server ships as two per-variant directories with their libraries (fetch-sidecars.sh both, PKGBUILD),
        # spawned by path from supervisor.rs, never through the shell plugin. A flat externalBin entry would make
        # the build look for binaries/llama-server-<triple>, which fetch-sidecars never writes.
        conf = json.load(open(os.path.join(R, "src-tauri", "tauri.conf.json")))
        self.assertEqual(conf["bundle"]["externalBin"], ["binaries/arrowbridge-companion"])
        caps = open(os.path.join(R, "src-tauri", "capabilities", "default.json")).read()
        self.assertNotIn("llama-server", caps)

    def test_makepkg_never_rewrites_a_binary_and_the_gate_compares_bytes(self):
        t = open(os.path.join(R, "packaging", "arch", "PKGBUILD")).read()
        self.assertRegex(t, r"(?m)^options=\('!strip' '!debug'\)$")
        v = open(os.path.join(R, "scripts", "verify-pkg.sh")).read()
        self.assertIn('same "$BIN/arrowbridge-companion-$TRIPLE" "$W/usr/lib/arrowmem/arrowbridge-companion"', v)
        self.assertIn('for v in cpu vulkan; do', v)
        self.assertIn('"pair_protocol": *"typed6"', v)
        self.assertIn('companion-freeze.sha256', v)
        self.assertIn('the packaged companion is not the reviewed freeze', v)
        self.assertTrue(v.rstrip().endswith('sha256sum "$PKG"'), "the package sha256 is the last line printed")
        self.assertIn('mkdir -m 700 "$W/state"', v)
        self.assertIn("exit 1", v)
        self.assertNotRegex(v, r"PORT=(8788|8080|11434)\b")

    def test_verify_pkg_reports_different_bytes(self):
        # Runs the comparison half on a fake extracted tree: identical files pass, one changed byte fails.
        import shutil, tempfile
        d = tempfile.mkdtemp()
        try:
            v = open(os.path.join(R, "scripts", "verify-pkg.sh")).read()
            fn = v[v.index("same() {"):v.index("\n}\n", v.index("same() {")) + 3]
            a, b = os.path.join(d, "a"), os.path.join(d, "b")
            open(a, "wb").write(b"x" * 100); open(b, "wb").write(b"x" * 100)
            ok = subprocess.run(["/bin/sh", "-c", "fail=0\n" + fn + 'same "$1" "$2"; echo "fail=$fail"', "sh", a, b],
                                capture_output=True, text=True)
            self.assertIn("fail=0", ok.stdout)
            open(b, "wb").write(b"x" * 99 + b"y")
            bad = subprocess.run(["/bin/sh", "-c", "fail=0\n" + fn + 'same "$1" "$2"; echo "fail=$fail"', "sh", a, b],
                                 capture_output=True, text=True)
            self.assertIn("fail=1", bad.stdout)
            self.assertIn("DIFFERENT", bad.stderr)
        finally:
            shutil.rmtree(d)

    def test_helper_declares_a_version(self):
        s = open(os.path.join(R, "scripts", "arrowbridge-fw")).read()
        self.assertRegex(s, r"(?m)^HELPER_VERSION=[0-9]+$")

    def test_no_root_install_path_remains(self):
        needles = ["bash " + "-s", "root" + "-install", "root" + "install"]
        for base, dirs, files in os.walk(R):
            dirs[:] = [d for d in dirs if d not in ("target", ".git", "__pycache__", "node_modules")]
            for f in files:
                if f.endswith((".png", ".lock")) or f == "test_release_files.py":
                    continue
                text = open(os.path.join(base, f), encoding="utf-8", errors="replace").read()
                for n in needles:
                    self.assertNotIn(n, text, f"{n} in {os.path.join(base, f)}")

    def test_policy_has_one_action_and_both_languages(self):
        t = open(os.path.join(R, "packaging", "polkit", "ca.arrowmem.arrowbridge.firewall.policy"), encoding="utf-8").read()
        self.assertEqual(t.count("<action "), 1)
        self.assertEqual(t.count('xml:lang="fr"'), 2)
        self.assertNotIn("PLACEHOLDER", t)


if __name__ == "__main__":
    unittest.main()
