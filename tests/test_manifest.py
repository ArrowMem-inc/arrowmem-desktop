import copy, json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from validate_manifest import validate
M = json.load(open(os.path.join(os.path.dirname(__file__), "..", "models", "manifest.json")))

class T(unittest.TestCase):
    def test_real_manifest_ok(self): self.assertEqual(validate(M), [])
    def mut(self, f):
        m = copy.deepcopy(M); f(m); return validate(m)
    def test_3n_repo_refused(self):
        def f(m): m["models"][0]["repo"] = "google/gemma-3n-E2B-it"; m["allowed_repos"].append("google/gemma-3n-E2B-it")
        self.assertTrue(any("3n" in e for e in self.mut(f)))
    def test_3n_file_refused(self):
        self.assertTrue(any("3n" in e for e in self.mut(lambda m: m["models"][0].update(file="gemma-3n.gguf"))))
    def test_unlisted_repo_refused(self):
        self.assertTrue(any("allowlist" in e for e in self.mut(lambda m: m["models"][0].update(repo="evil/x"))))
    def test_gated_refused(self):
        self.assertTrue(self.mut(lambda m: m["models"][1].update(gated=True)))
    def test_other_license_refused(self):
        self.assertTrue(self.mut(lambda m: m["models"][2].update(license="Gemma")))
    def test_default_is_e4b(self):
        d = [e["id"] for e in M["models"] if e["default"]]
        self.assertEqual(d, ["gemma-4-E4B-it-q4_0"])
    def test_two_defaults_refused(self):
        self.assertTrue(any("default" in e for e in self.mut(lambda m: m["models"][0].update(default=True))))
    def test_missing_tier_refused(self):
        self.assertTrue(any("tier" in e for e in self.mut(lambda m: m["models"][0].pop("tier"))))
    def test_bad_ram_refused(self):
        self.assertTrue(any("min_ram" in e for e in self.mut(lambda m: m["models"][0].update(min_ram_gb=0))))
    def test_non_hf_host_refused(self):
        self.assertTrue(any("source_host" in e for e in self.mut(lambda m: m["models"][0].update(source_host="evil.example"))))
    def test_larger_tier_exists(self):
        self.assertGreater(max(e["tier"] for e in M["models"]), [e for e in M["models"] if e["default"]][0]["tier"])
    def test_only_e4b_and_e2b_approved(self):
        self.assertEqual(sorted(e["id"] for e in M["models"] if e["approved"]), ["gemma-4-E2B-it-q4_0", "gemma-4-E4B-it-q4_0"])
    def test_candidates_unapproved_and_google_sourced(self):
        c = [e for e in M["models"] if e["id"] in ("gemma-4-12B-it-q4_0", "gemma-4-26B-A4B-it-q4_0")]
        self.assertEqual(len(c), 2)
        for e in c:
            self.assertFalse(e["approved"]); self.assertTrue(e["repo"].startswith("google/")); self.assertEqual(len(e["sha256"]), 64)
    def test_no_third_party_iq4(self):
        self.assertFalse(any("iq4" in e["id"].lower() or "iq4" in e["file"].lower() for e in M["models"]))
if __name__ == "__main__": unittest.main()
