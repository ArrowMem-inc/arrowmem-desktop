import json, os, shutil, subprocess, unittest
JS = os.path.join(os.path.dirname(__file__), "..", "packaging", "omarchy-panel", "arrowbridge-panel", "Model.js")
HARNESS = "var vm=require('vm'),fs=require('fs');var src=fs.readFileSync(process.argv[1],'utf8').replace('.pragma library','');" \
          "var c={};vm.runInNewContext(src+';this.okId=okId',c);var ids=JSON.parse(process.argv[2]);" \
          "console.log(JSON.stringify(ids.map(function(i){return c.okId(i)})))"

def verdicts(ids):
    out = subprocess.run(["node", "-e", HARNESS, JS, json.dumps(ids)], capture_output=True, text=True, check=True).stdout
    return json.loads(out)

@unittest.skipUnless(shutil.which("node"), "node absent")
class T(unittest.TestCase):
    def test_refused(self):
        bad = ["áb", "a͸b", "a b", "x" * 201, "", "aéb", "a\U0001F600b", "a\nb"]
        self.assertEqual(verdicts(bad), [False] * len(bad))
    def test_accepted(self):
        good = ["qwen3-coder:30b", "org/model.v2_1", "x" * 200]
        self.assertEqual(verdicts(good), [True] * len(good))
