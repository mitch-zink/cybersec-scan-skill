"""Tests for scripts/cyber_state.py. Run: python3 tests/test_cyber_state.py -v"""
import contextlib
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys_path = HERE.parent / "scripts"
import sys
sys.path.insert(0, str(sys_path))
import cyber_state as cs  # noqa: E402


def run_cli(*args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cs.main(list(args))
    return rc, buf.getvalue()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "repo")
        subprocess.run(["bash", str(HERE / "make_fixture.sh"), self.repo], check=True,
                       capture_output=True)

    def head(self):
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo,
                              capture_output=True, text=True).stdout.strip()

    def save_base(self):
        n = len(cs.discover(self.repo)["files"])
        return run_cli("save", self.repo, "FULL", str(n))[0]

    def commit_edit(self, rel, text):
        pathlib.Path(self.repo, rel).write_text(text)
        subprocess.run(["git", "commit", "-qam", "edit"], cwd=self.repo, check=True,
                       env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e.invalid",
                                GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e.invalid"))


class DiscoverTests(Fixture):
    def test_skips_binary_and_lists_top_level(self):
        d = cs.discover(self.repo)
        self.assertIn("app/search.py", d["files"])
        self.assertEqual(d["skipped"].get("logo.png"), "binary")
        self.assertEqual(d["top_level"]["app"]["status"], "scanned")
        self.assertEqual(d["top_level"]["logo.png"]["status"], "skipped")

    def test_skip_dirs_never_scanned(self):
        pathlib.Path(self.repo, "node_modules").mkdir()
        pathlib.Path(self.repo, "node_modules", "x.js").write_text("x")
        subprocess.run(["git", "add", "-f", "node_modules/x.js"], cwd=self.repo, check=True)
        self.assertNotIn("node_modules/x.js", cs.discover(self.repo)["files"])


class CapTests(Fixture):
    def test_full_refused_over_cap_and_no_state_saved(self):
        orig = cs.FULL_CAP
        cs.FULL_CAP = 2
        try:
            rc, out = run_cli("incr", self.repo)
            self.assertEqual(rc, 3)                      # no state yet
            n = len(cs.discover(self.repo)["files"])
            rc, out = run_cli("save", self.repo, "FULL", str(n))
            self.assertEqual(rc, 5)
            self.assertFalse(pathlib.Path(self.repo, ".cybersec", "state.json").exists())
        finally:
            cs.FULL_CAP = orig

    def test_partial_read_is_never_saved(self):
        rc, out = run_cli("save", self.repo, "FULL", "1")
        self.assertEqual(rc, 4)
        self.assertFalse(pathlib.Path(self.repo, ".cybersec", "state.json").exists())


class StateTests(Fixture):
    def test_missing_state(self):
        self.assertEqual(cs.load_state(self.repo)["status"], "missing")

    def test_save_then_load(self):
        self.save_base()
        st = cs.load_state(self.repo)
        self.assertEqual(st["status"], "ok")
        self.assertEqual(st["data"]["last_sha"], self.head())

    def test_corrupt_state_is_renamed_and_full_is_forced(self):
        p = pathlib.Path(self.repo, ".cybersec", "state.json")
        p.parent.mkdir(parents=True)
        p.write_text("{not json")
        self.assertEqual(cs.load_state(self.repo)["status"], "corrupt")
        self.assertFalse(p.exists())
        self.assertTrue(any(f.name.startswith("state.json.bad-")
                            for f in p.parent.iterdir()))


class IncrementalTests(Fixture):
    def test_read_set_is_edited_file_plus_direct_dependent(self):
        self.save_base()
        self.commit_edit("app/search.py", pathlib.Path(self.repo, "app/search.py").read_text()
                         + "\n# touched\n")
        rc, out = run_cli("incr", self.repo)
        self.assertEqual(rc, 0)
        res = json.loads(out)
        self.assertEqual(res["mode"], "INCR")
        self.assertEqual(res["changed"], ["app/search.py"])
        self.assertIn("app/api.py", res["dependents"])          # imports search
        self.assertNotIn("app/safe.py", res["read_set"])         # unrelated
        self.assertNotIn("app/secrets.py", res["read_set"])

    def test_no_state_forces_full(self):
        rc, out = run_cli("incr", self.repo)
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(out)["mode"], "FULL")

    def test_read_cap_forces_full(self):
        self.save_base()
        orig = cs.READ_CAP
        cs.READ_CAP = 0
        try:
            self.commit_edit("app/search.py", "x = 1\n")
            rc, out = run_cli("incr", self.repo)
        finally:
            cs.READ_CAP = orig
        self.assertEqual(rc, 3)
        self.assertIn("read set", json.loads(out)["reason"])


class MergeTests(Fixture):
    def cands(self, *items):
        f = os.path.join(self.tmp, "c.json")
        pathlib.Path(f).write_text(json.dumps(list(items)))
        return f

    def test_incremental_keeps_unread_findings_open(self):
        a = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4", "evidence": "execute(...)"}
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2", "evidence": "API_KEY"}
        run_cli("merge", self.repo, self.cands(a, b))
        scope = os.path.join(self.tmp, "incr.json")
        pathlib.Path(scope).write_text(json.dumps({"read_set": ["app/search.py"]}))
        rc, out = run_cli("merge", self.repo, self.cands(a), "--scope", scope)
        res = json.loads(out)
        self.assertEqual(res["fixed"], [])                         # secrets.py was not read
        kept = {f["file"]: f["status"] for f in res["findings"]}
        self.assertEqual(kept, {"app/search.py": "open", "app/secrets.py": "open"})

    def test_dropped_but_still_present_stays_open(self):
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2", "evidence": "API_KEY"}
        run_cli("merge", self.repo, self.cands(b))
        scope = os.path.join(self.tmp, "incr.json")
        pathlib.Path(scope).write_text(json.dumps({"read_set": ["app/secrets.py"]}))
        res = json.loads(run_cli("merge", self.repo, self.cands(), "--scope", scope)[1])
        self.assertEqual(res["fixed"], [])                # key still in file
        self.assertEqual(res["findings"][0]["status"], "open")

    def test_incremental_fixes_only_inside_read_set(self):
        a = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4", "evidence": "execute(...)"}
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2", "evidence": "API_KEY"}
        run_cli("merge", self.repo, self.cands(a, b))
        pathlib.Path(self.repo, "app/secrets.py").write_text("# key removed\n")
        scope = os.path.join(self.tmp, "incr.json")
        pathlib.Path(scope).write_text(json.dumps({"read_set": ["app/secrets.py"]}))
        res = json.loads(run_cli("merge", self.repo, self.cands(a), "--scope", scope)[1])
        self.assertEqual([f["file"] for f in res["fixed"]], ["app/secrets.py"])

    def test_ids_stable_and_status_transitions(self):
        a = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4",
             "evidence": "execute(...)", "severity": "high"}
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2",
             "evidence": "API_KEY", "severity": "high"}
        rc, out1 = run_cli("merge", self.repo, self.cands(a, b))
        first = json.loads(out1)["findings"]
        self.assertTrue(all(f["status"] == "new" for f in first))
        pathlib.Path(self.repo, "app/secrets.py").write_text("# key removed\n")
        rc, out2 = run_cli("merge", self.repo, self.cands(a))
        second = json.loads(out2)
        self.assertEqual(second["findings"][0]["id"], first[0]["id"])
        self.assertEqual(second["findings"][0]["status"], "open")
        self.assertEqual([f["id"] for f in second["fixed"]], [first[1]["id"]])
        self.assertEqual(second["fixed"][0]["status"], "fixed")

    def test_duplicate_candidates_get_distinct_ids(self):
        a = {"class": "CWE-22", "file": "app/files.py", "lines": "6-6", "evidence": "open("}
        _, out = run_cli("merge", self.repo, self.cands(a, a))
        ids = [f["id"] for f in json.loads(out)["findings"]]
        self.assertEqual(len(set(ids)), 2)


class ToolTests(Fixture):
    def test_html_escapes_untrusted_text(self):
        import tools
        f = [{"severity": "high", "class": "<script>x</script>", "owasp": "A05", "source": "agent",
              "file": "a.py", "lines": "1-1", "evidence": "<img onerror=1>", "fix_hint": "",
              "status": "new"}]
        page = tools.html_report(f, {"repo": "r", "mode": "FULL", "date": "d", "scanners": "s"}, [])
        self.assertNotIn("<script>x", page)
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", page)

    def test_tool_findings_survive_agent_merge(self):
        tool = {"class": "CVE-2025-1", "file": "package-lock.json", "lines": "-",
                "evidence": "pkg@1 CVE-2025-1", "severity": "high", "source": "osv"}
        p = os.path.join(self.tmp, "c.json")
        pathlib.Path(p).write_text(json.dumps([tool]))
        pathlib.Path(self.repo, ".cybersec").mkdir()
        pathlib.Path(self.repo, ".cybersec", "last_findings.json").write_text(
            json.dumps([dict(tool, id="F-tool", status="open")]))
        empty = os.path.join(self.tmp, "none.json")
        pathlib.Path(empty).write_text("[]")
        res = json.loads(run_cli("merge", self.repo, empty)[1])
        self.assertEqual(res["fixed"], [])
        self.assertIn("F-tool", [f["id"] for f in res["findings"]])


if __name__ == "__main__":
    unittest.main()
