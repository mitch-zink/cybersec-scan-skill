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
        for _ in range(10):
            run_cli("batch-next", self.repo)
            if json.loads(run_cli("batch-done", self.repo)[1])["complete"]:
                break
        return run_cli("save", self.repo, "FULL")[0]

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
    def test_partial_read_is_never_saved(self):
        rc, out = run_cli("save", self.repo, "FULL")
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
        a = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4", "evidence": "db.execute(", "control_checked": "Looked for a guard or bound parameter; none found."}
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2", "evidence": "API_KEY", "control_checked": "Looked for a guard or bound parameter; none found."}
        run_cli("merge", self.repo, self.cands(a, b))
        scope = os.path.join(self.tmp, "incr.json")
        pathlib.Path(scope).write_text(json.dumps({"read_set": ["app/search.py"]}))
        rc, out = run_cli("merge", self.repo, self.cands(a), "--scope", scope)
        res = json.loads(out)
        self.assertEqual(res["fixed"], [])                         # secrets.py was not read
        kept = {f["file"]: f["status"] for f in res["findings"]}
        self.assertEqual(kept, {"app/search.py": "open", "app/secrets.py": "open"})

    def test_dropped_but_still_present_stays_open(self):
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2", "evidence": "API_KEY", "control_checked": "Looked for a guard or bound parameter; none found."}
        run_cli("merge", self.repo, self.cands(b))
        scope = os.path.join(self.tmp, "incr.json")
        pathlib.Path(scope).write_text(json.dumps({"read_set": ["app/secrets.py"]}))
        res = json.loads(run_cli("merge", self.repo, self.cands(), "--scope", scope)[1])
        self.assertEqual(res["fixed"], [])                # key still in file
        self.assertEqual(res["findings"][0]["status"], "open")

    def test_incremental_fixes_only_inside_read_set(self):
        a = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4", "evidence": "db.execute(", "control_checked": "Looked for a guard or bound parameter; none found."}
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2", "evidence": "API_KEY", "control_checked": "Looked for a guard or bound parameter; none found."}
        run_cli("merge", self.repo, self.cands(a, b))
        pathlib.Path(self.repo, "app/secrets.py").write_text("# key removed\n")
        scope = os.path.join(self.tmp, "incr.json")
        pathlib.Path(scope).write_text(json.dumps({"read_set": ["app/secrets.py"]}))
        res = json.loads(run_cli("merge", self.repo, self.cands(a), "--scope", scope)[1])
        self.assertEqual([f["file"] for f in res["fixed"]], ["app/secrets.py"])

    def test_ids_stable_and_status_transitions(self):
        a = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4",
             "evidence": "db.execute(", "control_checked": "Looked for a guard or bound parameter; none found.", "severity": "high"}
        b = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2",
             "evidence": "API_KEY", "control_checked": "Looked for a guard or bound parameter; none found.", "severity": "high"}
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
        a = {"class": "CWE-22", "file": "app/files.py", "lines": "6-6", "evidence": "open(", "control_checked": "Looked for a guard or bound parameter; none found."}
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


class VerdictBatchTests(Fixture):
    def cands(self, evidence, cls="CWE-89"):
        p = os.path.join(self.tmp, "v.json")
        pathlib.Path(p).write_text(json.dumps([{"class": cls, "file": "app/search.py", "lines": "4-4",
                                                  "evidence": evidence, "control_checked": "Looked for a guard or bound parameter; none found."}]))
        return p

    def test_verdict_kept_on_rescan_and_cleared_on_change(self):
        first = json.loads(run_cli("merge", self.repo, self.cands("db.execute("))[1])["findings"][0]
        run_cli("verdict", self.repo, first["id"], "false_positive", "reviewed")
        again = json.loads(run_cli("merge", self.repo, self.cands("return db.execute("))[1])["findings"][0]
        self.assertEqual(again["id"], first["id"])                     # same class, file, function
        self.assertEqual(again["verdict"], "false_positive")
        moved = json.loads(run_cli("merge", self.repo, self.cands("db.execute(", "CWE-78"))[1])["findings"][0]
        self.assertNotEqual(moved["id"], first["id"])
        self.assertEqual(moved["verdict"], "new")                      # class change clears it

    def test_batches_pick_auth_code_first_and_complete(self):
        rc, out = run_cli("batch-next", self.repo, "--size", "2")
        b = json.loads(out)
        self.assertLessEqual(b["files"], 2)
        self.assertEqual(b["batch"], 1)
        run_cli("batch-done", self.repo)
        rc, out = run_cli("batch-next", self.repo, "--size", "100", "--all")
        b2 = json.loads(out)
        self.assertEqual(b2["batch"], 2)
        rc, out = run_cli("batch-done", self.repo)
        self.assertTrue(json.loads(out)["complete"])                    # every in-scope file read

    def test_bad_verdict_value_rejected(self):
        self.assertEqual(run_cli("verdict", self.repo, "F-x", "maybe")[0], 2)


class RuleTests(unittest.TestCase):
    """Each Semgrep rule must fire on its '# expect:' lines and nowhere else."""
    def test_semgrep_rules_match_expectations(self):
        import re, glob, tools
        samples = str(HERE.parent / "rules" / "samples")
        status, found = tools.semgrep_findings(samples, {"skip_tests": False})
        self.assertEqual(status, "ran")
        hits = {(os.path.basename(f["file"]), int(f["lines"].split("-")[0]), f["evidence"].split(" ")[0]) for f in found}
        expected = set()
        for path in glob.glob(os.path.join(samples, "**", "*.*"), recursive=True):
            for i, line in enumerate(open(path), 1):
                m = re.search(r"expect: (\S+)", line)
                if m:
                    expected.add((os.path.basename(path), i, m.group(1)))
        self.assertEqual(expected - hits, set(), "rules that did not fire")
        self.assertEqual(hits - expected, set(), "rules that fired unexpectedly")


class SqlRoleTests(unittest.TestCase):
    def test_service_role_only_policy_not_flagged_but_public_is(self):
        import sql_state, tempfile
        d = tempfile.mkdtemp()
        pathlib.Path(d, "0001.sql").write_text(
            "CREATE TABLE public.a (id uuid, tenant_id uuid);\n"
            "ALTER TABLE public.a ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY a_srv ON public.a FOR ALL TO service_role USING (true) WITH CHECK (true);\n"
            "CREATE TABLE public.b (id uuid, tenant_id uuid);\n"
            "ALTER TABLE public.b ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY b_open ON public.b FOR ALL TO authenticated USING (true);\n")
        f, _ = sql_state.findings(d)
        hit = {x["file"] + " " + x["evidence"].split(" ")[1] for x in f if x["evidence"].startswith("R2")}
        self.assertFalse(any(" a" in h for h in hit))
        self.assertTrue(any("b" in h for h in hit))


class SqlReplayTests(unittest.TestCase):
    def test_replay_flags_open_policy_leak_and_grant(self):
        import sql_state
        f, meta = sql_state.findings(str(HERE.parent / "rules" / "samples" / "migrations"))
        rules = sorted(x["evidence"].split(" ")[0] for x in f)
        self.assertIn("R1", rules)      # invoices: RLS off, anon reaches it by default grants
        self.assertIn("R2", rules)      # notes: USING (true)
        self.assertIn("R5", rules)      # SECURITY DEFINER export_all, callable by public
        self.assertIn("R8", rules)      # export_all has no search_path
        self.assertEqual(meta["unparsed"], 0)
        self.assertEqual(meta["do_unexpanded"], 1)   # the DO block, counted not guessed


if __name__ == "__main__":
    unittest.main()
