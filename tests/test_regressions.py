"""Regression tests for the 20 v2 defects (B1-B10, X1-X10). Run: python3 tests/test_regressions.py -v"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from test_cyber_state import HERE, Fixture, cs, run_cli

import config  # noqa: E402  (scripts/ is on sys.path via test_cyber_state)
import sql_state  # noqa: E402
import tools  # noqa: E402

GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e.invalid")
AWS = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"\naws_access_key_id = "AKIAZ7Q2XBVN3MLTY4PS"\n'
STRIPE = 'export STRIPE_KEY="sk_' 'live_51HxQz2eZvKYlo2C8a9b7c6d5e4f3g2h1"\n'
DATA = HERE / "data"
has = shutil.which


def sql_dir(text):
    d = tempfile.mkdtemp()
    pathlib.Path(d, "0001.sql").write_text(text)
    return d


def rules(findings, rule):
    return [f for f in findings if f["evidence"].startswith(rule + " ")]


class Reg(Fixture):
    def write(self, rel, text):
        p = pathlib.Path(self.repo, rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def commit(self):
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True, env=GIT_ENV)
        subprocess.run(["git", "commit", "-qm", "x"], cwd=self.repo, check=True, env=GIT_ENV)

    def cands(self, *items):
        p = os.path.join(self.tmp, "c.json")
        pathlib.Path(p).write_text(json.dumps(list(items)))
        return p

    def report(self):
        return pathlib.Path(self.repo, ".cybersec", "report.html").read_text()

    def full_loop(self):
        for _ in range(10):
            run_cli("batch-next", self.repo)
            done = json.loads(run_cli("batch-done", self.repo)[1])
            if done["complete"]:
                return done
        return done

    # ---- batch state (S4)
    def test_b1_full_loop_completes_without_flags(self):
        self.assertTrue(self.full_loop()["complete"])

    def test_b5_save_full_with_sql_files(self):
        self.write("migrations/0001.sql", "select 1;\n"); self.commit()
        self.full_loop()
        self.assertEqual(run_cli("save", self.repo, "FULL")[0], 0)

    def test_b6_changed_file_is_reread(self):
        self.full_loop()
        self.write("app/search.py", "x = 1  # changed\n"); self.commit()
        b = json.loads(run_cli("batch-next", self.repo)[1])
        self.assertIn("app/search.py", b["read_set"])

    # ---- skip lists (S2, S3)
    def test_b2_lockfiles_not_skipped_for_osv(self):
        fn = getattr(config, "vendor_skipped", None)
        self.assertIsNotNone(fn, "config.vendor_skipped missing")
        cfg = {"skip_tests": True}
        for lf in ("yarn.lock", "poetry.lock", "uv.lock", "Cargo.lock"):
            self.assertIsNone(fn(lf, cfg), lf)
        self.assertEqual(fn("node_modules/a/yarn.lock", cfg), "skip-dir")

    @unittest.skipUnless(has("gitleaks"), "gitleaks not installed")
    def test_b3_secrets_in_docs_are_reported(self):
        self.write("docs/setup.md", STRIPE); self.write("NOTES.md", AWS); self.commit()
        _, found = tools.gitleaks_findings(self.repo, {"skip_tests": True}, history=False)
        files = {f["file"] for f in found}
        self.assertIn("docs/setup.md", files)
        self.assertIn("NOTES.md", files)

    # ---- tools (S5, S6, S9)
    def test_b7_timeout_marks_tool_not_run(self):
        orig = subprocess.run

        def fake(cmd, *a, **k):
            if cmd[0] in ("osv-scanner", "gitleaks", "semgrep", "zizmor", "trivy"):
                raise subprocess.TimeoutExpired(cmd, 1)
            return orig(cmd, *a, **k)
        tools.subprocess.run = fake
        try:
            rc, _ = run_cli("tools", self.repo, "--no-history")
        finally:
            tools.subprocess.run = orig
        self.assertEqual(rc, 0)
        self.assertIn("NOT RUN (timeout", self.report())

    @unittest.skipUnless(has("gitleaks"), "gitleaks not installed")
    def test_x1_no_history_keeps_history_findings_open(self):
        self.write("app/old.py", AWS); self.commit()
        pathlib.Path(self.repo, "app/old.py").unlink(); self.commit()
        run_cli("tools", self.repo)
        out = json.loads(run_cli("tools", self.repo, "--no-history")[1])
        self.assertEqual(out["fixed"], 0)
        hist = [f for f in json.loads(pathlib.Path(self.repo, ".cybersec/last_findings.json").read_text())
                if f.get("scope") == "history"]
        self.assertTrue(hist and all(f["status"] == "open" for f in hist))

    @unittest.skipUnless(has("gitleaks"), "gitleaks not installed")
    def test_x2_report_has_status_and_fixed_section(self):
        self.write("app/k.py", AWS); self.commit()
        run_cli("tools", self.repo, "--no-history")
        pathlib.Path(self.repo, "app/k.py").unlink(); self.commit()
        run_cli("tools", self.repo, "--no-history")
        page = self.report()
        self.assertIn("<th>Status</th>", page)
        self.assertRegex(page, r"Fixed since last run \(\d+\)")

    def test_b10_verdict_command_is_absolute(self):
        run_cli("tools", self.repo, "--no-history")
        m = re.search(r"python3 (\S+cyber_state\.py) verdict", self.report())
        self.assertTrue(m, "no verdict command")
        self.assertTrue(os.path.isabs(os.path.expanduser(m.group(1))))
        self.assertTrue(os.path.exists(os.path.expanduser(m.group(1))))

    def test_x9_tools_rewrites_main_report(self):
        run_cli("merge", self.repo, self.cands())
        p = pathlib.Path(self.repo, ".cybersec/report.html")
        before = p.stat().st_mtime_ns
        os.utime(p, ns=(before - 10**9, before - 10**9))
        run_cli("tools", self.repo, "--no-history")
        self.assertNotEqual(p.stat().st_mtime_ns, before - 10**9)

    # ---- ids and merge (S7, S8)
    def test_b8_ids_wide_and_stable(self):
        ids = {cs.finding_id("agent", "CWE-89", f"f{i}.py", "x", set()) for i in range(2000)}
        self.assertEqual(len(ids), 2000)
        self.assertTrue(all(re.fullmatch(r"F-[0-9a-f]{12}", i) for i in ids))
        base = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4",
                "control_checked": "Looked for a bound parameter or allowlist in find(); none."}
        a = json.loads(run_cli("merge", self.repo, self.cands(dict(base, evidence="db.execute(")))[1])["findings"][0]["id"]
        b = json.loads(run_cli("merge", self.repo, self.cands(dict(base, evidence="return db.execute(")))[1])["findings"][0]["id"]
        self.assertEqual(a, b)

    def test_x3_finding_in_deleted_file_is_fixed(self):
        n = len(cs.discover(self.repo)["files"])
        run_cli("save", self.repo, "FULL", str(n))
        c = {"class": "CWE-798", "file": "app/secrets.py", "lines": "2-2", "evidence": "API_KEY",
             "control_checked": "Looked for an env lookup or vault read; the key is a literal."}
        run_cli("merge", self.repo, self.cands(c))
        pathlib.Path(self.repo, "app/secrets.py").unlink(); self.commit()
        run_cli("incr", self.repo)
        res = json.loads(run_cli("merge", self.repo, self.cands(), "--scope",
                                 os.path.join(self.repo, ".cybersec/incr.json"))[1])
        self.assertEqual([f["file"] for f in res["fixed"]], ["app/secrets.py"])
        self.assertEqual(res["fixed"][0].get("fixed_reason"), "file deleted")

    def test_x8_invented_evidence_is_rejected(self):
        c = {"class": "CWE-89", "file": "app/safe.py", "lines": "1-1", "evidence": "this text is not in the file",
             "control_checked": "Looked for parameters; none found in this function."}
        res = json.loads(run_cli("merge", self.repo, self.cands(c))[1])
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["rejected"][0]["reason"], "evidence-not-in-file")

    # ---- SQL (S10, S11, S12)
    def test_b9_sql_meta_sums_folders(self):
        for sub, t in (("a/migrations", "x"), ("b/migrations", "y")):
            self.write(f"{sub}/0001.sql", f"CREATE TABLE public.{t} (id uuid, org_id uuid);\n")
        self.commit()
        run_cli("tools", self.repo, "--no-history")
        self.assertRegex(self.report(), r"SQL replay: 2 tables")

    def test_x6_vendor_migrations_skipped(self):
        self.write("node_modules/pkg/migrations/0001.sql", "CREATE TABLE public.vend (id uuid, tenant_id uuid);\n")
        subprocess.run(["git", "add", "-f", "-A"], cwd=self.repo, check=True, env=GIT_ENV)
        subprocess.run(["git", "commit", "-qm", "v"], cwd=self.repo, check=True, env=GIT_ENV)
        run_cli("tools", self.repo, "--no-history")
        lf = json.loads(pathlib.Path(self.repo, ".cybersec/last_findings.json").read_text())
        self.assertFalse([f for f in lf if "vend" in f["evidence"]])


class SqlReg(unittest.TestCase):
    def test_b4_no_r3(self):
        f, _ = sql_state.findings(sql_dir(
            "CREATE TABLE public.t (id uuid, user_id uuid);\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY s ON public.t FOR SELECT USING (user_id = auth.uid());\n"))
        self.assertEqual(rules(f, "R3"), [])

    def test_x4_quoted_policy_name(self):
        f, meta = sql_state.findings(sql_dir(
            'CREATE TABLE public.p (id uuid, user_id uuid);\nALTER TABLE public.p ENABLE ROW LEVEL SECURITY;\n'
            'CREATE POLICY "Anyone can read" ON public.p FOR SELECT USING (true);\n'))
        self.assertEqual(len(rules(f, "R2")), 1)
        self.assertEqual(meta["unparsed"], 0)

    def test_x5_schema_qualified(self):
        f, meta = sql_state.findings(sql_dir(
            "CREATE TABLE public.users (id uuid, org_id uuid);\nCREATE TABLE private.users (id uuid);\n"
            "ALTER TABLE private.users ENABLE ROW LEVEL SECURITY;\n"))
        self.assertTrue(any("public.users" in x["evidence"] for x in rules(f, "R1")))
        self.assertEqual(meta["tables"], 2)

    def test_x7_grant_all_tables_in_schema(self):
        d = sql_dir("CREATE TABLE public.g (id uuid, org_id uuid);\nALTER TABLE public.g ENABLE ROW LEVEL SECURITY;\n"
                    "REVOKE ALL ON public.g FROM anon;\nGRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;\n")
        _, meta = sql_state.findings(d)
        self.assertEqual(meta["unparsed"], 0)
        row = next(r for r in sql_state.table_rows(d) if r["table"] == "public.g")
        self.assertIn("anon", row["roles"])


class OsvReg(unittest.TestCase):
    def test_x10_osv_severity_from_groups(self):
        d = tempfile.mkdtemp()
        shutil.copy(DATA / "poetry.lock", d)
        data = json.loads((DATA / "osv_requests.json").read_text())
        orig, tools.shutil.which = tools.shutil.which, (lambda t: "/x/" + t)
        orig_run = tools._run
        tools._run = lambda *a, **k: ("ok", 1, data)
        try:
            status, found = tools.osv_findings(d, {"skip_tests": True, "osv_enrich": False})
        finally:
            tools.shutil.which, tools._run = orig, orig_run
        self.assertEqual(status, "ran")
        cve = next(f for f in found if f["class"] == "CVE-2018-18074")
        self.assertEqual(cve["severity"], "high")
        self.assertIn("2.20.0", cve["fix_hint"])


if __name__ == "__main__":
    unittest.main()
