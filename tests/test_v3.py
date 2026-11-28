"""v3 step tests (S7, S11-S18, S21-S23). Run: python3 tests/test_v3.py -v"""
import json
import os
import pathlib
import shutil
import tempfile
import unittest

from test_cyber_state import Fixture, cs, run_cli
from test_regressions import DATA, rules, sql_dir

import sql_state  # noqa: E402
import tools  # noqa: E402

CC = "Looked for an auth check or bound parameter; none found."
T = "CREATE TABLE public.t (id uuid, user_id uuid);\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"


def sql_rules(text, rule):
    return rules(sql_state.findings(sql_dir(text))[0], rule)


class IdMigrationTests(Fixture):
    def test_id_migration(self):
        c = {"class": "CWE-89", "file": "app/search.py", "lines": "4-4", "evidence": "db.execute(", "control_checked": CC}
        legacy = cs._hid("agent", "CWE-89", "app/search.py", "db.execute(", n=4)
        run_cli("verdict", self.repo, legacy, "accepted_risk", "v2 verdict")
        p = os.path.join(self.tmp, "c.json")
        pathlib.Path(p).write_text(json.dumps([c]))
        f = json.loads(run_cli("merge", self.repo, p)[1])["findings"][0]
        self.assertEqual(f["verdict"], "accepted_risk")
        v = json.loads(pathlib.Path(self.repo, ".cybersec/verdicts.json").read_text())
        self.assertEqual(v[f["id"]]["migrated_from"], legacy)


class SqlParserTests(unittest.TestCase):
    def test_do_loop_expansion(self):
        d = sql_dir("CREATE TABLE public.agent_runs (id uuid, user_id uuid);\n"
                    "CREATE TABLE public.agent_memory (id uuid, user_id uuid);\n"
                    "DO $$ DECLARE t text; BEGIN\n"
                    "  FOREACH t IN ARRAY ARRAY['agent_runs','agent_memory'] LOOP\n"
                    "    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);\n"
                    "    EXECUTE format('REVOKE ALL ON public.%I FROM anon', t);\n"
                    "    EXECUTE format('CREATE POLICY %I ON public.%I FOR SELECT TO authenticated '\n"
                    "                   'USING (user_id = auth.uid())', t || '_own', t);\n"
                    "  END LOOP;\nEND $$;\n")
        rows = {r["table"]: r for r in sql_state.table_rows(d)}
        for t in ("agent_runs", "agent_memory"):
            r = rows["public." + t]
            self.assertTrue(r["rls"])
            self.assertNotIn("anon", r["roles"])
            self.assertEqual(r["policies"], [f"{t}_own:SELECT"])
        f, meta = sql_state.findings(d)
        self.assertEqual(rules(f, "R1"), [])
        self.assertEqual(meta["do_expanded"], 1)

    def test_alter_add_column_makes_tenant(self):
        f = sql_rules("CREATE TABLE public.x (id uuid);\nALTER TABLE public.x ADD COLUMN IF NOT EXISTS org_id uuid;\n", "R1")
        self.assertEqual(f[0]["severity"], "critical")

    def test_create_table_trailing_clause(self):
        f, meta = sql_state.findings(sql_dir("CREATE TABLE public.e (id uuid, org_id uuid) PARTITION BY RANGE (id);\n"))
        self.assertEqual(meta["unparsed"], 0)
        self.assertEqual(len(rules(f, "R1")), 1)


class SqlRuleTests(unittest.TestCase):
    def test_rule_r1(self):
        self.assertTrue(sql_rules("CREATE TABLE public.a (id uuid);\n", "R1"))
        self.assertFalse(sql_rules("CREATE TABLE public.a (id uuid);\nREVOKE ALL ON public.a FROM anon, authenticated;\n", "R1"))
        self.assertFalse(sql_rules("CREATE TABLE private.a (id uuid, org_id uuid);\n", "R1"))

    def test_rule_r2(self):
        self.assertTrue(sql_rules(T + "CREATE POLICY p ON public.t FOR SELECT TO anon USING (true);\n", "R2"))
        self.assertFalse(sql_rules(T + "CREATE POLICY p ON public.t AS RESTRICTIVE FOR SELECT TO anon USING (true);\n", "R2"))
        self.assertFalse(sql_rules(T + "CREATE POLICY p ON public.t FOR SELECT TO service_role USING (true);\n", "R2"))

    def test_rule_r3_removed_r4_removed(self):
        d = T + "GRANT SELECT ON public.t TO anon;\n"
        self.assertFalse(sql_rules(d, "R3") or sql_rules(d, "R4"))

    def test_rule_r5(self):
        base = T + "CREATE FUNCTION public.f() RETURNS SETOF public.t LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ {} $$;\n"
        self.assertTrue(sql_rules(base.format("SELECT * FROM public.t"), "R5"))
        self.assertFalse(sql_rules(base.format("SELECT * FROM public.t WHERE user_id = auth.uid()"), "R5"))
        self.assertFalse(sql_rules(base.format("SELECT * FROM public.t") +
                                   "REVOKE EXECUTE ON FUNCTION public.f() FROM public, anon, authenticated;\n", "R5"))
        trig = T + "CREATE FUNCTION public.g() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN INSERT INTO public.t VALUES (NEW.id, NEW.id); RETURN NEW; END $$;\n"
        self.assertFalse(sql_rules(trig, "R5"))

    def test_rule_r6(self):
        self.assertTrue(sql_rules(T + "CREATE POLICY p ON public.t FOR SELECT TO authenticated USING (auth.role() = 'authenticated');\n", "R6"))
        self.assertFalse(sql_rules(T + "CREATE POLICY p ON public.t FOR SELECT TO authenticated USING (user_id = auth.uid());\n", "R6"))

    def test_rule_r7(self):
        self.assertTrue(sql_rules(T + "CREATE POLICY p ON public.t USING ((auth.jwt() -> 'user_metadata' ->> 'org') = 'x');\n", "R7"))
        self.assertFalse(sql_rules(T + "CREATE POLICY p ON public.t USING ((auth.jwt() -> 'app_metadata' ->> 'org') = 'x');\n", "R7"))

    def test_rule_r8(self):
        f = "CREATE FUNCTION public.h() RETURNS int LANGUAGE sql SECURITY DEFINER {} AS $$ SELECT 1 $$;\n"
        self.assertTrue(sql_rules(f.format(""), "R8"))
        self.assertFalse(sql_rules(f.format("SET search_path = ''"), "R8"))
        self.assertFalse(sql_rules(f.format("") + "ALTER FUNCTION public.h() SET search_path = '';\n", "R8"))

    def test_rule_r9(self):
        self.assertTrue(sql_rules(T + "CREATE VIEW public.v AS SELECT * FROM public.t;\n", "R9"))
        self.assertFalse(sql_rules(T + "CREATE VIEW public.v WITH (security_invoker = true) AS SELECT * FROM public.t;\n", "R9"))
        self.assertFalse(sql_rules(T + "CREATE VIEW public.v AS SELECT * FROM public.t;\nALTER VIEW public.v SET (security_invoker = on);\n", "R9"))

    def test_default_privileges_revoke(self):
        d = ("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;\n"
             "CREATE TABLE public.z (id uuid, org_id uuid);\n")
        self.assertFalse(sql_rules(d, "R1"))


class LiveTests(unittest.TestCase):
    def test_live_probe(self):
        import http.server
        import threading
        import live
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("apikey"))
                body = {"/rest/v1/t_open": b'[{"id":1}]', "/rest/v1/t_safe": b"[]"}.get(self.path.split("?")[0])
                self.send_response(200 if body else 401)
                self.end_headers()
                self.wfile.write(body or b'{"code":"42501"}')

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            st, f, stats = live.probe(f"http://127.0.0.1:{srv.server_port}", "anon-key", ["t_open", "t_safe", "t_denied"],
                                      {"t_open", "t_safe", "t_denied"}, "localhost", rate=100)
        finally:
            srv.shutdown()
        self.assertEqual(st, "ran")
        self.assertEqual([x["table"] for x in f], ["public.t_open"])
        self.assertEqual(stats, {"tables": 3, "readable": 2, "rows": 1})
        self.assertEqual(set(seen), {"anon-key"})
        self.assertNotIn("anon-key", json.dumps(f))

    def test_live_catalog_parse(self):
        import live
        d = tempfile.mkdtemp()
        log = os.path.join(d, "env.log")
        fake = pathlib.Path(d, "psql")
        fake.write_text(f"""#!/usr/bin/env python3
import os, sys
open({log!r}, "a").write(os.environ.get("PGOPTIONS", "") + "\\n")
q = sys.argv[sys.argv.index("-c") + 1]
if "has_function_privilege" in q:
    print('[{{"t":"f_callable","anon":true,"authed":true}},{{"t":"f_revoked","anon":false,"authed":false}}]')
elif "relrowsecurity" in q:
    print('[{{"t":"leaky","tenant":true}}]')
elif "pg_policies" in q:
    print('[{{"t":"doc_gaps","name":"anyone","cmd":"INSERT","roles":"{{anon}}"}}]')
else:
    print('[]')
""")
        fake.chmod(0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + old
        try:
            st, f, callable_ = live.catalog("postgresql://ro@localhost/db", "localhost", {"f_callable", "f_revoked"})
        finally:
            os.environ["PATH"] = old
        self.assertEqual(st, "ran")
        self.assertEqual(sorted(x["rule"] for x in f), ["L1", "L2"])
        self.assertEqual(next(x for x in f if x["rule"] == "L1")["severity"], "critical")
        self.assertEqual(callable_, {"f_callable"})
        self.assertTrue(all("default_transaction_read_only=on" in ln for ln in open(log).read().splitlines()))


UV_LOCK = """version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }]
[[package]]
name = "requests"
version = "2.19.0"
dependencies = [{ name = "urllib3" }]
[[package]]
name = "urllib3"
version = "1.0"
[[package]]
name = "pytest"
version = "8.0"
"""


class OsvTests(unittest.TestCase):
    def osv(self, enrich=False):
        d = tempfile.mkdtemp()
        shutil.copy(DATA / "poetry.lock", d)
        data = json.loads((DATA / "osv_requests.json").read_text())
        which, run = tools.shutil.which, tools._run
        tools.shutil.which, tools._run = (lambda t: "/x/" + t), (lambda *a, **k: ("ok", 1, data))
        try:
            return tools.osv_findings(d, {"skip_tests": True, "osv_enrich": enrich})[1], data
        finally:
            tools.shutil.which, tools._run = which, run

    def test_osv_groups(self):
        found, data = self.osv()
        by = {f["evidence"].split("@")[0]: f for f in found}
        self.assertEqual(sorted(by), ["pyyaml", "requests"])                 # one finding per package@version
        r = by["requests"]
        self.assertEqual((r["class"], r["severity"], r["scope"]), ("CVE-2018-18074", "high", "prod"))
        self.assertEqual(len(r["advisories"]), 5)
        self.assertIn("to 2.33.0 (fixes all 5)", r["fix_hint"])
        self.assertEqual((by["pyyaml"]["severity"], by["pyyaml"]["scope"]), ("critical", "dev"))
        self.assertIn("to 5.4 ", by["pyyaml"]["fix_hint"])
        self.assertEqual(r["fp"], "requests|poetry.lock")

    def test_lockscope_poetry(self):
        import lockscope
        self.assertEqual(lockscope.scope(DATA / "poetry.lock", "requests"), "prod")
        self.assertEqual(lockscope.scope(DATA / "poetry.lock", "PyYAML"), "dev")
        self.assertEqual(lockscope.scope(DATA / "poetry.lock", "nope"), "unknown")

    def test_lockscope_uv(self):
        import lockscope
        p = pathlib.Path(tempfile.mkdtemp(), "uv.lock")
        p.write_text(UV_LOCK)
        self.assertEqual([lockscope.scope(p, n) for n in ("requests", "urllib3", "pytest")], ["prod", "prod", "dev"])

    def test_enrich_cache(self):
        import datetime
        import enrich
        cache = pathlib.Path(tempfile.mkdtemp())
        (cache / "kev.json").write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2018-18074"}]}))
        (cache / f"epss-{datetime.date.today().isoformat()}.json").write_text(json.dumps({"CVE-2018-18074": 0.07, "CVE-2020-1747": 0.9}))
        found = [{"class": "CVE-2018-18074", "severity": "high"}, {"class": "CVE-2020-1747", "severity": "critical"}]
        get, enrich._get = enrich._get, (lambda url: (_ for _ in ()).throw(OSError("offline")))
        try:
            enrich.apply(found, cache)
        finally:
            enrich._get = get
        self.assertEqual(found[0]["severity"], "critical")       # KEV raises it
        self.assertTrue(found[0]["kev"])
        self.assertEqual(found[1]["epss"], 0.9)
        self.assertEqual(enrich.LAST_NOTE, "")


class SideEffectTests(Fixture):
    def test_read_commands_write_nothing_and_output_is_ignored(self):
        import subprocess
        cs.discover(self.repo)
        self.assertFalse(pathlib.Path(self.repo, ".cybersec").exists())
        run_cli("tools", self.repo, "--no-history")
        st = subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True, text=True).stdout
        self.assertEqual(st, "")


class SecretFilterTests(unittest.TestCase):
    def test_secret_noise(self):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "a.md").write_text('curl -s -u "$SK:" https://api.example.com\nIdempotency-Key: refund-x-A-12345678\n'
                                'tokens: `bg-surface-900`\nk = "sk-live-1234567890abcdef1234"\n')
        f = lambda line, rule="generic-api-key", match="x REDACTED": {"RuleID": rule, "Match": match, "File": "a.md",
                                                                      "StartLine": line, "StartColumn": 1, "EndColumn": 60}
        self.assertEqual(tools.secret_noise(d, f(1, "curl-auth-user")), "placeholder")
        self.assertEqual(tools.secret_noise(d, f(2, match="Idempotency-Key: REDACTED")), "not-a-secret-name")
        self.assertEqual(tools.secret_noise(d, f(3)), "identifier")
        self.assertIsNone(tools.secret_noise(d, f(4)))          # a real key shape is kept


class SecretNoiseTests(Fixture):
    def test_secret_in_test_file_skipped_and_history_duplicate_dropped(self):
        import config
        self.assertEqual(config.secret_skipped("src/lib/a.test.ts", {"skip_tests": True}), "skip-name")
        self.assertIsNone(config.secret_skipped("src/lib/a.test.ts", {"skip_tests": False}))
        if not shutil.which("gitleaks"):
            self.skipTest("gitleaks not installed")
        run_cli("tools", self.repo)                       # app/secrets.py key is in current files and history
        lf = json.loads(pathlib.Path(self.repo, ".cybersec/last_findings.json").read_text())
        srcs = [f["source"] for f in lf if f["file"] == "app/secrets.py" and f["class"] == "CWE-798"]
        self.assertEqual(srcs, ["gitleaks"])


class BatchTests(Fixture):
    def add(self, rel, text):
        p = pathlib.Path(self.repo, rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        import subprocess
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)

    def test_batch_bytes(self):
        for i in range(6):
            self.add(f"lib/m{i}.py", "x = 1\n" * 5000)            # 30,000 bytes each
        b = json.loads(run_cli("batch-next", self.repo, "--max-bytes", "70000")[1])
        self.assertLessEqual(b["bytes"], 70000)
        self.assertGreaterEqual(b["batches_estimate"], 3)

    def test_batch_groups_imports(self):
        self.add("src/routes/r.ts", "import { q } from '../lib/q';\nexport const r = () => q();\n")
        self.add("src/lib/q.ts", "export const q = () => 1;\n")
        b = json.loads(run_cli("batch-next", self.repo, "--max-files", "2")[1])
        self.assertEqual(b["read_set"], ["app/api.py", "app/search.py"])        # python: from app.search import
        rs = json.loads(run_cli("batch-next", self.repo)[1])["read_set"]
        self.assertEqual(rs[rs.index("src/routes/r.ts") + 1], "src/lib/q.ts")   # ts: from '../lib/q'

    def test_priority(self):
        import batching
        self.assertEqual(batching.rank("src/organize.ts", 0), 2)
        self.assertEqual(batching.rank("src/lib/x.ts", batching.score("const c = supabaseAdmin.from('t')")), 0)
        self.assertEqual(batching.rank("src/api/x.ts", 0), 0)

    def test_batch_context(self):
        self.write_tool_finding()
        run_cli("batch-next", self.repo)
        ctx = json.loads(pathlib.Path(self.repo, ".cybersec/batch.json").read_text())["context"]
        self.assertEqual([f["id"] for f in ctx["tool_findings"]], ["F-tool"])

    def write_tool_finding(self):
        p = pathlib.Path(self.repo, ".cybersec", "last_findings.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps([{"id": "F-tool", "source": "semgrep", "class": "CWE-89", "file": "app/search.py",
                                  "lines": "4-4", "evidence": "x", "severity": "high"}]))


HIGH = {"id": "F-aaaaaaaaaaaa", "source": "gitleaks", "class": "CWE-798", "severity": "high", "status": "new",
        "verdict": "new", "file": "app/k.py", "lines": "1-1", "evidence": "aws-access-token app/k.py:1", "fix_hint": "Rotate."}


class OpsTests(unittest.TestCase):
    def test_notify_posts_once(self):
        import http.server
        import threading
        import notify
        posts = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                posts.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        root = pathlib.Path(tempfile.mkdtemp(), "repo")
        (root / ".cybersec").mkdir(parents=True)
        hook = root.parent / "slack_webhook"
        hook.write_text(f"http://127.0.0.1:{srv.server_port}/hook")
        hook.chmod(0o600)
        try:
            first = notify.run(root, [HIGH], hook)
            second = notify.run(root, [HIGH], hook)
        finally:
            srv.shutdown()
        self.assertEqual((first["notified"], second["notified"]), (1, 0))
        self.assertEqual(len(posts), 1)
        self.assertIn("[high] CWE-798 app/k.py:1-1 (gitleaks)", posts[0]["text"])

    def test_notify_mode_check(self):
        import notify
        hook = pathlib.Path(tempfile.mkdtemp(), "slack_webhook")
        hook.write_text("http://127.0.0.1:9/hook")
        hook.chmod(0o644)
        self.assertEqual(notify.webhook_url(hook), (None, "mode"))
        root = pathlib.Path(tempfile.mkdtemp())
        (root / ".cybersec").mkdir()
        self.assertEqual(notify.run(root, [HIGH], hook)["skipped"], "mode")

    def test_sarif(self):
        import sarif
        doc = sarif.build([HIGH, dict(HIGH, id="F-b", verdict="false_positive"), dict(HIGH, id="F-c", status="fixed")])
        self.assertEqual(doc["version"], "2.1.0")
        res = doc["runs"][0]["results"]
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["level"], "error")
        self.assertEqual(res[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        self.assertEqual(res[0]["partialFingerprints"]["cybersecId/v1"], HIGH["id"])
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"][0]["id"], "gitleaks:CWE-798")


class OpsFixtureTests(Fixture):
    def test_fail_on(self):
        import subprocess
        self.assertEqual(run_cli("tools", self.repo, "--no-history", "--fail-on", "high")[0], 6)   # seeded secret, new
        self.assertEqual(run_cli("tools", self.repo, "--no-history", "--fail-on", "high")[0], 0)   # now open, not new
        self.assertEqual(run_cli("tools", self.repo, "--no-history")[0], 0)

    def test_stats(self):
        p = pathlib.Path(self.repo, ".cybersec", "last_findings.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps([dict(HIGH, id="a"), dict(HIGH, id="b"), dict(HIGH, id="c"), dict(HIGH, id="d", source="agent")]))
        for fid, v in (("a", "real"), ("b", "false_positive"), ("d", "accepted_risk")):
            run_cli("verdict", self.repo, fid, v, "test")
        rows = json.loads(run_cli("stats", self.repo)[1])
        self.assertEqual(rows["gitleaks"], {"findings": 3, "real": 1, "false_positive": 1, "accepted_risk": 0,
                                            "unreviewed": 1, "precision": "0.50"})
        self.assertEqual(rows["agent"]["precision"], "n/a")


class ConfigTests(unittest.TestCase):
    def test_config_verify_jwt(self):
        samples = str(pathlib.Path(__file__).resolve().parent.parent / "rules" / "samples")
        st, f = tools.config_findings(samples, {"skip_tests": False})
        self.assertEqual(st, "ran")
        self.assertEqual([(x["file"], x["lines"], x["evidence"]) for x in f],
                         [("supabase/config.toml", "1", "verify_jwt = false for function open-hook")])


class ScannerParseTests(unittest.TestCase):
    def test_zizmor_parse(self):
        f = tools.parse_zizmor("/repo", json.loads((DATA / "zizmor.json").read_text()))
        self.assertEqual([(x["class"], x["severity"], x["file"], x["lines"]) for x in f],
                         [("template-injection", "high", ".github/workflows/bad.yml", "10")])
        self.assertIn("github.event.issue.title", f[0]["evidence"])

    def test_zizmor_groups_per_file(self):
        item = json.loads((DATA / "zizmor.json").read_text())[0]
        two = [item, json.loads(json.dumps(item))]
        two[1]["locations"][0]["concrete"]["location"]["start_point"]["row"] = 20
        f = tools.parse_zizmor("/repo", two)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["lines"], "10, 21")
        self.assertIn("(+1 more in this file)", f[0]["evidence"])

    def test_trivy_parse(self):
        f = tools.parse_trivy("/repo", json.loads((DATA / "trivy.json").read_text()))
        self.assertEqual(sorted((x["class"], x["severity"], x["file"]) for x in f),
                         [("DS-0002", "high", "Dockerfile"), ("DS-0026", "low", "Dockerfile")])

    def test_missing_tool_status(self):
        which, tools.shutil.which = tools.shutil.which, (lambda t: None)
        d = tempfile.mkdtemp()
        pathlib.Path(d, ".github", "workflows").mkdir(parents=True)
        try:
            self.assertEqual(tools.zizmor_findings(d, {})[0], "missing")
            self.assertEqual(tools.trivy_findings(d, {})[0], "missing")
        finally:
            tools.shutil.which = which


if __name__ == "__main__":
    unittest.main()
