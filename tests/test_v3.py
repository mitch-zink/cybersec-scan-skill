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


if __name__ == "__main__":
    unittest.main()
