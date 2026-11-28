#!/usr/bin/env python3
"""Scorecard for the scanner. Gates must pass (exit 0). Stdlib only.
  bench.py        tool gates (CI): unit tests, regressions, planted tool bugs, safe code, SQL rules
  bench.py --ai   AI reviewer on tests/ai_bench (real Claude runs; cost): recall and false alarms"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import sql_state  # noqa: E402
import tools  # noqa: E402

PLANTED = {"gitleaks": "app/secrets.py", "semgrep-sql": "app/search.py", "semgrep-path": "app/files.py", "sql-open": "0001.sql"}
SAFE_MUST_NOT = ["tests/fake_key.py", "app/safe.py", "migrations/0002_srv.sql"]
ACCESS = {"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"}   # one access bug gets any of these classes
AI_PLANTED = {"routes/t1_invoices.ts": ACCESS | {"CWE-639", "CWE-863", "T1"}, "routes/t2_invoice.ts": ACCESS | {"CWE-639", "CWE-862", "T2"},
              "routes/t5_profile.ts": ACCESS | {"CWE-639", "CWE-269", "T5"}, "lib/t6_cache.ts": ACCESS | {"CWE-524", "CWE-639", "T6"},
              "routes/t7_export.ts": ACCESS | {"CWE-862", "CWE-639", "T7"}, "lib/t8_context.ts": {"CWE-362", "CWE-488", "T8"},
              "routes/t9_invite.ts": ACCESS | {"CWE-863", "T9"}, "routes/t10_webhook.ts": {"CWE-345", "CWE-306", "T10"},
              "routes/t11_lookup.ts": {"CWE-204", "T11"}, "lib/t12_audit.ts": {"CWE-532", "CWE-359", "T12"}}
AI_SAFE = ["routes/s1_invoices.ts", "routes/s2_invoice.ts", "routes/s5_profile.ts", "lib/s6_cache.ts",
           "routes/s7_export.ts", "routes/s10_webhook.ts"]


def seed(d):
    for path, body in {
        "app/search.py": 'def f(db, q):\n    return db.execute("SELECT * FROM t WHERE n = \'" + q + "\'")\n',
        "app/safe.py": 'def g(db, q):\n    return db.execute("SELECT * FROM t WHERE n = ?", (q,))\n',
        "app/secrets.py": 'API_KEY = "sk-live-1234567890abcdef1234"\n',
        "app/files.py": 'import os\ndef r(n):\n    return open(os.path.join("/srv", n)).read()\n',
        "tests/fake_key.py": 'API_KEY = "sk-live-9999888877776666aaaa"\n',
        "docs/setup.md": 'export STRIPE_KEY="sk_' 'live_51HxQz2eZvKYlo2C8a9b7c6d5e4f3g2h1"\n',
        "migrations/0001.sql": ("CREATE TABLE public.inv (id uuid, tenant_id uuid);\n"
                                "ALTER TABLE public.inv ENABLE ROW LEVEL SECURITY;\n"
                                "CREATE POLICY p ON public.inv FOR ALL TO authenticated USING (true);\n"),
        "migrations/0002_srv.sql": ("CREATE TABLE public.ev (id uuid, tenant_id uuid);\n"
                                    "ALTER TABLE public.ev ENABLE ROW LEVEL SECURITY;\n"
                                    "CREATE POLICY s ON public.ev FOR ALL TO service_role USING (true) WITH CHECK (true);\n"),
        "migrations/0003_loop.sql": ("CREATE TABLE public.lp (id uuid, user_id uuid);\nDO $$ DECLARE t text; BEGIN\n"
                                     "FOREACH t IN ARRAY ARRAY['lp'] LOOP\n"
                                     "EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);\n"
                                     "END LOOP; END $$;\n"),
    }.items():
        p = pathlib.Path(d, path); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)


def suite_ok(pattern):
    s = unittest.TestLoader().discover(str(ROOT / "tests"), pattern=pattern)
    return unittest.TextTestRunner(stream=open(os.devnull, "w")).run(s).wasSuccessful()


def tool_gates():
    cfg = {"skip_tests": True}
    with tempfile.TemporaryDirectory() as d:
        seed(d)
        found = tools.semgrep_findings(d, cfg)[1] + tools.gitleaks_findings(d, cfg, history=False)[1]
        sql = sql_state.findings(str(pathlib.Path(d, "migrations")))[0]
    found += sql
    data = json.loads((ROOT / "tests/data/osv_requests.json").read_text())
    which, run = tools.shutil.which, tools._run
    tools.shutil.which, tools._run = (lambda t: "/x/" + t), (lambda *a, **k: ("ok", 1, data))
    try:
        osv = tools.osv_findings(str(ROOT / "tests/data"), {"skip_tests": False, "osv_enrich": False})[1]
    finally:
        tools.shutil.which, tools._run = which, run
    recall = {k: any(f["file"].endswith(v) for f in found) for k, v in PLANTED.items()}
    false_alarm = [f for f in SAFE_MUST_NOT if any(x["file"].endswith(f) for x in found)]
    gates = {"unit_tests": suite_ok("test_cyber_state.py"), "regressions": suite_ok("test_regressions.py"),
             "recall_all_planted": all(recall.values()), "no_false_alarm_safe_code": not false_alarm,
             "no_r2_on_service_role": not [f for f in sql if f.get("rule") == "R2" and f.get("table") == "public.ev"],
             "secrets_in_docs": any(f["file"] == "docs/setup.md" for f in found),
             "osv_lockfile_not_skipped": len(osv) > 0,
             "sql_no_r3": not [f for f in sql if f.get("rule") == "R3"],
             "sql_do_loop": not [f for f in sql if f.get("rule") == "R1" and f.get("table") == "public.lp"]}
    return {"gates": gates, "recall": recall, "false_alarms": false_alarm, "findings_on_seed": len(found)}


def ai_bench():
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp, "ai_bench")
        shutil.copytree(ROOT / "tests" / "ai_bench", d)
        env = dict(os.environ, GIT_AUTHOR_NAME="b", GIT_AUTHOR_EMAIL="b@e.invalid", GIT_COMMITTER_NAME="b",
                   GIT_COMMITTER_EMAIL="b@e.invalid")
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-qm", "bench"]):
            subprocess.run(cmd, cwd=d, check=True, env=env)
        rc = subprocess.run(["bash", str(ROOT / "scripts" / "run-full.sh"), str(d)], env=env).returncode
        found = [f for f in json.loads((d / ".cybersec" / "last_findings.json").read_text()) if f.get("source") == "agent"]
        if os.environ.get("CYBERSEC_BENCH_OUT"):
            shutil.copy(d / ".cybersec" / "last_findings.json", os.environ["CYBERSEC_BENCH_OUT"])
    hit = {k: any(f["file"] == k and f["class"] in v for f in found) for k, v in AI_PLANTED.items()}
    alarms = [f"{f['file']} {f['class']}" for f in found if f["file"] in AI_SAFE]
    gates = {"run_full_ok": rc == 0, "recall_9_of_10": sum(hit.values()) >= 9, "false_alarms_max_1": len(alarms) <= 1}
    return {"gates": gates, "recall": f"{sum(hit.values())}/{len(hit)}", "missed": [k for k, v in hit.items() if not v],
            "false_alarms": alarms, "agent_findings": len(found)}


def main(argv):
    res = ai_bench() if "--ai" in argv else tool_gates()
    print(json.dumps(res, indent=2))
    return 0 if all(res["gates"].values()) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
