#!/usr/bin/env python3
"""Scorecard for the scanner. Gates must pass (exit 0). Stdlib only.
Gates: unit tests, seeded recall (all planted bugs found), zero false alarms on planted safe code,
zero R2 hits on service-role-only policies."""
import json, os, pathlib, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import cyber_state as cs  # noqa: E402
import sql_state  # noqa: E402

PLANTED = {"gitleaks": "app/secrets.py", "semgrep-sql": "app/search.py", "semgrep-path": "app/files.py", "sql-open": "0001.sql"}
SAFE_MUST_NOT = ["tests/fake_key.py", "app/safe.py", "migrations/0002_srv.sql"]


def seed(d):
    for path, body in {
        "app/search.py": 'def f(db, q):\n    return db.execute("SELECT * FROM t WHERE n = \'" + q + "\'")\n',
        "app/safe.py": 'def g(db, q):\n    return db.execute("SELECT * FROM t WHERE n = ?", (q,))\n',
        "app/secrets.py": 'API_KEY = "sk-live-1234567890abcdef1234"\n',
        "app/files.py": 'import os\ndef r(n):\n    return open(os.path.join("/srv", n)).read()\n',
        "tests/fake_key.py": 'API_KEY = "sk-live-9999888877776666aaaa"\n',
        "migrations/0001.sql": ("CREATE TABLE public.inv (id uuid, tenant_id uuid);\n"
                                "ALTER TABLE public.inv ENABLE ROW LEVEL SECURITY;\n"
                                "CREATE POLICY p ON public.inv FOR ALL TO authenticated USING (true);\n"),
        "migrations/0002_srv.sql": ("CREATE TABLE public.ev (id uuid, tenant_id uuid);\n"
                                    "ALTER TABLE public.ev ENABLE ROW LEVEL SECURITY;\n"
                                    "CREATE POLICY s ON public.ev FOR ALL TO service_role USING (true) WITH CHECK (true);\n"),
    }.items():
        p = pathlib.Path(d, path); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)


def scan(d):
    cfg = {"skip_tests": True}
    found = []
    import tools
    found += tools.semgrep_findings(d, cfg)[1]
    found += tools.gitleaks_findings(d, cfg, history=False)[1]
    found += sql_state.findings(str(pathlib.Path(d, "migrations")))[0]
    return found


def main():
    suite = unittest.TestLoader().discover(str(ROOT / "tests"), pattern="test_cyber_state.py")
    tests_ok = unittest.TextTestRunner(stream=open(os.devnull, "w")).run(suite).wasSuccessful()
    with tempfile.TemporaryDirectory() as d:
        seed(d)
        found = scan(d)
    files = {f["file"] for f in found}
    recall = {k: any(f["file"].endswith(v) for f in found) for k, v in PLANTED.items()}
    false_alarm = [f for f in SAFE_MUST_NOT if any(x["file"].endswith(f) for x in found)]
    srv_r2 = [f for f in found if f["evidence"].startswith("R2") and "ev" in f["evidence"].split(" ")[1:2]]
    gates = {"unit_tests": tests_ok, "recall_all_planted": all(recall.values()),
             "no_false_alarm_safe_code": not false_alarm, "no_r2_on_service_role": not srv_r2}
    print(json.dumps({"gates": gates, "recall": recall, "false_alarms": false_alarm,
                      "findings_on_seed": len(found)}, indent=2))
    return 0 if all(gates.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
