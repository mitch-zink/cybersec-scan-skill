"""Live checks (opt-in, read-only). Stdlib only.
Anon probe: GET /rest/v1/<table>?limit=1 with the public anon key; keeps status and row count only.
Catalog: psql with default_transaction_read_only=on; rules L1-L4 plus EXECUTE checks for replay R5 hits.
Key and URL values are never printed or stored; only the URL host is kept."""
import json
import os
import pathlib
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import supabase_checks

TENANT = "array['tenant_id','org_id','workspace_id','account_id','user_id']"
HAS_TENANT = f"exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = any({TENANT}) and not a.attisdropped)"
PUB = "from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public'"
CATALOG = {
    "L1": f"select c.relname as t, {HAS_TENANT} as tenant {PUB} and c.relkind in ('r','p') and not c.relrowsecurity",
    "L2": ("select p.tablename as t, p.policyname as name, p.cmd, p.roles::text as roles from pg_policies p "
           "join pg_class c on c.relname = p.tablename join pg_namespace n on n.oid = c.relnamespace and n.nspname = p.schemaname "
           f"where p.schemaname = 'public' and p.permissive = 'PERMISSIVE' and p.roles <> '{{service_role}}' "
           rf"and (p.qual ~* '^\s*true\s*$' or p.with_check ~* '^\s*true\s*$') and {HAS_TENANT}"),
    "L3": (f"select c.relname as t {PUB} and c.relkind = 'v' "
           "and not coalesce(c.reloptions::text ~ 'security_invoker=(true|on)', false) "
           "and (has_table_privilege('anon', c.oid, 'SELECT') or has_table_privilege('authenticated', c.oid, 'SELECT'))"),
    "L4": ("select p.proname as t from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
           "where n.nspname = 'public' and p.prosecdef and not exists "
           "(select 1 from unnest(coalesce(p.proconfig, '{}'::text[])) x where x like 'search_path=%')"),
}
FUNCS = ("select p.proname as t, bool_or(has_function_privilege('anon', p.oid, 'EXECUTE')) as anon, "
         "bool_or(has_function_privilege('authenticated', p.oid, 'EXECUTE')) as authed "
         "from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' "
         "and p.proname = any(array[{}]::text[]) group by p.proname")
RULES = {"L1": ("CWE-284", "RLS off on a live public table", "Enable RLS and add policies."),
         "L2": ("CWE-863", "permissive policy with true on a tenant table", "Replace true with a tenant predicate."),
         "L3": ("CWE-284", "view runs as owner and API roles can read it", "SET (security_invoker = true)."),
         "L4": ("CWE-426", "SECURITY DEFINER function with no fixed search_path", "SET search_path = ''."),
         "L5": ("CWE-284", "anon key read a row from a tenant table", "Fix RLS on this table now.")}


def env_value(root, name):
    """Environment first, then ROOT/.env key=value lines."""
    if os.environ.get(name):
        return os.environ[name]
    env = pathlib.Path(root, ".env")
    for line in env.read_text().splitlines() if env.exists() else []:
        k, _, v = line.partition("=")
        if k.strip() == name:
            return v.strip().strip('"').strip("'")
    return ""


def finding(rule, table, sev, detail, host):
    cls, what, fix = RULES[rule]
    return {"source": "live", "rule": rule, "table": f"public.{table}", "owasp": "A02" if rule == "L4" else "A01",
            "class": cls, "severity": sev, "confidence": "confirmed", "scope": "live", "file": f"db:{host}",
            "lines": "-", "evidence": f"{rule} public.{table}: {what}{'; ' + detail if detail else ''}",
            "fp": f"{rule}|{table}|{detail}", "fix_hint": fix}


def probe(url, key, tables, tenant, host, rate=4.0):
    """Returns (status, findings, stats)."""
    out, stats = [], {"tables": 0, "readable": 0, "rows": 0}
    for t in tables:
        req = urllib.request.Request(f"{url.rstrip('/')}/rest/v1/{urllib.parse.quote(t)}?select=*&limit=1",
                                     headers={"apikey": key, "Authorization": f"Bearer {key}",
                                              "Accept": "application/json", "User-Agent": "cybersec-scan"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                status, n = r.status, len(json.loads(r.read() or b"[]"))
        except urllib.error.HTTPError as e:
            status, n = e.code, 0
            e.close()
        except (urllib.error.URLError, OSError, ValueError):
            return "error", out, stats
        stats["tables"] += 1
        stats["readable"] += status == 200
        stats["rows"] += status == 200 and n > 0
        if status == 200 and n > 0 and t in tenant:
            out.append(finding("L5", t, "critical", "", host))
        time.sleep(1 / rate)
    return "ran", out, stats


def psql_json(dsn, sql, timeout=60):
    env = dict(os.environ, PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=30000", PGCONNECT_TIMEOUT="10")
    q = f"select coalesce(json_agg(x), '[]') from ({sql}) x"
    r = subprocess.run(["psql", dsn, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", q],
                       capture_output=True, text=True, timeout=timeout, env=env)
    if r.returncode != 0:
        raise RuntimeError("psql failed")
    return json.loads(r.stdout.strip() or "[]")


def catalog(dsn, host, r5_funcs):
    """Returns (status, findings, executable function names)."""
    if not shutil.which("psql"):
        return "missing", [], set()
    try:
        rows = {k: psql_json(dsn, v) for k, v in CATALOG.items()}
        names = ",".join("'" + f.replace("'", "''") + "'" for f in sorted(r5_funcs)) or "''"
        fx = psql_json(dsn, FUNCS.format(names))
    except (RuntimeError, subprocess.TimeoutExpired, ValueError, OSError):
        return "error", [], set()
    out = [finding("L1", x["t"], "critical" if x["tenant"] else "high", "", host) for x in rows["L1"]]
    out += [finding("L2", x["t"], "high", f"policy {x['name']} {x['cmd']} {x['roles']}", host) for x in rows["L2"]]
    out += [finding("L3", x["t"], "high", "", host) for x in rows["L3"]]
    out += [finding("L4", x["t"], "medium", "", host) for x in rows["L4"]]
    return "ran", out, {x["t"] for x in fx if x["anon"] or x["authed"]}


def run(root, cfg, sql_findings, sql_rows):
    """Returns (status by part, live findings, ids of replay findings live disproves, notes)."""
    lc = cfg["live"]
    if not lc.get("enabled"):
        return {"live": "off"}, [], set(), []
    url, key, dsn = (env_value(root, lc[k]) for k in ("url_env", "anon_key_env", "db_url_env"))
    host = urllib.parse.urlparse(url).hostname or "db"
    tables = [r["table"].split(".", 1)[1] for r in sql_rows if r["table"].startswith("public.")]
    tenant = {r["table"].split(".", 1)[1] for r in sql_rows if r["tenant_cols"]}
    st, notes, out, drop = {}, [], [], set()
    if url and key:
        st["live-probe"], f, s = probe(url, key, tables, tenant, host)
        out += f
        notes.append(f"Live anon probe: {s['tables']} tables, {s['readable']} readable, tenant tables that returned rows: {len(f)}.")
    else:
        st["live-probe"] = "missing"
    if dsn:
        r5 = {f.get("function", "").split(".")[-1]: f["id"] for f in sql_findings if f.get("rule") == "R5"}
        st["live-catalog"], f, callable_ = catalog(dsn, host, set(r5))
        if st["live-catalog"] == "ran":
            out += f
            drop = {x["id"] for x in sql_findings if x.get("rule") in ("R1", "R2", "R8", "R9")}
            drop |= {fid for name, fid in r5.items() if name not in callable_}
            notes.append(f"Live catalog (read-only): {len(f)} findings. Replay results disproved by live: {len(drop)} removed.")
    else:
        st["live-catalog"] = "off"
    sb_st, sb_f, sb_notes = supabase_checks.run(root, cfg, url, dsn, host)
    st.update(sb_st)
    if sb_st.get("advisors") == "ran":              # advisors cover RLS off, definer views and search_path
        out = [f for f in out if f["rule"] not in ("L1", "L3", "L4")]
    return st, out + sb_f, drop, notes + sb_notes
