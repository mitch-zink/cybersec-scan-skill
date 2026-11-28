"""Supabase-native checks (opt-in, read-only). Stdlib only.
  Advisors: Management API v1 security + performance lints (needs a personal access token),
            else splinter.sql (the linter behind the advisors) through psql (needs a read-only DB URL).
  Health:   inspect-style database health through psql: cache hit, seq scans, slow queries,
            long-running queries, dead tuples, connection use.
Tokens and URLs are never printed or stored; findings name only the project host."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import urllib.error
import urllib.request

API = "https://api.supabase.com/v1/projects/{ref}/advisors/{kind}"
SPLINTER_URL = "https://raw.githubusercontent.com/supabase/splinter/2026.11.0/splinter.sql"
SPLINTER_SHA256 = "e652eb2be316eaf44ad523e8b0e6e76bb4952942be86692811064d0b72402b46"
CACHE = pathlib.Path.home() / ".cache" / "cybersec-scan"
LEVEL = {"ERROR": "high", "WARN": "medium", "INFO": "low"}
RO_ENV = {"PGOPTIONS": "-c default_transaction_read_only=on -c statement_timeout=60000", "PGCONNECT_TIMEOUT": "10"}

HEALTH = {
    "cache_hit": ("select round(sum(heap_blks_hit)::numeric / nullif(sum(heap_blks_hit) + sum(heap_blks_read), 0), 4) as ratio "
                  "from pg_statio_user_tables having sum(heap_blks_hit) + sum(heap_blks_read) > 10000"),
    "seq_scans": ("select relname as t, seq_scan, coalesce(idx_scan, 0) as idx_scan, n_live_tup as rows from pg_stat_user_tables "
                  "where schemaname = 'public' and n_live_tup > 10000 and seq_scan > coalesce(idx_scan, 0) "
                  "and seq_tup_read / greatest(seq_scan, 1) > 1000 order by seq_tup_read desc limit 20"),
    "slow_queries": ("select left(regexp_replace(query, '\\s+', ' ', 'g'), 200) as q, calls, round(mean_exec_time::numeric, 1) as mean_ms "
                     "from extensions.pg_stat_statements where calls >= 10 and mean_exec_time > 500 "
                     "order by mean_exec_time * calls desc limit 10"),
    "long_running": ("select pid, round(extract(epoch from now() - query_start)) as secs, left(regexp_replace(query, '\\s+', ' ', 'g'), 120) as q "
                     "from pg_stat_activity where state <> 'idle' and backend_type = 'client backend' "
                     "and now() - query_start > interval '5 minutes' order by query_start limit 10"),
    "dead_tuples": ("select relname as t, n_dead_tup as dead, n_live_tup as live from pg_stat_user_tables "
                    "where schemaname = 'public' and n_live_tup > 10000 and n_dead_tup > 0.2 * n_live_tup "
                    "order by n_dead_tup desc limit 20"),
    "connections": ("select count(*) as used, current_setting('max_connections')::int as max from pg_stat_activity "
                    "having count(*) > 0.8 * current_setting('max_connections')::int"),
}


def project_ref(url):
    m = re.match(r"https://([a-z0-9]{20})\.supabase\.co", url or "")
    return m.group(1) if m else None


def _psql(dsn, script, timeout=180):
    env = dict(os.environ, **RO_ENV)
    r = subprocess.run(["psql", dsn, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-"], input=script,
                       capture_output=True, text=True, timeout=timeout, env=env)
    if r.returncode != 0:
        raise RuntimeError("psql failed")
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    return json.loads(lines[-1]) if lines else []


def as_json(sql):
    return f"select coalesce(json_agg(x), '[]') from ({sql}) x;"


def splinter_sql(cache=CACHE):
    """splinter.sql at the pinned release; refused if its SHA-256 differs."""
    p = cache / "splinter-2026.11.0.sql"
    if not p.exists():
        req = urllib.request.Request(SPLINTER_URL, headers={"User-Agent": "cybersec-scan"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
        cache.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    text = p.read_bytes()
    if hashlib.sha256(text).hexdigest() != SPLINTER_SHA256:
        p.unlink(missing_ok=True)
        raise RuntimeError("splinter.sql checksum mismatch")
    return text.decode()


def splinter_script(text):
    """Setup statements, then the final query wrapped in json_agg, in one read-only transaction."""
    m = re.search(r"end\s*\$\$;\s*\n\s*\(", text)
    if not m:
        raise RuntimeError("splinter.sql layout changed")
    cut = m.end() - 1
    return "begin read only;\n" + text[:cut] + "\n" + as_json(text[cut:]) + "\ncommit;\n"


def advisors_api(ref, token):
    lints = []
    for kind in ("security", "performance"):
        req = urllib.request.Request(API.format(ref=ref, kind=kind),
                                     headers={"Authorization": f"Bearer {token}", "User-Agent": "cybersec-scan"})
        with urllib.request.urlopen(req, timeout=60) as r:
            lints += json.loads(r.read()).get("lints", [])
    return lints


def lint_findings(lints, host):
    out = {}
    for x in lints:
        cats = [c.upper() for c in x.get("categories") or []]
        f = {"source": "advisors", "rule": x["name"], "class": x["name"], "severity": LEVEL.get(x.get("level"), "low"),
             "owasp": "A02" if "SECURITY" in cats else "PERF", "confidence": "confirmed", "scope": "live",
             "file": f"db:{host}", "lines": "-", "evidence": f"{x.get('title', x['name'])}: {x.get('detail', '')}"[:300],
             "fp": x.get("cache_key") or f"{x['name']}|{x.get('detail', '')}",
             "fix_hint": f"{x.get('description', '')} {x.get('remediation', '')}".strip()[:400]}
        out[f["fp"]] = f
    return list(out.values())


def health_findings(rows, host):
    f = []

    def add(rule, sev, detail, fix, key):
        f.append({"source": "dbhealth", "rule": rule, "class": rule, "severity": sev, "owasp": "PERF",
                  "confidence": "confirmed", "scope": "live", "file": f"db:{host}", "lines": "-",
                  "evidence": f"{rule}: {detail}"[:300], "fp": f"{rule}|{key}", "fix_hint": fix})
    for r in rows.get("cache_hit") or []:
        if r["ratio"] is not None and float(r["ratio"]) < 0.99:
            add("cache_hit", "medium", f"table cache hit ratio {r['ratio']} (target 0.99)",
                "Add memory (compute size) or cut large scans; see seq_scans and slow_queries.", "ratio")
    for r in rows.get("seq_scans") or []:
        add("seq_scans", "medium", f"{r['t']}: {r['seq_scan']} seq scans vs {r['idx_scan']} index scans on {r['rows']} rows",
            "Add an index for the filter columns of the queries on this table.", r["t"])
    for r in rows.get("slow_queries") or []:
        add("slow_queries", "medium", f"{r['mean_ms']} ms mean over {r['calls']} calls: {r['q']}",
            "Run EXPLAIN ANALYZE on this query; add indexes or rewrite it.", hashlib.sha1(r["q"].encode()).hexdigest()[:12])
    for r in rows.get("long_running") or []:
        add("long_running", "medium", f"pid {r['pid']} running {r['secs']} s: {r['q']}",
            "Check the query; set statement_timeout for the role that runs it.", hashlib.sha1(r["q"].encode()).hexdigest()[:12])
    for r in rows.get("dead_tuples") or []:
        add("dead_tuples", "low", f"{r['t']}: {r['dead']} dead vs {r['live']} live rows",
            "Tune autovacuum for this table or run VACUUM (ANALYZE).", r["t"])
    for r in rows.get("connections") or []:
        add("connections", "high", f"{r['used']} of {r['max']} connections in use",
            "Use the connection pooler (Supavisor) or raise compute size.", "connections")
    return f


def run(root, cfg, url, dsn, host):
    """Returns (status by part, findings, notes)."""
    st, out, notes = {}, [], []
    token = os.environ.get(cfg.get("supabase", {}).get("access_token_env", "SUPABASE_ACCESS_TOKEN"), "")
    ref = cfg.get("supabase", {}).get("project_ref") or project_ref(url)
    try:
        if token and ref:
            out += lint_findings(advisors_api(ref, token), host)
            st["advisors"], how = "ran", "Management API"
        elif dsn and shutil.which("psql"):
            out += lint_findings(_psql(dsn, splinter_script(splinter_sql())), host)
            st["advisors"], how = "ran", "splinter.sql 2026.11.0"
        else:
            st["advisors"], how = "missing", ""
    except (urllib.error.URLError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        st["advisors"], how = "error", ""
    if st["advisors"] == "ran":
        notes.append(f"Supabase advisors ({how}): {len(out)} lints.")
    if dsn and shutil.which("psql"):
        rows = {}
        for name, sql in HEALTH.items():
            try:
                rows[name] = _psql(dsn, as_json(sql), timeout=60)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired):
                rows[name] = None                        # e.g. pg_stat_statements not enabled
        h = health_findings(rows, host)
        out += h
        st["dbhealth"] = "ran"
        skipped = [k for k, v in rows.items() if v is None]
        notes.append(f"Database health: {len(h)} findings" + (f"; not available: {', '.join(skipped)}." if skipped else "."))
    else:
        st["dbhealth"] = "off"
    return st, out, notes
