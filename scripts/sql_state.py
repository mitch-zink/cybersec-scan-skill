"""Replay SQL migrations in filename order. Compute the final row-level security (RLS) state per table.
Stdlib only. Pattern-based: statements it does not understand are counted, not guessed."""
import pathlib
import re

TENANT_COLS = {"tenant_id", "org_id", "workspace_id", "account_id", "user_id"}
WRITE_CMDS = {"INSERT", "UPDATE", "DELETE"}


def statements(text):
    """Split SQL on ';' outside quotes, dollar-quoted blocks, and comments. Yields (start_offset, stmt)."""
    out, buf, i, start, n, first = [], [], 0, 0, len(text), None
    while i < n:
        c = text[i]
        if first is None and not c.isspace():
            first = i
        if text.startswith("--", i):
            j = text.find("\n", i); j = n if j < 0 else j
            buf.append(text[i:j]); i = j; continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2); j = n if j < 0 else j + 2
            buf.append(text[i:j]); i = j; continue
        if c == "'":
            j = i + 1
            while j < n and not (text[j] == "'" and (j + 1 >= n or text[j + 1] != "'")):
                j += 2 if text[j] == "'" else 1
            buf.append(text[i:j + 1]); i = j + 1; continue
        m = re.match(r"\$([A-Za-z_]*)\$", text[i:i + 64]) if c == "$" else None
        if m:
            tag = m.group(0); j = text.find(tag, i + len(tag))
            j = n if j < 0 else j + len(tag)
            buf.append(text[i:j]); i = j; continue
        if c == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append((first, stmt))
            buf, start, first = [], i + 1, None
        else:
            buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append((first, tail))
    return out


def _clean(stmt):
    stmt = re.sub(r"--[^\n]*", " ", stmt)
    return re.sub(r"/\*.*?\*/", " ", stmt, flags=re.S).strip()


def _name(raw):
    return raw.split(".")[-1].strip('"').lower()


def _columns(body):
    cols, depth, cur = [], 0, ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            cols.append(cur.strip()); cur = ""
        else:
            cur += ch
    cols.append(cur.strip())
    names = set()
    for c in cols:
        w = c.split()
        if w and w[0].upper() not in {"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "EXCLUDE"}:
            names.add(w[0].strip('"').lower())
    return names


def replay(migration_dir):
    files = sorted(pathlib.Path(migration_dir).rglob("*.sql"), key=lambda p: p.name)
    tables, funcs, unknown = {}, {}, 0
    for f in files:
        text = f.read_text(errors="ignore")
        for off, raw in statements(text):
            stmt = _clean(raw)
            line = text.count("\n", 0, off) + 1
            where = {"file": f.name, "line": line}
            m = re.match(r"CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?([\w.\"]+)\s*\((.*)\)\s*$", stmt, re.I | re.S)
            if m:
                cols = _columns(m.group(3))
                tables[_name(m.group(2))] = {"cols": cols, "rls": False, "policies": [], "grants": [], "created": where}
                continue
            m = re.match(r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w.\"]+)\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY", stmt, re.I)
            if m and _name(m.group(1)) in tables:
                tables[_name(m.group(1))]["rls"] = m.group(2).upper() == "ENABLE"; continue
            m = re.match(r"CREATE\s+POLICY\s+(\"?\w+\"?)\s+ON\s+([\w.\"]+)(.*)$", stmt, re.I | re.S)
            if m and _name(m.group(2)) in tables:
                rest = m.group(3)
                cmd = (re.search(r"\bFOR\s+(\w+)", rest, re.I) or [None, "ALL"])[1].upper() if re.search(r"\bFOR\s+", rest, re.I) else "ALL"
                using = re.search(r"\bUSING\s*\((.*?)\)\s*(WITH|$)", rest, re.I | re.S)
                check = re.search(r"\bWITH\s+CHECK\s*\((.*)\)", rest, re.I | re.S)
                to = re.search(r"\bTO\s+(.*?)(?=\bUSING\b|\bWITH\s+CHECK\b|$)", rest, re.I | re.S)
                roles = sorted({r.strip().strip('"').lower() for r in to.group(1).split(",")}) if to else ["public"]
                tables[_name(m.group(2))]["policies"].append({
                    "name": m.group(1).strip('"'), "cmd": cmd, "roles": roles,
                    "using": (using.group(1).strip() if using else ""),
                    "check": (check.group(1).strip() if check else ""), "where": where})
                continue
            m = re.match(r"DROP\s+POLICY\s+(IF\s+EXISTS\s+)?(\"?\w+\"?)\s+ON\s+([\w.\"]+)", stmt, re.I)
            if m and _name(m.group(3)) in tables:
                t = tables[_name(m.group(3))]
                t["policies"] = [p for p in t["policies"] if p["name"] != m.group(2).strip('"')]; continue
            m = re.match(r"DROP\s+TABLE\s+(IF\s+EXISTS\s+)?([\w.\"]+)", stmt, re.I)
            if m:
                tables.pop(_name(m.group(2)), None); continue
            m = re.match(r"GRANT\s+.*?\s+ON\s+(?:TABLE\s+)?([\w.\"]+)\s+TO\s+(.*)$", stmt, re.I | re.S)
            if m and _name(m.group(1)) in tables:
                roles = {r.strip().lower() for r in m.group(2).split(",")}
                tables[_name(m.group(1))]["grants"].append({"roles": sorted(roles), "where": where}); continue
            m = re.match(r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.\"]+)(.*)$", stmt, re.I | re.S)
            if m:
                body = m.group(2)
                funcs[_name(m.group(1))] = {"definer": bool(re.search(r"SECURITY\s+DEFINER", body, re.I)),
                                            "body": body, "where": where}
                continue
            unknown += 1
    return tables, funcs, unknown


def findings(migration_dir):
    tables, funcs, unknown = replay(migration_dir)
    out = []

    def add(rule, cls, owasp, sev, tname, t, detail, fix, w=None):
        w = w or t["created"]
        out.append({"source": "sql", "owasp": owasp, "class": cls, "severity": sev, "confidence": "confirmed",
                    "scope": "current", "file": w["file"], "lines": str(w["line"]),
                    "evidence": f"{rule} {tname}: {detail}", "fp": f"{rule}|{tname}|{detail}",
                    "fix_hint": fix})

    for name, t in tables.items():
        tenant = sorted(t["cols"] & TENANT_COLS)
        if not tenant:
            continue
        if not t["rls"]:
            add("R1", "CWE-284", "A01", "high", name, t, f"RLS off, tenant column {tenant[0]}",
                f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY and add policies.")
        for p in t["policies"]:
            if p["roles"] == ["service_role"]:
                continue   # server-only policy: the service key is already trusted
            for field in ("using", "check"):
                if re.fullmatch(r"\s*true\s*", p[field], re.I):
                    add("R2", "CWE-863", "A01", "high", name, t, f"policy {p['name']} {field.upper()} (true)",
                        "Replace true with a predicate on the tenant column.", p["where"])
        cmds = {p["cmd"] for p in t["policies"]}
        for wc in sorted(WRITE_CMDS):
            if t["rls"] and "ALL" not in cmds and wc not in cmds:
                add("R3", "CWE-862", "A01", "medium", name, t, f"no {wc} policy",
                    f"Add a {wc} policy that checks the tenant column.")
        for g in t["grants"]:
            if {"anon", "public"} & set(g["roles"]):
                add("R4", "CWE-732", "A01", "high", name, t, "grant to anon or public",
                    "Revoke the grant. Expose tenant data only through an authenticated policy.", g["where"])
    guard = re.compile(r"auth\.uid\(\)|auth\.jwt\(\)|current_setting|tenant|org_id|workspace|is_member|has_role", re.I)
    for fname, f in funcs.items():
        if not f["definer"] or guard.search(f["body"]):
            continue
        hit = next((tn for tn, t in tables.items() if t["cols"] & TENANT_COLS
                    and re.search(r"\b" + re.escape(tn) + r"\b", f["body"], re.I)), None)
        if hit:
            add("R5", "CWE-863", "A01", "medium", hit, tables[hit], f"SECURITY DEFINER {fname} reads or writes {hit} with no tenant check",
                "Check the caller's tenant inside the function, or use SECURITY INVOKER.", f["where"])
    return out, {"tables": len(tables), "tenant_tables": sum(1 for t in tables.values() if t["cols"] & TENANT_COLS),
                 "functions": len(funcs), "unparsed_statements": unknown}


def table_rows(migration_dir):
    """One row per table: final RLS state, policies, grants, tenant columns (for AC8)."""
    tables, _, _ = replay(migration_dir)
    return [{"table": n, "rls": t["rls"], "tenant_cols": sorted(t["cols"] & TENANT_COLS),
             "policies": [p["name"] + ":" + p["cmd"] for p in t["policies"]],
             "grants_to": sorted({r for g in t["grants"] for r in g["roles"]}), "created_in": t["created"]["file"]}
            for n, t in sorted(tables.items())]
