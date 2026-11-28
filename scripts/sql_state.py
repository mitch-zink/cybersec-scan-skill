"""Replay SQL migrations in filename order. Compute final RLS, grants, policies, views and functions per object.
Stdlib only. Pattern-based: statements it does not understand are counted, not guessed."""
import collections
import pathlib
import re

TENANT_COLS = {"tenant_id", "org_id", "workspace_id", "account_id", "user_id"}
API_ROLES = {"public", "anon", "authenticated"}
IDENT = r'(?:"(?:[^"]|"")+"|[\w$]+)'
QNAME = rf"{IDENT}(?:\s*\.\s*{IDENT})?"
I, S = re.I, re.I | re.S
IGNORED = re.compile(r"(CREATE\s+(UNIQUE\s+)?INDEX|DROP\s+INDEX|COMMENT\s+ON|NOTIFY|BEGIN|COMMIT|START\s+TRANSACTION|"
                     r"CREATE\s+(OR\s+REPLACE\s+)?(CONSTRAINT\s+)?TRIGGER|DROP\s+TRIGGER|ALTER\s+TRIGGER|CREATE\s+EXTENSION|"
                     r"ALTER\s+EXTENSION|SELECT|INSERT|UPDATE|DELETE|WITH|SET|RESET|CREATE\s+SEQUENCE|ALTER\s+SEQUENCE|"
                     r"DROP\s+SEQUENCE|CREATE\s+TYPE|ALTER\s+TYPE|DROP\s+TYPE|DROP\s+FUNCTION|DROP\s+VIEW|"
                     r"DROP\s+MATERIALIZED\s+VIEW|CREATE\s+SCHEMA|ANALYZE|VACUUM|REFRESH\s+MATERIALIZED\s+VIEW|"
                     r"TRUNCATE|LOCK|CREATE\s+(OR\s+REPLACE\s+)?(AGGREGATE|CAST|DOMAIN)|CLUSTER|REINDEX)\b", I)
GUARD = re.compile(r"auth\.uid\(\)|auth\.jwt\(\)|request\.jwt", I)
WEAK = re.compile(r"\(*\s*(auth\.role\(\)\s*=\s*'authenticated'|\(?\s*(select\s+)?auth\.uid\(\)\s*\)?\s+is\s+not\s+null)\s*\)*", I)
LOOP = re.compile(r"FOREACH\s+(\w+)\s+IN\s+ARRAY\s+ARRAY\s*\[(.*?)\]\s+LOOP(.*?)END\s+LOOP", S)
FMT = re.compile(r"format\(\s*((?:'(?:[^']|'')*'\s*)+|\$(\w*)\$.*?\$\2\$)\s*,", S)
DIRECT = re.compile(r"\b(ALTER\s+TABLE|CREATE\s+POLICY|DROP\s+POLICY|GRANT|REVOKE)\b[^;]*", I)


def statements(text):
    """Split SQL on ';' outside quotes, dollar-quoted blocks, and comments. Returns [(start_offset, stmt)]."""
    out, buf, i, n, first = [], [], 0, len(text), None
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
            buf, first = [], None
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


def _unq(s):
    s = s.strip()
    return s[1:-1].replace('""', '"') if s.startswith('"') else s.lower()


def qname(raw):
    """'schema.name', default schema public."""
    parts = [_unq(x) for x in re.findall(IDENT, raw)]
    return ".".join(parts[-2:]) if len(parts) > 1 else "public." + parts[0]


def _roles(text):
    return {r.strip().strip('"').lower() for r in text.split(",") if r.strip()}


def _paren(text, start):
    """Text inside the balanced parens that open at or after start, else ''. Not stripped."""
    i = text.find("(", start)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(text)):
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        if depth == 0:
            return text[i + 1:j]
    return text[i + 1:]


def _columns(body):
    cols, depth, cur = [], 0, ""
    for ch in body:
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if ch == "," and depth == 0:
            cols.append(cur.strip()); cur = ""
        else:
            cur += ch
    cols.append(cur.strip())
    skip = {"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "EXCLUDE", "LIKE"}
    return {_unq(c.split()[0]) for c in cols if c.split() and c.split()[0].upper() not in skip}


def _func_names(text):
    """Function names in a GRANT/REVOKE ... ON FUNCTION list."""
    return [qname(m) for m in re.findall(rf"({QNAME})\s*\(", text)]


class Replay:
    def __init__(self, default_grants=True):
        self.tables, self.views, self.funcs = {}, {}, {}
        self.default_grants = default_grants
        self.table_default = {"anon", "authenticated"} if default_grants else set()
        self.func_default = {"public", "anon", "authenticated"} if default_grants else {"public"}
        self.meta = collections.Counter()
        self.kinds = collections.Counter()

    def _default_roles(self, q):
        return set(self.table_default) if q.startswith("public.") else set()

    def _objs(self, names):
        return [self.tables.get(q) or self.views.get(q) for q in names if q in self.tables or q in self.views]

    def _schema_objs(self, schema):
        return [o for q, o in list(self.tables.items()) + list(self.views.items()) if q.startswith(schema + ".")]

    # each handler returns True when it understood the statement
    def create_table(self, s, where):
        m = re.match(rf"CREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({QNAME})\s*(\(|AS\b|PARTITION\s+OF\b)", s, I)
        if not m:
            return False
        q = qname(m.group(1))
        unknown = m.group(2) != "("
        cols = set() if unknown else _columns(_paren(s, m.start(2)))
        if q not in self.tables or "IF NOT EXISTS" not in s[:m.end(1)].upper():
            self.tables[q] = {"cols": cols, "cols_unknown": unknown, "rls": False, "force": False, "policies": [],
                              "roles": self._default_roles(q), "created": where}
        return True

    def alter_table(self, s, where):
        m = re.match(rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({QNAME})\s+(.*)$", s, S)
        if not m:
            return False
        q, rest = qname(m.group(1)), m.group(2)
        t = self.tables.get(q)
        if t is None:
            return True                                   # table from outside these migrations
        for c in re.findall(rf"ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})", rest, I):
            if c.upper() not in {"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "EXCLUDE"}:
                t["cols"].add(_unq(c))
        for c in re.findall(rf"DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?({IDENT})", rest, I):
            t["cols"].discard(_unq(c))
        for c_old, c_new in re.findall(rf"RENAME\s+(?:COLUMN\s+)?({IDENT})\s+TO\s+({IDENT})", rest, I):
            if _unq(c_old) in t["cols"]:
                t["cols"].discard(_unq(c_old)); t["cols"].add(_unq(c_new))
        if re.search(r"\bENABLE\s+ROW\s+LEVEL\s+SECURITY", rest, I):
            t["rls"] = True
        if re.search(r"\bDISABLE\s+ROW\s+LEVEL\s+SECURITY", rest, I):
            t["rls"] = False
        if re.search(r"\bNO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY", rest, I):
            t["force"] = False
        elif re.search(r"\bFORCE\s+ROW\s+LEVEL\s+SECURITY", rest, I):
            t["force"] = True
        r = re.match(rf"RENAME\s+TO\s+({IDENT})\s*$", rest.strip(), I)
        if r:
            self.tables[q.split(".")[0] + "." + _unq(r.group(1))] = self.tables.pop(q)
        return True

    def _policy_parts(self, rest):
        head = re.split(r"\bUSING\b|\bWITH\s+CHECK\b", rest, maxsplit=1, flags=I)[0]
        part = {}
        if (m := re.search(r"\bAS\s+(PERMISSIVE|RESTRICTIVE)\b", head, I)):
            part["permissive"] = m.group(1).upper() == "PERMISSIVE"
        if (m := re.search(r"\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b", head, I)):
            part["cmd"] = m.group(1).upper()
        if (m := re.search(r"\bTO\s+(.*)$", head, S)):
            part["roles"] = sorted(_roles(m.group(1)))
        if (m := re.search(r"\bUSING\s*\(", rest, I)):
            part["using"] = _paren(rest, m.start()).strip()
        if (m := re.search(r"\bWITH\s+CHECK\s*\(", rest, I)):
            part["check"] = _paren(rest, m.start()).strip()
        return part

    def create_policy(self, s, where):
        m = re.match(rf"CREATE\s+POLICY\s+({IDENT})\s+ON\s+({QNAME})(.*)$", s, S)
        if not m:
            return False
        t = self.tables.get(qname(m.group(2)))
        if t is not None:
            pol = {"name": _unq(m.group(1)), "cmd": "ALL", "roles": ["public"], "permissive": True,
                   "using": "", "check": "", "where": where}
            pol.update(self._policy_parts(m.group(3)))
            t["policies"] = [x for x in t["policies"] if x["name"] != pol["name"]] + [pol]
        return True

    def alter_policy(self, s, where):
        m = re.match(rf"ALTER\s+POLICY\s+({IDENT})\s+ON\s+({QNAME})(.*)$", s, S)
        if not m:
            return False
        t = self.tables.get(qname(m.group(2)))
        pol = next((x for x in (t or {}).get("policies", []) if x["name"] == _unq(m.group(1))), None)
        if pol is not None:
            rest = m.group(3)
            if (r := re.match(rf"\s*RENAME\s+TO\s+({IDENT})", rest, I)):
                pol["name"] = _unq(r.group(1))
            else:
                pol.update(self._policy_parts(rest)); pol["where"] = where
        return True

    def drop_policy(self, s, where):
        m = re.match(rf"DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?({IDENT})\s+ON\s+({QNAME})", s, I)
        if not m:
            return False
        t = self.tables.get(qname(m.group(2)))
        if t is not None:
            t["policies"] = [x for x in t["policies"] if x["name"] != _unq(m.group(1))]
        return True

    def grant_revoke(self, s, where):
        m = re.match(r"(GRANT|REVOKE)\s+(?:GRANT\s+OPTION\s+FOR\s+)?(.*?)\s+ON\s+(.*?)\s+(TO|FROM)\s+(.*?)(?:\s+(?:WITH\s+GRANT\s+OPTION|GRANTED\s+BY\s+\w+|CASCADE|RESTRICT))?\s*$", s, S)
        if not m:
            return False
        grant, privs, target, roles = m.group(1).upper() == "GRANT", m.group(2).upper(), m.group(3), _roles(m.group(5))
        reads = "ALL" in privs or "SELECT" in privs
        if (f := re.match(r"(?:ALL\s+)?(?:FUNCTIONS?|ROUTINES?|PROCEDURES?)\s+(?:IN\s+SCHEMA\s+(\w+))?(.*)$", target, S)):
            if not ("EXECUTE" in privs or "ALL" in privs):
                return True
            names = [q for q in self.funcs if q.startswith(f.group(1) + ".")] if f.group(1) else _func_names(f.group(2))
            for q in names:
                if q in self.funcs:
                    fr = self.funcs[q]["exec_roles"]
                    fr |= roles if grant else set()
                    fr -= set() if grant else roles
            return True
        if re.match(r"(SCHEMA|SEQUENCE|ALL\s+SEQUENCES|TYPE|DOMAIN|DATABASE|LARGE\s+OBJECT)\b", target, I):
            return True
        if (a := re.match(r"ALL\s+TABLES\s+IN\s+SCHEMA\s+(.+)$", target, I)):
            objs = [o for sc in _roles(a.group(1)) for o in self._schema_objs(sc)]
        else:
            objs = self._objs([qname(x) for x in re.findall(QNAME, re.sub(r"^\s*TABLE\s+", "", target, flags=I))])
        for o in objs if reads else []:
            o["roles"] = o["roles"] | roles if grant else o["roles"] - roles
        return True

    def view(self, s, where):
        m = re.match(rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?({QNAME})(.*?)\bAS\b", s, S)
        if m:
            q = qname(m.group(1))
            inv = bool(re.search(r"security_invoker\s*(=\s*(true|on|1)|[,)])", m.group(2), I))
            prev = self.views.get(q, {})
            self.views[q] = {"invoker": inv, "roles": prev.get("roles", self._default_roles(q)), "where": where}
            return True
        m = re.match(rf"ALTER\s+(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+EXISTS\s+)?({QNAME})\s+(.*)$", s, S)
        if not m:
            return False
        v = self.views.get(qname(m.group(1)))
        if v is not None and (o := re.search(r"security_invoker\s*=\s*(\w+)", m.group(2), I)):
            v["invoker"] = o.group(1).lower() in ("true", "on", "1")
        return True

    def function(self, s, where):
        m = re.match(rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+({QNAME})(.*)$", s, S)
        if m:
            q = qname(m.group(1))
            prev = self.funcs.get(q, {})
            self.funcs[q] = {"definer": bool(re.search(r"SECURITY\s+DEFINER", m.group(2), I)), "body": m.group(2),
                             "search_path": bool(re.search(r"SET\s+search_path", m.group(2), I)),
                             "trigger": bool(re.search(r"RETURNS\s+(event_)?trigger\b", m.group(2), I)),
                             "exec_roles": prev.get("exec_roles", set(self.func_default)), "where": where}
            return True
        m = re.match(rf"ALTER\s+(?:FUNCTION|PROCEDURE|ROUTINE)\s+({QNAME})(.*)$", s, S)
        if not m:
            return False
        f = self.funcs.get(qname(m.group(1)))
        if f is not None:
            if re.search(r"\bSET\s+search_path", m.group(2), I):
                f["search_path"] = True
            if re.search(r"\bSECURITY\s+DEFINER", m.group(2), I):
                f["definer"] = True
            elif re.search(r"\bSECURITY\s+INVOKER", m.group(2), I):
                f["definer"] = False
        return True

    def default_privileges(self, s, where):
        m = re.match(r"ALTER\s+DEFAULT\s+PRIVILEGES\s+(?:FOR\s+(?:ROLE|USER)\s+[\w\s,\"]+?\s+)?(?:IN\s+SCHEMA\s+(\w+)\s+)?"
                     r"(GRANT|REVOKE)\s+(.*?)\s+ON\s+(TABLES|FUNCTIONS|ROUTINES)\s+(?:TO|FROM)\s+(.*?)\s*(?:CASCADE)?$", s, S)
        if not m:
            return False
        if (m.group(1) or "public").lower() != "public":
            return True
        grant, privs, roles = m.group(2).upper() == "GRANT", m.group(3).upper(), _roles(m.group(5))
        target = self.table_default if m.group(4).upper() == "TABLES" else self.func_default
        if "ALL" in privs or "SELECT" in privs or "EXECUTE" in privs:
            target |= roles if grant else set()
            target -= set() if grant else roles
        return True

    def drop_table(self, s, where):
        m = re.match(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(.*?)(?:\s+(?:CASCADE|RESTRICT))?\s*$", s, S)
        if not m:
            return False
        for x in re.findall(QNAME, m.group(1)):
            self.tables.pop(qname(x), None)
        return True

    def do_block(self, s, where):
        if not re.match(r"DO\b", s, I):
            return False
        body = re.search(r"\$(\w*)\$(.*)\$\1\$", s, S)
        body = body.group(2) if body else s
        n = 0
        for var, arr, loop in LOOP.findall(body):
            names = [x.replace("''", "'") for x in re.findall(r"'((?:[^']|'')*)'", arr)]
            for fm in FMT.finditer(loop):
                tpl = fm.group(1)
                tpl = tpl[len(fm.group(2)) + 2:-(len(fm.group(2)) + 2)] if tpl.startswith("$") else \
                    "".join(x.replace("''", "'") for x in re.findall(r"'((?:[^']|'')*)'", tpl))
                args = _paren(loop, fm.start())[fm.end() - fm.start() - len("format("):]
                argv = [a.strip() for a in re.split(r",(?![^(]*\))", args) if a.strip()]
                if any(not re.fullmatch(rf"{var}(\s*\|\|\s*'[^']*')?", a, I) for a in argv) \
                        or tpl.count("%I") != len(argv) or re.search(r"%[^I%]", tpl):
                    continue
                for name in names:
                    sql = tpl
                    for a in argv:
                        suffix = re.search(r"'([^']*)'", a)
                        sql = sql.replace("%I", name + (suffix.group(1) if suffix else ""), 1)
                    self.dispatch(sql.replace("%%", "%"), where, count=False)
                    n += 1
        for d in DIRECT.finditer(body):
            if "%" not in d.group(0):
                self.dispatch(d.group(0), where, count=False)
                n += 1
        self.meta["do_expanded" if n else "do_unexpanded"] += 1
        return True

    HANDLERS = ("do_block", "create_table", "alter_table", "create_policy", "alter_policy", "drop_policy",
                "grant_revoke", "view", "function", "default_privileges", "drop_table")

    def dispatch(self, stmt, where, count=True):
        s = _clean(stmt)
        if not s:
            return
        if count:
            if IGNORED.match(s):
                self.meta["ignored"] += 1
                return
            self.meta["relevant"] += 1
        for h in self.HANDLERS:
            if getattr(self, h)(s, where):
                return
        if count:
            self.meta["unparsed"] += 1
            self.kinds[" ".join(s.split()[:3]).upper()] += 1

    def run(self, migration_dir):
        for f in sorted(pathlib.Path(migration_dir).rglob("*.sql"), key=lambda q: q.name):
            text = f.read_text(errors="ignore")
            for off, raw in statements(text):
                self.dispatch(raw, {"file": f.name, "line": text.count("\n", 0, off) + 1})
        return self


def replay(migration_dir, cfg=None):
    grants = ((cfg or {}).get("sql") or {}).get("public_default_grants", True)
    return Replay(grants).run(migration_dir)


def tenant(t):
    return sorted(t["cols"] & TENANT_COLS)


def findings(migration_dir, cfg=None):
    r = replay(migration_dir, cfg)
    out = []

    def add(rule, cls, sev, q, detail, fix, where):
        out.append({"source": "sql", "rule": rule, "table": q, "owasp": "A02" if rule == "R8" else "A01",
                    "class": cls, "severity": sev, "confidence": "confirmed", "scope": "current",
                    "file": where["file"], "lines": str(where["line"]), "evidence": f"{rule} {q}: {detail}",
                    "fp": f"{rule}|{q}|{detail}", "fix_hint": fix})

    no_write = 0
    for q, t in r.tables.items():
        tc = tenant(t)
        open_roles = sorted(t["roles"] & API_ROLES)
        if q.startswith("public.") and not t["rls"] and open_roles:
            add("R1", "CWE-284", "critical" if tc else "high", q,
                f"RLS off; {', '.join(open_roles)} can reach it" + (f"; tenant column {tc[0]}" if tc else ""),
                f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY and add policies, or revoke access from anon and authenticated.",
                t["created"])
        cmds = {x["cmd"] for x in t["policies"]}
        if t["rls"] and "ALL" not in cmds and not {"INSERT", "UPDATE", "DELETE"} <= cmds:
            no_write += 1
        for pol in t["policies"]:
            api = set(pol["roles"]) & API_ROLES
            if not tc or not api:
                continue
            for field in ("using", "check"):
                if pol["permissive"] and re.fullmatch(r"\s*\(*\s*true\s*\)*\s*", pol[field], I):
                    add("R2", "CWE-863", "high", q, f"policy {pol['name']} {pol['cmd']} {field.upper()} (true)",
                        "Replace true with a predicate on the tenant column.", pol["where"])
                elif WEAK.fullmatch(pol[field].strip()):
                    add("R6", "CWE-863", "high", q, f"policy {pol['name']} {field.upper()} only checks sign-in",
                        "Compare the tenant column to auth.uid() or a membership check.", pol["where"])
                if re.search(r"user_metadata|raw_user_meta_data", pol[field], I):
                    add("R7", "CWE-639", "high", q, f"policy {pol['name']} {field.upper()} reads user_metadata",
                        "user_metadata is editable by the user. Use app_metadata or a table you control.", pol["where"])
    tenant_q = {q for q, t in r.tables.items() if tenant(t)}
    tenant_tables = {q.split(".")[1] for q in tenant_q}
    guarded = {q.split(".")[1] for q, f in r.funcs.items() if GUARD.search(f["body"])}
    calls_guard = re.compile(r"\b(" + "|".join(map(re.escape, sorted(guarded))) + r")\s*\(", I) if guarded else None
    hits = re.compile(r"\b(?:(\w+)\s*\.\s*)?(" + "|".join(map(re.escape, sorted(tenant_tables))) + r")\b", I) if tenant_tables else None

    def tenant_hit(body):
        for m in hits.finditer(body) if hits else []:
            q = f"{(m.group(1) or 'public').lower()}.{m.group(2).lower()}"
            if q in tenant_q:
                return q
        return None
    for q, f in r.funcs.items():
        if not f["definer"] or f["trigger"]:
            continue
        if not f["search_path"]:
            add("R8", "CWE-426", "medium", q, f"SECURITY DEFINER {q} has no fixed search_path",
                f"ALTER FUNCTION {q} SET search_path = '' and qualify object names.", f["where"])
        callers = f["exec_roles"] & API_ROLES
        if not callers or GUARD.search(f["body"]) or (calls_guard and calls_guard.search(f["body"])):
            continue
        tq = tenant_hit(f["body"])
        if tq:
            add("R5", "CWE-863", "high" if callers & {"anon", "public"} else "medium", tq,
                f"SECURITY DEFINER {q} reads or writes {tq} with no auth check; callable by {', '.join(sorted(callers))}",
                "Check auth.uid() inside the function, revoke EXECUTE from anon and authenticated, or use SECURITY INVOKER.",
                f["where"])
    for q, v in r.views.items():
        open_roles = sorted(v["roles"] & {"anon", "authenticated"})
        if q.startswith("public.") and not v["invoker"] and open_roles:
            add("R9", "CWE-284", "high", q, f"view runs as owner (no security_invoker); {', '.join(open_roles)} can read it",
                f"ALTER VIEW {q} SET (security_invoker = true), or revoke access.", v["where"])
    meta = {"tables": len(r.tables), "tenant_tables": len(tenant_q), "functions": len(r.funcs),
            "views": len(r.views), "policies": sum(len(t["policies"]) for t in r.tables.values()),
            "no_write_policy_tables": no_write, "relevant": r.meta["relevant"], "ignored": r.meta["ignored"],
            "unparsed": r.meta["unparsed"], "do_expanded": r.meta["do_expanded"],
            "do_unexpanded": r.meta["do_unexpanded"], "unparsed_kinds": dict(r.kinds.most_common(10))}
    return out, meta


def table_rows(migration_dir, cfg=None):
    """One row per table: final RLS state, policies, roles, tenant columns."""
    r = replay(migration_dir, cfg)
    return [{"table": q, "rls": t["rls"], "force": t["force"], "tenant_cols": tenant(t),
             "policies": [x["name"] + ":" + x["cmd"] for x in t["policies"]], "roles": sorted(t["roles"]),
             "created_in": t["created"]["file"]} for q, t in sorted(r.tables.items())]
