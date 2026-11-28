#!/usr/bin/env python3
"""cybersec-scan helper. Stdlib only.

  discover ROOT                        file list, skip rules, coverage
  incr ROOT                            read set since saved state (exit 3 = run FULL)
  state ROOT                           saved state: ok | missing | corrupt
  save ROOT MODE [N]                   save state (FULL: every non-SQL file read at its current hash)
  merge ROOT CANDIDATES [--scope F]    merge agent findings; reject unverifiable ones; apply verdicts
  tools ROOT [--no-history] [--fail-on LEVEL]   run every scanner; write report (exit 6 = new finding at LEVEL+)
  batch-reset ROOT                     start a new full review
  batch-next ROOT [--max-bytes N] [--max-files N] [--priority-only]   choose the next files
  batch-done ROOT                      record the last batch as read
  live ROOT                            tools plus read-only live database checks
  notify ROOT                          Slack alert for new high or critical findings (once per id)
  sarif ROOT OUT                       SARIF 2.1.0 file of open findings
  stats ROOT [--md]                    verdict counts and precision per source
  verdict ROOT ID VALUE [REASON]       owner only: real | false_positive | accepted_risk | new
  prereqs                              tool paths
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import batching  # noqa: E402
import config  # noqa: E402
import live  # noqa: E402
import notify  # noqa: E402
import sarif  # noqa: E402
import sql_state  # noqa: E402
import symbols  # noqa: E402
import tools  # noqa: E402

FULL_CAP = 150          # max files per batch
READ_CAP = 200          # incremental read set cap
TOOL_SOURCES = ("osv", "gitleaks", "gitleaks-history", "semgrep", "sql", "config", "zizmor", "trivy", "live")
REL = {k: pathlib.PurePosixPath(".cybersec", v) for k, v in {
    "state": "state.json", "findings": "last_findings.json", "incr": "incr.json", "batch": "batch.json",
    "progress": "progress.json", "verdicts": "verdicts.json", "report": "report.html"}.items()}
IMPORT_RE = re.compile(r"^\s*(import\b|from\b|require\(|#include\b|use\b|@import\b)")
REQUIRED = ("class", "file", "lines", "evidence", "control_checked")
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def p(root, key):
    return pathlib.Path(root, REL[key])


def read_json(path, default):
    path = pathlib.Path(path)
    return json.loads(path.read_text()) if path.exists() else default


def write_json(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)


def out(obj):
    print(json.dumps(obj))


def git(root, *args):
    r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    return r.returncode, r.stdout


def is_git(root):
    return git(root, "rev-parse", "--is-inside-work-tree")[0] == 0


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def is_binary(path):
    with open(path, "rb") as fh:
        return b"\0" in fh.read(8000)


def tracked(root):
    if is_git(root):
        return [f for f in git(root, "ls-files")[1].splitlines() if f]
    return [str(q.relative_to(root)) for q in pathlib.Path(root).rglob("*") if q.is_file()]


def discover(root):
    root = str(pathlib.Path(root).resolve())
    cfg = config.load(root)
    files, skipped = [], {}
    for rel in tracked(root):
        full = pathlib.Path(root, rel)
        reason = config.path_skipped(rel, cfg)
        if reason is None and (not full.is_file() or full.stat().st_size > 300 * 1024):
            reason = "too-large-or-missing"
        if reason is None and is_binary(full):
            reason = "binary"
        if reason:
            skipped[rel] = reason
        else:
            files.append(rel)
    top = {}
    for entry in sorted(os.listdir(root)):
        if entry == ".git":
            continue
        under = [f for f in files if f == entry or f.startswith(entry + "/")]
        if under:
            top[entry] = {"status": "scanned", "files": len(under)}
        else:
            reason = skipped.get(entry) or ("skip-dir" if config.path_skipped(entry + "/x", cfg) else "no scannable files")
            top[entry] = {"status": "skipped", "reason": reason}
    hashes = {f: sha256(pathlib.Path(root, f)) for f in files}
    return {"root": root, "git": is_git(root), "files": files, "count": len(files), "top_level": top,
            "skipped": skipped, "hashes": hashes, "cfg": cfg}


def non_sql(d):
    return [f for f in d["files"] if not f.endswith(".sql")]


# ---------------------------------------------------------------- incremental and state

def incr(root):
    root = str(pathlib.Path(root).resolve())
    st = load_state(root)
    if st["status"] != "ok":
        out({"mode": "FULL", "reason": "state " + st["status"]})
        return 3
    if not is_git(root):
        out({"mode": "FULL", "reason": "not a git repo"})
        return 3
    head = git(root, "rev-parse", "HEAD")[1].strip()
    diff = git(root, "diff", "--name-status", st["data"]["last_sha"], "HEAD")[1]
    changed, deleted = [], []
    for line in diff.splitlines():
        parts = line.split("\t")
        (deleted if parts[0].startswith("D") else changed).append(parts[-1])
    cur = discover(root)
    alive = set(cur["files"])
    changed = sorted(f for f in changed if f in alive)
    deps = set()
    for tok in {pathlib.PurePosixPath(f).stem for f in changed}:
        if not tok:
            continue
        word = re.compile(r"\b" + re.escape(tok) + r"\b")
        for f in cur["files"]:
            if f in changed:
                continue
            try:
                lines = pathlib.Path(root, f).read_text(errors="ignore").splitlines()
            except OSError:
                continue
            if any(IMPORT_RE.match(ln) and word.search(ln) for ln in lines):
                deps.add(f)
    read_set = sorted(set(changed) | deps)
    if len(read_set) > READ_CAP:
        out({"mode": "FULL", "reason": f"read set {len(read_set)} > {READ_CAP}"})
        return 3
    res = {"mode": "INCR", "base": st["data"]["last_sha"], "head": head, "changed": changed,
           "dependents": sorted(deps), "deleted": sorted(deleted), "read_set": read_set,
           "hashes": {f: cur["hashes"][f] for f in read_set}, "context": context(root, read_set)}
    write_json(p(root, "incr"), res)
    out(res)
    return 0


def load_state(root):
    path = p(root, "state")
    if not path.exists():
        return {"status": "missing"}
    try:
        data = json.loads(path.read_text())
        if data.get("schema") != 1 or not data.get("last_sha"):
            raise ValueError("bad schema")
        return {"status": "ok", "data": data}
    except (ValueError, json.JSONDecodeError):
        ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        path.rename(path.with_name(f"state.json.bad-{ts}"))
        return {"status": "corrupt"}


def save(root, mode, read_count=None):
    """FULL: every non-SQL file read at its current hash. INCR: read count equals the read set."""
    root = str(pathlib.Path(root).resolve())
    d = discover(root)
    res = {}
    if mode == "FULL":
        expected = len(non_sql(d))
        done = progress_done(root, d)
        pending = [f for f in non_sql(d) if f not in done]
        if pending:
            out({"saved": False, "reason": f"{len(pending)} of {expected} files not read at current hash",
                 "pending": pending[:20]})
            return 4
        if read_count is not None and read_count != expected:
            res["warning"] = f"N={read_count} differs from {expected} non-SQL files; progress is complete"
    else:
        expected = len(read_json(p(root, "incr"), {"read_set": []})["read_set"])
        if read_count != expected:
            out({"saved": False, "reason": f"read {read_count} of {expected}; state kept"})
            return 4
    head = git(root, "rev-parse", "HEAD")[1].strip() or "no-git"
    write_json(p(root, "state"), {"schema": 1, "last_sha": head, "mode": mode, "last_run": tools.utc_now(),
                                  "files": d["hashes"]})
    out({"saved": True, "files": len(d["hashes"]), **res})
    return 0


# ---------------------------------------------------------------- ids and verdicts

def _hid(*parts, n=12):
    return "F-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:n]


def finding_id(source, cls, path, key, taken):
    base = _hid(source, cls, path, key)
    fid, n = base, 2
    while fid in taken:
        fid, n = f"{base}-{n}", n + 1
    taken.add(fid)
    return fid


def assign_ids(root, cands):
    """Ids in start-line order, so duplicate keys get stable -2, -3 suffixes. legacy_id = the v2 4-hex id."""
    taken = set()
    for c in sorted(cands, key=lambda c: (c["file"], symbols.start_line(c["lines"]))):
        if c["source"] == "agent":
            key = symbols.enclosing(root, c["file"], symbols.start_line(c["lines"]))
            legacy_key = c["evidence"]
        else:
            key = legacy_key = c["fp"]
        c["id"] = finding_id(c["source"], c["class"], c["file"], key, taken)
        c["legacy_id"] = _hid("gitleaks" if c["source"] == "gitleaks-history" else c["source"],
                              c["class"], c["file"], legacy_key, n=4)
    return cands


def apply_verdicts(root, findings):
    v = read_json(p(root, "verdicts"), {})
    migrated = False
    for f in findings:
        rec = v.get(f["id"])
        if rec is None and f.get("legacy_id") in v:
            rec = dict(v[f["legacy_id"]], migrated_from=f["legacy_id"])
            v[f["id"]] = rec
            migrated = True
        f["verdict"] = rec["verdict"] if rec else "new"
        f["reason"] = rec.get("reason", "") if rec else ""
    if migrated:
        write_json(p(root, "verdicts"), v)
    return findings


def source_of(f):
    s = f.get("source", "agent")
    return "gitleaks-history" if s == "gitleaks" and f.get("scope") == "history" else s


# ---------------------------------------------------------------- merge (agent findings)

def norm(s):
    return " ".join(str(s).split())


def check_candidate(root, c):
    """Reason string when the candidate cannot be verified, else None."""
    missing = next((k for k in REQUIRED if not str(c.get(k, "")).strip()), None)
    if missing:
        return f"missing:{missing}"
    path = pathlib.Path(root, c["file"])
    if not path.is_file():
        return "no-such-file"
    text = path.read_text(errors="ignore")
    if norm(c["evidence"]) not in norm(text):
        return "evidence-not-in-file"
    if not 1 <= symbols.start_line(c["lines"]) <= max(1, len(text.splitlines())):
        return "bad-lines"
    if not 10 <= len(c["control_checked"]) <= 300:
        return "no-control-check"
    return None


def evidence_present(root, rel, evidence):
    try:
        return norm(evidence) in norm(pathlib.Path(root, rel).read_text(errors="ignore"))
    except OSError:
        return False


def merge(root, candidates_file, scope_file=None):
    """Agent findings. Only findings in the scope read_set (or in deleted files) may become fixed."""
    root = str(pathlib.Path(root).resolve())
    cands = json.loads(pathlib.Path(candidates_file).read_text())
    prev = {f["id"]: f for f in read_json(p(root, "findings"), [])}
    scope = set(read_json(scope_file, {"read_set": []})["read_set"]) if scope_file else None
    rejected, good = [], []
    for i, c in enumerate(cands):
        why = check_candidate(root, c)
        if why:
            rejected.append({"index": i, "file": c.get("file", ""), "reason": why})
            continue
        good.append({"source": "agent", "class": c["class"], "owasp": c.get("owasp", ""),
                     "severity": c.get("severity", "medium"), "confidence": c.get("confidence", "likely"),
                     "scope": "current", "file": c["file"], "lines": c["lines"], "evidence": c["evidence"],
                     "symbol": c.get("symbol", ""), "control_checked": c["control_checked"],
                     "fix_hint": c.get("fix_hint", "")})
    assign_ids(root, good)
    for f in good:
        f["status"] = "open" if f["id"] in prev else "new"
    now = {f["id"] for f in good}
    fixed, carried = [], []
    for i, f in prev.items():
        if i in now or source_of(f) in TOOL_SOURCES:
            continue
        if not pathlib.Path(root, f["file"]).exists():
            fixed.append(dict(f, status="fixed", fixed_reason="file deleted"))
        elif (scope is None or f["file"] in scope) and not evidence_present(root, f["file"], f["evidence"]):
            fixed.append(dict(f, status="fixed", fixed_reason="evidence gone from file"))
        else:
            carried.append(dict(f, status="open"))
    tool_prev = [f for f in prev.values() if source_of(f) in TOOL_SOURCES]   # tools own their status
    everything = apply_verdicts(root, good + carried + tool_prev)
    write_json(p(root, "findings"), everything)
    notes = [f"Fixed in this merge: {len(fixed)}.", f"Merge rejected {len(rejected)} candidates (not verifiable)."]
    tools.build_html(everything + apply_verdicts(root, fixed), {"repo": pathlib.Path(root).name, "mode": "REVIEW",
                     "date": tools.utc_now(), "scanners": "agent review, saved tool results"},
                     notes, p(root, "report"), root)
    print(json.dumps({"findings": everything, "fixed": fixed, "rejected": rejected}, indent=2))
    return 0


# ---------------------------------------------------------------- tools

def sql_scan(root, cfg):
    """SQL replay over every non-vendored migrations folder. Meta values are summed."""
    meta, found, rows = {"folders": 0}, [], []
    for m in sorted(pathlib.Path(root).rglob("migrations")):
        rp = tools.rel(root, m)
        if not m.is_dir() or not any(m.glob("*.sql")) or config.vendor_skipped(rp + "/x", cfg):
            continue
        f, mm = sql_state.findings(str(m), cfg)
        for x in f:
            x["file"] = f"{rp}/{x['file']}"
        found += f
        rows += sql_state.table_rows(str(m), cfg)
        meta["folders"] += 1
        for k, v in mm.items():
            meta[k] = meta.get(k, 0) + v if isinstance(v, (int, float)) else v
    return "ran", found, meta, rows


def status_note(name, st, cfg):
    if st == "ran":
        return f"{name}: ran"
    if st == "off":
        return f"{name}: off"
    if st == "timeout":
        key = name.replace("-", "_")
        return f"{name}: NOT RUN (timeout after {cfg.get('timeout_' + key, 600)} s)"
    if st == "missing" and name.startswith("live"):
        return f"{name}: NOT RUN ({'psql not installed' if name == 'live-catalog' else 'no URL or anon key; see [live] in config.toml'})"
    if st == "missing":
        return f"{name}: NOT RUN (missing; install: {tools.PREREQ_HINT})"
    return f"{name}: NOT RUN (error)"


def scan_tools(root, history=True, fail_on="none", force_live=False):
    """Run every scanner, the SQL replay and live checks. Tool results replace earlier results of tools that ran."""
    root = str(pathlib.Path(root).resolve())
    cfg = config.load(root)
    if force_live:
        cfg["live"]["enabled"] = True
    prev = read_json(p(root, "findings"), [])
    ran, cands = {}, []
    jobs = {"osv": lambda: tools.osv_findings(root, cfg),
            "gitleaks": lambda: tools.gitleaks_findings(root, cfg, history=False),
            "gitleaks-history": (lambda: tools.gitleaks_findings(root, cfg, history=True)) if history and is_git(root)
            else (lambda: ("off", [])),
            "semgrep": lambda: tools.semgrep_findings(root, cfg),
            "config": lambda: tools.config_findings(root, cfg),
            "zizmor": lambda: tools.zizmor_findings(root, cfg),
            "trivy": lambda: tools.trivy_findings(root, cfg)}
    for name, job in jobs.items():
        ran[name], f = job()
        cands += f
    ran["sql"], sql_f, sql_meta, sql_rows = sql_scan(root, cfg)
    cands += sql_f
    assign_ids(root, cands)
    live_st, live_f, drop, live_notes = live.run(root, cfg, sql_f, sql_rows)
    ran.update(live_st)
    ran["live"] = "ran" if "ran" in live_st.values() else "off"
    cands = [c for c in cands if c["id"] not in drop] + assign_ids(root, live_f)
    prev_ids = {f["id"] for f in prev}
    now = {c["id"] for c in cands}
    fresh = [dict(c, status="open" if c["id"] in prev_ids else "new") for c in cands]
    fixed, carried = [], []
    for f in prev:
        src = source_of(f)
        if src not in TOOL_SOURCES or f["id"] in now:
            continue
        (fixed if ran.get(src) == "ran" else carried).append(dict(f, source=src, status="fixed" if ran.get(src) == "ran" else "open"))
    agents = [f for f in prev if source_of(f) not in TOOL_SOURCES]
    findings = apply_verdicts(root, fresh + carried + agents)
    write_json(p(root, "findings"), findings)
    d = pathlib.Path(root, ".cybersec", "reports", datetime.date.today().isoformat() + "-tools")
    everything = findings + apply_verdicts(root, fixed)
    write_json(d / "findings.json", everything)
    write_json(d / "sql_tables.json", sql_rows)
    rel_total = sql_meta.get("relevant", 0)
    notes = [status_note(k, v, cfg) for k, v in ran.items()]
    notes += [f"SQL replay: {sql_meta.get('tables', 0)} tables in {sql_meta['folders']} folders, "
              f"{sql_meta.get('tenant_tables', 0)} with tenant columns, {sql_meta.get('do_expanded', 0)} DO loops expanded, "
              f"{sql_meta.get('unparsed', 0)} relevant statements not parsed"
              + (f" ({100 * sql_meta.get('unparsed', 0) / rel_total:.1f}%)." if rel_total else "."),
              *live_notes, *([tools.enrich.LAST_NOTE] if tools.enrich.LAST_NOTE else []),
              "Skipped paths: see .cybersec/config.toml.",
              f"Agent findings carried over: {len(agents)}. Fixed since last tool run: {len(fixed)}."]
    warnings = [n for n in notes if "NOT RUN" in n]
    if warnings:
        warnings = [f"{len(warnings)} tools did not run. Their earlier findings stay open. " + " ".join(warnings)]
    meta = {"repo": pathlib.Path(root).name, "mode": "TOOLS", "date": tools.utc_now(),
            "scanners": ", ".join(k for k, v in ran.items() if v == "ran")}
    for path in (d / "report.html", p(root, "report")):
        tools.build_html(everything, meta, notes, path, root, warnings)
    hot = [f for f in fresh if f["status"] == "new" and f["verdict"] == "new"
           and SEV_RANK.get(f["severity"], 9) <= SEV_RANK.get(fail_on, -1)]
    rc = 6 if hot else 0
    out({"ran": ran, "new": sum(f["status"] == "new" for f in fresh), "open": len(findings), "fixed": len(fixed),
         "new_high_or_critical": sum(f["status"] == "new" and f["verdict"] == "new" and SEV_RANK.get(f["severity"], 9) <= 1
                                     for f in fresh),
         "report": str(p(root, "report")), "exit": rc})
    return rc


# ---------------------------------------------------------------- batches

def progress(root):
    prog = read_json(p(root, "progress"), {})
    return prog if prog.get("schema") == 2 else {"schema": 2, "started": tools.utc_now(), "batches": 0, "read": {}}


def progress_done(root, d):
    read = progress(root)["read"]
    return {f for f in non_sql(d) if read.get(f) == d["hashes"][f]}


def batch_reset(root):
    for k in ("progress", "batch"):
        p(root, k).unlink(missing_ok=True)
    out({"reset": True})
    return 0


def context(root, read_set):
    """What the agent gets with a read set: the newest table inventory and open tool findings in those files."""
    tables = sorted(pathlib.Path(root, ".cybersec", "reports").glob("*-tools/sql_tables.json"))
    rs = set(read_set)
    return {"sql_tables": str(tables[-1]) if tables else None,
            "tool_findings": [{k: f[k] for k in ("id", "source", "class", "file", "lines")}
                              for f in read_json(p(root, "findings"), [])
                              if source_of(f) in TOOL_SOURCES and f["file"] in rs]}


def batch_next(root, max_files=FULL_CAP, priority_only=False, max_bytes=None):
    """Next unread files (current hash not yet read), by bytes, imports grouped. SQL is excluded: the replay reads it."""
    root = str(pathlib.Path(root).resolve())
    d = discover(root)
    prog, done = progress(root), progress_done(root, d)
    todo = [f for f in non_sql(d) if f not in done]
    sizes = {f: pathlib.Path(root, f).stat().st_size for f in todo}
    if priority_only:
        todo = [f for f in todo if batching.rank(f, batching.score(batching.read(root, f))) == 0]
    pick, info, used, est = batching.plan(root, todo, sizes, max_bytes or batching.MAX_BYTES, min(max_files, FULL_CAP))
    batch = {"read_set": pick, "batch": prog["batches"] + 1, "bytes": used, "files": info, "context": context(root, pick)}
    write_json(p(root, "batch"), batch)
    out({"batch": batch["batch"], "files": len(pick), "bytes": used, "batches_estimate": est,
         "remaining_in_scope": len(todo) - len(pick), "sql_replay_only": sum(f.endswith(".sql") for f in d["files"]),
         "total": d["count"], "skipped": len(d["skipped"]), "read_set": pick})
    return 0


def batch_done(root):
    root = str(pathlib.Path(root).resolve())
    b = read_json(p(root, "batch"), None)
    if b is None:
        out({"ok": False, "reason": "no batch.json; run batch-next first"})
        return 2
    d = discover(root)
    prog = progress(root)
    prog["read"].update({f: d["hashes"][f] for f in b["read_set"] if f in d["hashes"]})
    prog["batches"] = b["batch"]
    write_json(p(root, "progress"), prog)
    pending = [f for f in non_sql(d) if f not in progress_done(root, d)]
    out({"read": len(prog["read"]), "total": d["count"], "pending_non_sql": len(pending), "complete": not pending})
    return 0


def stats(root, md=False):
    """Verdict counts per source; precision = real / (real + false_positive). Fixed findings excluded."""
    rows = {}
    for f in read_json(p(root, "findings"), []):
        r = rows.setdefault(source_of(f), {"findings": 0, "real": 0, "false_positive": 0, "accepted_risk": 0, "unreviewed": 0})
        r["findings"] += 1
        r[f.get("verdict", "new") if f.get("verdict", "new") != "new" else "unreviewed"] += 1
    for r in rows.values():
        d = r["real"] + r["false_positive"]
        r["precision"] = f"{r['real'] / d:.2f}" if d else "n/a"
    if md:
        cols = ["findings", "real", "false_positive", "accepted_risk", "unreviewed", "precision"]
        print("| Source | " + " | ".join(cols) + " |\n|" + "---|" * (len(cols) + 1))
        for src, r in sorted(rows.items()):
            print(f"| {src} | " + " | ".join(str(r[c]) for c in cols) + " |")
    else:
        out(rows)
    return 0


def verdict(root, fid, value, reason=""):
    if value not in ("real", "false_positive", "accepted_risk", "new"):
        out({"ok": False, "reason": "value must be real, false_positive, accepted_risk, or new"})
        return 2
    v = read_json(p(root, "verdicts"), {})
    v[fid] = {"verdict": value, "reason": reason, "set": datetime.date.today().isoformat()}
    write_json(p(root, "verdicts"), v)
    out({"ok": True, "id": fid, "verdict": value})
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="cyber_state")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("live").add_argument("root")
    sub.add_parser("notify").add_argument("root")
    st = sub.add_parser("stats"); st.add_argument("root"); st.add_argument("--md", action="store_true")
    sa = sub.add_parser("sarif"); sa.add_argument("root"); sa.add_argument("out")
    for name in ("discover", "incr", "state", "batch-reset", "batch-done"):
        sub.add_parser(name).add_argument("root")
    s = sub.add_parser("save"); s.add_argument("root"); s.add_argument("mode"); s.add_argument("read_count", type=int, nargs="?")
    m = sub.add_parser("merge"); m.add_argument("root"); m.add_argument("candidates_file"); m.add_argument("--scope", default=None)
    t = sub.add_parser("tools"); t.add_argument("root"); t.add_argument("--no-history", action="store_true")
    t.add_argument("--fail-on", choices=["none", "critical", "high", "medium"], default="none")
    b = sub.add_parser("batch-next"); b.add_argument("root")
    b.add_argument("--max-files", "--size", dest="max_files", type=int, default=FULL_CAP)
    b.add_argument("--max-bytes", type=int, default=None)
    b.add_argument("--priority-only", action="store_true")
    b.add_argument("--all", action="store_true", help="deprecated: all files is the default now")
    v = sub.add_parser("verdict"); v.add_argument("root"); v.add_argument("id"); v.add_argument("value"); v.add_argument("reason", nargs="?", default="")
    sub.add_parser("prereqs")
    a = ap.parse_args(argv)
    if a.cmd == "discover":
        print(json.dumps(discover(a.root), indent=2)); return 0
    if a.cmd == "state":
        out(load_state(a.root)); return 0
    if a.cmd == "prereqs":
        out(tools.prereqs()); return 0
    return {
        "incr": lambda: incr(a.root),
        "save": lambda: save(a.root, a.mode, a.read_count),
        "merge": lambda: merge(a.root, a.candidates_file, a.scope),
        "tools": lambda: scan_tools(a.root, history=not a.no_history, fail_on=a.fail_on),
        "live": lambda: scan_tools(a.root, history=False, force_live=True),
        "notify": lambda: out(notify.run(a.root, read_json(p(a.root, "findings"), []))) or 0,
        "stats": lambda: stats(a.root, a.md),
        "sarif": lambda: write_json(a.out, sarif.build(read_json(p(a.root, "findings"), []))) or 0,
        "batch-reset": lambda: batch_reset(a.root),
        "batch-next": lambda: batch_next(a.root, a.max_files, a.priority_only, a.max_bytes),
        "batch-done": lambda: batch_done(a.root),
        "verdict": lambda: verdict(a.root, a.id, a.value, a.reason),
    }[a.cmd]()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
