#!/usr/bin/env python3
"""cybersec-scan helper. Stdlib only.

  discover ROOT                      file list, skip rules, coverage
  incr ROOT                          read set since saved state (exit 3 = run FULL)
  state ROOT                         saved state: ok | missing | corrupt
  save ROOT MODE N                   save state if N files were read (4 = partial, 5 = over cap)
  merge ROOT CANDIDATES [--scope F]  merge agent findings; apply verdicts
  tools ROOT [--no-history]          run osv-scanner, gitleaks, semgrep, SQL replay; write report
  batch-next ROOT [--size 150]       choose the next unread files (auth and tenant code first)
  batch-done ROOT                    mark the last batch read
  verdict ROOT ID VALUE [REASON]     set real | false_positive | accepted_risk for a finding
  prereqs                            tool paths
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
import config  # noqa: E402
import sql_state  # noqa: E402
import tools  # noqa: E402

FULL_CAP = 150          # max files per batch; a batch is one agent run
READ_CAP = 200          # incremental read set cap
TOOL_SOURCES = ("osv", "gitleaks", "semgrep", "sql")
STATE_REL = pathlib.PurePosixPath(".cybersec/state.json")
FINDINGS_REL = pathlib.PurePosixPath(".cybersec/last_findings.json")
SCOPE_REL = pathlib.PurePosixPath(".cybersec/incr.json")
BATCH_REL = pathlib.PurePosixPath(".cybersec/batch.json")
PROGRESS_REL = pathlib.PurePosixPath(".cybersec/progress.json")
VERDICT_REL = pathlib.PurePosixPath(".cybersec/verdicts.json")
PRIORITY = re.compile(r"auth|session|jwt|tenant|org|workspace|role|permission|admin|webhook|invite|token|middleware|route|api|rls|policy", re.I)
IMPORT_RE = re.compile(r"^\s*(import\b|from\b|require\(|#include\b|use\b|@import\b)")


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
    return [str(p.relative_to(root)) for p in pathlib.Path(root).rglob("*") if p.is_file()]


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


def stem(rel):
    return pathlib.PurePosixPath(rel).stem


def incr(root):
    root = str(pathlib.Path(root).resolve())
    st = load_state(root)
    if st["status"] != "ok":
        print(json.dumps({"mode": "FULL", "reason": "state " + st["status"]}))
        return 3
    if not is_git(root):
        print(json.dumps({"mode": "FULL", "reason": "not a git repo"}))
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
    for tok in {stem(f) for f in changed}:
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
        print(json.dumps({"mode": "FULL", "reason": f"read set {len(read_set)} > {READ_CAP}"}))
        return 3
    res = {"mode": "INCR", "base": st["data"]["last_sha"], "head": head, "changed": changed,
           "dependents": sorted(deps), "deleted": sorted(deleted), "read_set": read_set,
           "hashes": {f: cur["hashes"][f] for f in read_set}}
    pathlib.Path(root, SCOPE_REL).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(root, SCOPE_REL).write_text(json.dumps(res, indent=2))
    print(json.dumps(res))
    return 0


def load_state(root):
    p = pathlib.Path(root, STATE_REL)
    if not p.exists():
        return {"status": "missing"}
    try:
        data = json.loads(p.read_text())
        if data.get("schema") != 1 or not data.get("last_sha"):
            raise ValueError("bad schema")
        return {"status": "ok", "data": data}
    except (ValueError, json.JSONDecodeError):
        ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        p.rename(p.with_name(f"state.json.bad-{ts}"))
        return {"status": "corrupt"}


def save(root, mode, read_count):
    """Store state only when every file in the scope was read (FULL) or the read set was read (INCR)."""
    root = str(pathlib.Path(root).resolve())
    d = discover(root)
    if mode == "FULL":
        expected = d["count"]
    else:
        expected = len(json.loads(pathlib.Path(root, SCOPE_REL).read_text())["read_set"])
    if read_count != expected:
        print(json.dumps({"saved": False, "reason": f"read {read_count} of {expected}; state kept"}))
        return 4
    head = git(root, "rev-parse", "HEAD")[1].strip()
    body = {"schema": 1, "last_sha": head, "mode": mode,
            "last_run": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": d["hashes"]}
    p = pathlib.Path(root, STATE_REL)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name("state.json.tmp")
    tmp.write_text(json.dumps(body, indent=2))
    os.replace(tmp, p)
    print(json.dumps({"saved": True, "files": len(d["hashes"])}))
    return 0


def finding_id(source, cls, path, fp, taken):
    base = "F-" + hashlib.sha1(f"{source}|{cls}|{path}|{fp}".encode()).hexdigest()[:4]
    fid, n = base, 2
    while fid in taken:
        fid, n = f"{base}-{n}", n + 1
    taken.add(fid)
    return fid


def _verdicts(root):
    p = pathlib.Path(root, VERDICT_REL)
    return json.loads(p.read_text()) if p.exists() else {}


def apply_verdicts(root, findings):
    v = _verdicts(root)
    for f in findings:
        rec = v.get(f["id"])
        f["verdict"] = rec["verdict"] if rec else "new"
        f["reason"] = rec.get("reason", "") if rec else ""
    return findings


def evidence_present(root, rel, evidence):
    """A finding is fixed only when its evidence text is gone from the file."""
    try:
        return evidence.strip() in pathlib.Path(root, rel).read_text(errors="ignore")
    except OSError:
        return False


def merge(root, candidates_file, scope_file=None):
    """Agent findings. scope_file (incr.json or batch.json): only findings in its read_set may become fixed."""
    root = str(pathlib.Path(root).resolve())
    cands = json.loads(pathlib.Path(candidates_file).read_text())
    prev_path = pathlib.Path(root, FINDINGS_REL)
    prev = {f["id"]: f for f in json.loads(prev_path.read_text())} if prev_path.exists() else {}
    scope = set(json.loads(pathlib.Path(scope_file).read_text())["read_set"]) if scope_file else None
    taken, out = set(), []
    for c in cands:
        fid = finding_id("agent", c["class"], c["file"], c["evidence"], taken)
        out.append({"id": fid, "source": "agent", "class": c["class"], "owasp": c.get("owasp", ""),
                    "severity": c.get("severity", "medium"), "confidence": c.get("confidence", "likely"),
                    "scope": "current", "file": c["file"], "lines": c["lines"], "evidence": c["evidence"],
                    "fp": c["evidence"], "fix_hint": c.get("fix_hint", ""),
                    "status": "open" if fid in prev else "new"})
    now = {f["id"] for f in out}
    fixed, carried = [], []
    for i, f in prev.items():
        if i in now or f.get("source", "agent") in TOOL_SOURCES:
            continue
        in_scope = scope is None or f["file"] in scope
        if in_scope and not evidence_present(root, f["file"], f["evidence"]):
            fixed.append(dict(f, status="fixed"))
        else:
            carried.append(dict(f, status="open"))
    tool_prev = [dict(f, status="open") for f in prev.values() if f.get("source") in TOOL_SOURCES]
    everything = apply_verdicts(root, out + carried + tool_prev)
    prev_path.parent.mkdir(parents=True, exist_ok=True)
    prev_path.write_text(json.dumps(everything, indent=2))
    tools.build_html(everything, {"repo": pathlib.Path(root).name, "mode": "REVIEW", "date": tools.utc_now(),
                                  "scanners": "agent review, saved tool results"},
                     [f"Fixed in this merge: {len(fixed)}."], pathlib.Path(root, ".cybersec", "report.html"))
    print(json.dumps({"findings": everything, "fixed": fixed}, indent=2))
    return 0


def scan_tools(root, history=True):
    """Run every scanner and the SQL replay. Tool results replace earlier tool results."""
    root = str(pathlib.Path(root).resolve())
    cfg = config.load(root)
    prev_path = pathlib.Path(root, FINDINGS_REL)
    prev = json.loads(prev_path.read_text()) if prev_path.exists() else []
    ran = {}
    ran["osv"], osv = tools.osv_findings(root, cfg)
    ran["gitleaks"], gl = tools.gitleaks_findings(root, cfg, history=False)
    if history:
        ran["gitleaks-history"], glh = tools.gitleaks_findings(root, cfg, history=True)
    else:
        glh = []
    ran["semgrep"], sg = tools.semgrep_findings(root, cfg)
    sql, sql_meta = [], {}
    mig = [p for p in pathlib.Path(root).rglob("migrations") if p.is_dir() and any(p.glob("*.sql"))]
    if mig:
        sql, sql_meta = [], {}
        for m in mig:
            f, meta = sql_state.findings(str(m))
            sql += f
            sql_meta = meta
    ran["sql"] = True
    cands = osv + gl + glh + sg + sql
    taken, now, out = set(), set(), []
    for c in cands:
        fid = finding_id(c["source"], c["class"], c["file"], c["fp"], taken)
        now.add(fid)
        out.append(dict(c, id=fid, status="open" if any(p["id"] == fid for p in prev) else "new"))
    src_ran = {"osv": ran["osv"], "gitleaks": ran["gitleaks"], "semgrep": ran["semgrep"], "sql": True}
    fixed = []
    for f in prev:
        if f.get("source") not in TOOL_SOURCES or f["id"] in now:
            continue
        if src_ran.get(f["source"], False):
            fixed.append(dict(f, status="fixed"))
        else:
            out.append(dict(f, status="open"))
    out += [dict(f, status="open") for f in prev if f.get("source", "agent") == "agent"]
    out = apply_verdicts(root, out)
    prev_path.parent.mkdir(parents=True, exist_ok=True)
    prev_path.write_text(json.dumps(out, indent=2))
    d = pathlib.Path(root, ".cybersec", "reports", datetime.date.today().isoformat() + "-tools")
    d.mkdir(parents=True, exist_ok=True)
    everything = out + apply_verdicts(root, fixed)
    (d / "findings.json").write_text(json.dumps(everything, indent=2))
    notes = [f"{k}: {'ran' if v else 'NOT RUN (install: ' + tools.PREREQ_HINT + ')'}" for k, v in ran.items()]
    notes += [f"SQL replay: {sql_meta.get('tables', 0)} tables, {sql_meta.get('tenant_tables', 0)} with tenant columns, "
              f"{sql_meta.get('unparsed_statements', 0)} statements not parsed.",
              "Skipped paths: see .cybersec/config.toml.",
              f"Agent findings carried over: {sum(1 for f in out if f.get('source', 'agent') == 'agent')}. "
              f"Fixed since last tool run: {len(fixed)}."]
    tools.build_html(everything, {"repo": pathlib.Path(root).name, "mode": "TOOLS",
                                  "date": tools.utc_now(), "scanners": ", ".join(k for k, v in ran.items() if v)},
                     notes, d / "report.html")
    print(json.dumps({"ran": ran, "new": sum(f["status"] == "new" for f in out),
                      "open": sum(f["status"] == "open" for f in out), "fixed": len(fixed),
                      "report": str(d / "report.html")}))
    return 0


def batch_next(root, size):
    root = str(pathlib.Path(root).resolve())
    d = discover(root)
    prog_p = pathlib.Path(root, PROGRESS_REL)
    prog = json.loads(prog_p.read_text()) if prog_p.exists() else {"read": [], "batches": 0}
    done = set(prog["read"])
    todo = [f for f in d["files"] if f not in done]
    todo.sort(key=lambda f: (0 if PRIORITY.search(f) else 1, f))
    pick = todo[:min(size, FULL_CAP)]
    pathlib.Path(root, BATCH_REL).write_text(json.dumps({"read_set": pick, "batch": prog["batches"] + 1}, indent=2))
    print(json.dumps({"batch": prog["batches"] + 1, "files": len(pick), "remaining_after": len(todo) - len(pick),
                      "total": d["count"], "skipped": len(d["skipped"]), "read_set": pick}))
    return 0


def batch_done(root):
    root = str(pathlib.Path(root).resolve())
    b = json.loads(pathlib.Path(root, BATCH_REL).read_text())
    prog_p = pathlib.Path(root, PROGRESS_REL)
    prog = json.loads(prog_p.read_text()) if prog_p.exists() else {"read": [], "batches": 0}
    prog["read"] = sorted(set(prog["read"]) | set(b["read_set"]))
    prog["batches"] = b["batch"]
    prog_p.write_text(json.dumps(prog, indent=2))
    total = discover(root)["count"]
    print(json.dumps({"read": len(prog["read"]), "total": total, "complete": len(prog["read"]) >= total}))
    return 0


def verdict(root, fid, value, reason=""):
    if value not in ("real", "false_positive", "accepted_risk", "new"):
        print(json.dumps({"ok": False, "reason": "value must be real, false_positive, accepted_risk, or new"}))
        return 2
    p = pathlib.Path(root, VERDICT_REL)
    v = _verdicts(root)
    v[fid] = {"verdict": value, "reason": reason, "set": datetime.date.today().isoformat()}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(v, indent=2))
    print(json.dumps({"ok": True, "id": fid, "verdict": value}))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="cyber_state")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("discover").add_argument("root")
    sub.add_parser("incr").add_argument("root")
    sub.add_parser("state").add_argument("root")
    s = sub.add_parser("save"); s.add_argument("root"); s.add_argument("mode"); s.add_argument("read_count", type=int)
    m = sub.add_parser("merge"); m.add_argument("root"); m.add_argument("candidates_file"); m.add_argument("--scope", default=None)
    t = sub.add_parser("tools"); t.add_argument("root"); t.add_argument("--no-history", action="store_true")
    b = sub.add_parser("batch-next"); b.add_argument("root"); b.add_argument("--size", type=int, default=FULL_CAP)
    sub.add_parser("batch-done").add_argument("root")
    v = sub.add_parser("verdict"); v.add_argument("root"); v.add_argument("id"); v.add_argument("value"); v.add_argument("reason", nargs="?", default="")
    sub.add_parser("prereqs")
    a = ap.parse_args(argv)
    if a.cmd == "discover":
        print(json.dumps(discover(a.root), indent=2)); return 0
    if a.cmd == "incr":
        return incr(a.root)
    if a.cmd == "state":
        print(json.dumps(load_state(a.root))); return 0
    if a.cmd == "save":
        return save(a.root, a.mode, a.read_count)
    if a.cmd == "merge":
        return merge(a.root, a.candidates_file, a.scope)
    if a.cmd == "tools":
        return scan_tools(a.root, history=not a.no_history)
    if a.cmd == "batch-next":
        return batch_next(a.root, a.size)
    if a.cmd == "batch-done":
        return batch_done(a.root)
    if a.cmd == "verdict":
        return verdict(a.root, a.id, a.value, a.reason)
    print(json.dumps(tools.prereqs())); return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
