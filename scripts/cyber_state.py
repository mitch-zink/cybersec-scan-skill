#!/usr/bin/env python3
"""Deterministic helpers for cybersec-scan. Standard library only.

Subcommands (all print JSON to stdout):
  discover  ROOT                  file list, skip rules, per-dir coverage
  incr      ROOT                  read set since state.last_sha (exit 3 = run FULL)
  state     ROOT                  read state (status: ok | missing | corrupt)
  save      ROOT MODE N           write state only if N files were read (exit 4 if not, 5 if over cap)
  merge     ROOT CANDIDATES.json [--scope .cybersec/incr.json]
                                  ids and statuses vs last findings; fixed only inside scope
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

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "vendor",
             "__pycache__", ".venv", ".cybersec"}
SKIP_SUFFIXES = (".lock",)
MAX_BYTES = 300 * 1024
READ_CAP = 200
FULL_CAP = 150  # FULL refuses repos above this; a partial FULL is never saved
STATE_REL = pathlib.PurePosixPath(".cybersec/state.json")
FINDINGS_REL = pathlib.PurePosixPath(".cybersec/last_findings.json")
SCOPE_REL = pathlib.PurePosixPath(".cybersec/incr.json")
IMPORT_RE = re.compile(r"^\s*(import\b|from\b|require\(|#include\b|use\b|@import\b)")


def git(root, *args):
    r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    return r.returncode, r.stdout


def is_git(root):
    return git(root, "rev-parse", "--is-inside-work-tree")[0] == 0


def is_binary(path):
    with open(path, "rb") as fh:
        return b"\0" in fh.read(8000)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def skip_reason(rel):
    parts = pathlib.PurePosixPath(rel).parts
    if any(p in SKIP_DIRS for p in parts):
        return "skip-dir"
    if rel.endswith(SKIP_SUFFIXES):
        return "lock-file"
    return None


def tracked_files(root):
    if is_git(root):
        _, out = git(root, "ls-files")
        return [f for f in out.splitlines() if f]
    return [str(p.relative_to(root)) for p in pathlib.Path(root).rglob("*") if p.is_file()]


def discover(root):
    """Return scan files and coverage for every top-level entry."""
    root = str(pathlib.Path(root).resolve())
    files, skipped = [], {}
    for rel in tracked_files(root):
        reason = skip_reason(rel)
        full = pathlib.Path(root, rel)
        if reason is None and (not full.is_file() or full.stat().st_size > MAX_BYTES):
            reason = "too-large-or-missing"
        if reason is None and is_binary(full):
            reason = "binary"
        if reason:
            skipped[rel] = reason
        else:
            files.append(rel)
    top = {}
    for entry in sorted(os.listdir(root)):
        if entry in (".git",):
            continue
        under = [f for f in files if f == entry or f.startswith(entry + "/")]
        if under:
            top[entry] = {"status": "scanned", "files": len(under)}
        elif entry in SKIP_DIRS or entry.startswith("."):
            top[entry] = {"status": "skipped", "reason": "skip-dir or hidden"}
        else:
            top[entry] = {"status": "skipped", "reason": "no scannable files"}
    hashes = {f: sha256(pathlib.Path(root, f)) for f in files}
    return {"root": root, "git": is_git(root), "files": files, "count": len(files),
            "over_cap": len(files) > FULL_CAP, "skipped": skipped,
            "top_level": top, "hashes": hashes}


def stem(rel):
    return pathlib.PurePosixPath(rel).stem


def incr(root):
    root = str(pathlib.Path(root).resolve())
    state = load_state(root)
    if state["status"] != "ok":
        print(json.dumps({"mode": "FULL", "reason": "state " + state["status"]}))
        return 3
    if not is_git(root):
        print(json.dumps({"mode": "FULL", "reason": "not a git repo"}))
        return 3
    if discover(root)["over_cap"]:
        print(json.dumps({"mode": "REFUSED", "reason": f"over {FULL_CAP} files; scope to a smaller folder"}))
        return 5
    _, head = git(root, "rev-parse", "HEAD")
    head = head.strip()
    _, diff = git(root, "diff", "--name-status", state["data"]["last_sha"], "HEAD")
    changed, deleted = [], []
    for line in diff.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("D"):
            deleted.append(parts[1])
        else:
            changed.append(parts[-1])
    current = discover(root)
    alive = set(current["files"])
    changed = sorted(f for f in changed if f in alive)
    dependents = set()
    for tok in {stem(f) for f in changed}:
        if not tok:
            continue
        word = re.compile(r"\b" + re.escape(tok) + r"\b")
        for f in current["files"]:
            if f in changed:
                continue
            try:
                lines = pathlib.Path(root, f).read_text(errors="ignore").splitlines()
            except OSError:
                continue
            if any(IMPORT_RE.match(ln) and word.search(ln) for ln in lines):
                dependents.add(f)
    read_set = sorted(set(changed) | dependents)
    if len(read_set) > READ_CAP:
        print(json.dumps({"mode": "FULL", "reason": f"read set {len(read_set)} > {READ_CAP}"}))
        return 3
    res = {"mode": "INCR", "base": state["data"]["last_sha"], "head": head,
           "changed": changed, "dependents": sorted(dependents),
           "deleted": sorted(deleted), "read_set": read_set,
           "hashes": {f: current["hashes"][f] for f in read_set}}
    pathlib.Path(root, SCOPE_REL).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(root, SCOPE_REL).write_text(json.dumps(res, indent=2))
    print(json.dumps(res))
    return 0


def state_path(root):
    return pathlib.Path(root, STATE_REL)


def load_state(root):
    p = state_path(root)
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
    """Store state only when the agent read every file it was asked to read."""
    root = str(pathlib.Path(root).resolve())
    d = discover(root)
    if mode == "FULL" and d["over_cap"]:
        print(json.dumps({"saved": False, "reason": f"over {FULL_CAP} files"}))
        return 5
    expected = d["count"] if mode == "FULL" else len(json.loads(pathlib.Path(root, SCOPE_REL).read_text())["read_set"])
    if read_count != expected:
        print(json.dumps({"saved": False, "reason": f"read {read_count} of {expected}; state kept"}))
        return 4
    _, head = git(root, "rev-parse", "HEAD")
    head, hashes = head.strip(), d["hashes"]
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {"schema": 1, "last_sha": head, "mode": mode,
            "last_run": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": hashes}
    tmp = p.with_name("state.json.tmp")
    tmp.write_text(json.dumps(body, indent=2))
    os.replace(tmp, p)
    print(json.dumps({"saved": str(p), "files": len(hashes)}))
    return 0


def finding_id(cls, path, evidence, taken):
    base = "F-" + hashlib.sha1(f"{cls}|{path}|{evidence}".encode()).hexdigest()[:4]
    fid, n = base, 2
    while fid in taken:
        fid, n = f"{base}-{n}", n + 1
    taken.add(fid)
    return fid


def evidence_present(root, rel, evidence):
    """A finding counts as fixed only when its evidence text is gone from the file."""
    try:
        text = pathlib.Path(root, rel).read_text(errors="ignore")
    except OSError:
        return False
    return evidence.strip() in text


def merge(root, candidates_file, scope_file=None):
    """scope_file: incr.json. Only findings in its read_set can become fixed.
    No scope_file = FULL scan: every file was read."""
    root = str(pathlib.Path(root).resolve())
    cands = json.loads(pathlib.Path(candidates_file).read_text())
    prev_path = pathlib.Path(root, FINDINGS_REL)
    prev = {f["id"]: f for f in json.loads(prev_path.read_text())} if prev_path.exists() else {}
    scope = set(json.loads(pathlib.Path(scope_file).read_text())["read_set"]) if scope_file else None
    taken, out = set(), []
    for c in cands:
        fid = finding_id(c["class"], c["file"], c["evidence"], taken)
        out.append({"id": fid, "class": c["class"], "owasp": c.get("owasp", ""),
                    "severity": c.get("severity", "medium"), "confidence": c.get("confidence", "likely"),
                    "file": c["file"], "lines": c["lines"], "evidence": c["evidence"],
                    "fix_hint": c.get("fix_hint", ""),
                    "status": "open" if fid in prev else "new"})
    now_ids = {f["id"] for f in out}
    fixed, carried = [], []
    for i, f in prev.items():
        if i in now_ids:
            continue
        in_scope = scope is None or f["file"] in scope
        gone = not evidence_present(root, f["file"], f["evidence"])
        if in_scope and gone:
            fixed.append(dict(f, status="fixed"))
        else:
            carried.append(dict(f, status="open"))
    out += carried
    prev_path.parent.mkdir(parents=True, exist_ok=True)
    prev_path.write_text(json.dumps(out, indent=2))
    print(json.dumps({"findings": out, "fixed": fixed}, indent=2))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="cyber_state")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("discover").add_argument("root")
    sub.add_parser("incr").add_argument("root")
    sub.add_parser("state").add_argument("root")
    s = sub.add_parser("save")
    s.add_argument("root")
    s.add_argument("mode")
    s.add_argument("read_count", type=int)
    m = sub.add_parser("merge")
    m.add_argument("root")
    m.add_argument("candidates_file")
    m.add_argument("--scope", default=None)
    a = ap.parse_args(argv)
    if a.cmd == "discover":
        print(json.dumps(discover(a.root), indent=2))
        return 0
    if a.cmd == "incr":
        return incr(a.root)
    if a.cmd == "state":
        st = load_state(a.root)
        print(json.dumps(st))
        return 0
    if a.cmd == "save":
        return save(a.root, a.mode, a.read_count)
    return merge(a.root, a.candidates_file, a.scope)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
