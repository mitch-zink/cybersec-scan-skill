"""External scanners: osv-scanner (dependency CVEs), gitleaks (secrets), semgrep (code rules).
Stdlib only. Secret values are never stored: gitleaks runs with --redact and only rule, file, line are kept."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

import config

HERE = pathlib.Path(__file__).resolve().parent
RULES = HERE.parent / "rules" / "semgrep.yml"
PREREQ_HINT = "brew install osv-scanner gitleaks semgrep"
SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
TOOLS = ("osv-scanner", "gitleaks", "semgrep")


def prereqs():
    found = {t: shutil.which(t) for t in TOOLS}
    return {"tools": found, "missing": [t for t, p in found.items() if not p], "install": PREREQ_HINT}


def _run(cmd, out_flag, timeout=1800):
    """Run cmd, writing JSON to a temp file. Returns (returncode, parsed JSON or None)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    argv = cmd + ([out_flag] if out_flag else []) + [path]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    data = None
    try:
        data = json.loads(pathlib.Path(path).read_text()) if os.path.getsize(path) else None
    except (OSError, json.JSONDecodeError):
        data = None
    pathlib.Path(path).unlink(missing_ok=True)
    return r.returncode, data


def _rel(root, p):
    try:
        return str(pathlib.Path(p).resolve().relative_to(pathlib.Path(root).resolve()))
    except ValueError:
        return str(p)


def _npm_scope(lockfile, name):
    """'prod' if the package is not dev-only in this npm lockfile, 'dev' if dev-only, else 'unknown'."""
    try:
        pk = json.loads(pathlib.Path(lockfile).read_text()).get("packages", {})
    except (OSError, json.JSONDecodeError):
        return "unknown"
    entries = [v for k, v in pk.items() if k.endswith("node_modules/" + name)]
    if not entries:
        return "unknown"
    return "prod" if any(not (v.get("dev") or v.get("devOptional")) for v in entries) else "dev"


def osv_findings(root, cfg):
    """Dependency CVEs, medium and above. Returns (ran, findings)."""
    if not shutil.which("osv-scanner"):
        return False, []
    rc, data = _run(["osv-scanner", "scan", "source", "-r", "--format", "json", str(root)], "--output-file")
    if data is None:
        return rc in (0, 1, 128), []     # 1 = found, 128 = no lockfiles
    out = []
    for res in data.get("results", []):
        src = res.get("source", {}).get("path", "?")
        rel = _rel(root, src)
        if config.path_skipped(rel, cfg):
            continue
        for pkg in res.get("packages", []):
            name, ver = pkg["package"]["name"], pkg["package"]["version"]
            scope = _npm_scope(src, name) if src.endswith("package-lock.json") else "unknown"
            for v in pkg.get("vulnerabilities", []):
                sev = SEV_MAP.get(str(v.get("database_specific", {}).get("severity", "")).upper(), "medium")
                if sev == "low":
                    continue
                cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v["id"])
                out.append({"source": "osv", "owasp": "A03", "class": cve, "severity": sev,
                            "confidence": "confirmed", "scope": scope, "file": rel, "lines": "-",
                            "evidence": f"{name}@{ver} {cve}", "fp": f"{name}@{ver}",
                            "fix_hint": f"Upgrade {name} past {ver}. {v.get('summary', '')}".strip()})
    return True, out


def gitleaks_findings(root, cfg, history):
    """Secrets. history=False: current files (current line numbers). history=True: git history."""
    if not shutil.which("gitleaks"):
        return False, []
    conf = config.gitleaks_config(root, cfg)
    mode = ["git"] if history else ["dir"]
    rc, data = _run(["gitleaks", *mode, str(root), "-c", conf, "--redact", "--no-banner", "-f", "json", "-r"], "", timeout=1800)
    if rc not in (0, 1) or (rc == 1 and data is None):   # 1 = leaks found; 1 with no output = config error
        return False, []
    out = []
    for f in data or []:
        rel = f.get("File", "?")
        if config.path_skipped(rel, cfg):
            continue
        scope = "history" if history else "current"
        hint = "Remove the secret and rotate it." + (" The value is in git history: rotate it even after removal." if history else "")
        out.append({"source": "gitleaks", "owasp": "A02", "class": "CWE-798", "severity": "high",
                    "confidence": "confirmed", "scope": scope, "file": rel,
                    "lines": f"{f.get('StartLine', '?')}-{f.get('EndLine', '?')}",
                    "evidence": f"{f.get('RuleID', 'secret')} {rel}:{f.get('StartLine', '?')}",
                    "fp": f"{f.get('RuleID', '')}:{f.get('Fingerprint', '')}",
                    "fix_hint": hint})
    return True, out


def semgrep_findings(root, cfg):
    """Code rules from rules/semgrep.yml. Returns (ran, findings)."""
    if not shutil.which("semgrep"):
        return False, []
    skip = [a for a in ("--exclude=" + d for d in config.ALWAYS_DIRS)]
    rc, data = _run(["semgrep", "--config", str(RULES), "--json", "--metrics=off", "--quiet", *skip, str(root)], "--output")
    if data is None:
        return False, []
    out = []
    for r in data.get("results", []):
        rel = _rel(root, r.get("path", "?"))
        if config.path_skipped(rel, cfg):
            continue
        meta = r.get("extra", {}).get("metadata", {})
        line = r.get("start", {}).get("line", "?")
        cid = r.get("check_id", "rule").split(".")[-1]
        out.append({"source": "semgrep", "owasp": meta.get("owasp", ""), "class": meta.get("cwe", cid),
                    "severity": r.get("extra", {}).get("severity", "WARNING").lower().replace("warning", "medium").replace("error", "high"),
                    "confidence": "confirmed", "scope": "current", "file": rel,
                    "lines": f"{line}-{r.get('end', {}).get('line', line)}",
                    "evidence": f"{cid} {rel}:{line}",
                    "fp": f"{cid}|{rel}|{hashlib.sha1(r.get('extra', {}).get('lines', '').encode()).hexdigest()}",
                    "fix_hint": meta.get("fix", r.get("extra", {}).get("message", ""))})
    return True, out


SEV_ORDER = ["critical", "high", "medium", "low"]
VERDICTS = ["new", "real", "accepted_risk", "false_positive"]


def utc_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def html_report(findings, meta, notes, max_rows=500):
    """One static page. Verdict changes are made with the CLI command shown on each row."""
    import html as H
    visible = [f for f in findings if f.get("verdict") != "false_positive"]
    hidden = len(findings) - len(visible)
    visible.sort(key=lambda f: (SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 9, f.get("id", "")))
    rows = []
    for f in visible[:max_rows]:
        cmd = f"python3 scripts/cyber_state.py verdict . {f.get('id', '?')} real"
        rows.append(
            f'<tr data-sev="{H.escape(f["severity"])}" data-src="{H.escape(f.get("source", "agent"))}">'
            f'<td><span class="sev {H.escape(f["severity"])}">{H.escape(f["severity"])}</span></td>'
            f'<td>{H.escape(f["class"])}</td><td>{H.escape(f.get("owasp", ""))}</td>'
            f'<td>{H.escape(f.get("source", "agent"))}</td><td>{H.escape(f.get("scope", ""))}</td>'
            f'<td><code>{H.escape(f["file"])}</code> {H.escape(str(f["lines"]))}</td>'
            f'<td><code>{H.escape(f["evidence"])}</code></td>'
            f'<td>{H.escape(f.get("fix_hint", ""))}</td>'
            f'<td>{H.escape(f.get("verdict", "new"))} <button data-cmd="{H.escape(cmd)}" onclick="cp(this)">copy verdict cmd</button></td></tr>')
    counts = {s: sum(1 for f in visible if f["severity"] == s) for s in SEV_ORDER}
    cards = "".join(f'<div class="card"><b>{counts[s]}</b><span class="sev {s}">{s}</span></div>' for s in SEV_ORDER)
    note_items = "".join(f"<li>{H.escape(n)}</li>" for n in notes)
    more = f"<p>{len(visible) - max_rows} more rows not shown. Use the CLI report.</p>" if len(visible) > max_rows else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan: {H.escape(meta['repo'])}</title>
<style>
body{{font:14px -apple-system,system-ui,sans-serif;margin:24px;color:#1d2330;background:#f7f8fb}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#5b6577;margin-bottom:16px}}
.cards{{display:flex;gap:12px;margin:12px 0}} .card{{background:#fff;border:1px solid #d9dee8;border-radius:8px;padding:10px 14px;min-width:90px}}
.card b{{display:block;font-size:22px}} .sev{{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}}
.critical{{background:#7a1020}} .high{{background:#c2410c}} .medium{{background:#b45309}} .low{{background:#4b5563}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px}} th,td{{border:1px solid #d9dee8;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#eef1f7}} code{{font-size:12px}} button{{font-size:11px}} .notes{{color:#5b6577;font-size:12px}}
@media (prefers-color-scheme: dark){{body{{color:#e6e9f0;background:#14171f}} .card,table{{background:#1d2330}} th{{background:#252c3b}} th,td,.card{{border-color:#2e3646}}}}
</style></head><body>
<h1>Security scan: {H.escape(meta['repo'])}</h1>
<div class="sub">Mode: {H.escape(meta['mode'])} · Date: {H.escape(meta['date'])} · Scanners: {H.escape(meta['scanners'])} · Hidden as false positive: {hidden}</div>
<div class="cards">{cards}</div>
<label>Severity <select id="f"><option value="">all</option>{''.join(f'<option>{s}</option>' for s in SEV_ORDER)}</select></label>
<table><thead><tr><th>Severity</th><th>Class</th><th>OWASP 2025</th><th>Source</th><th>Scope</th><th>File</th><th>Evidence</th><th>Fix</th><th>Verdict</th></tr></thead>
<tbody id="rows">{''.join(rows)}</tbody></table>{more}
<h3>Coverage and tools</h3><ul class="notes">{note_items}</ul>
<script>
document.getElementById('f').addEventListener('change',e=>{{const v=e.target.value;
document.querySelectorAll('#rows tr').forEach(r=>r.style.display=(!v||r.dataset.sev===v)?'':'none');}});
function cp(b){{navigator.clipboard&&navigator.clipboard.writeText(b.dataset.cmd).catch(()=>{{}});}}
</script></body></html>"""


def build_html(findings, meta, notes, path):
    pathlib.Path(path).write_text(html_report(findings, meta, notes))
    return str(path)
