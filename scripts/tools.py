"""External scanners and HTML report. Stdlib only. Imported by cyber_state.py."""
import datetime
import html
import json
import pathlib
import shutil
import subprocess
import tempfile

PREREQ_HINT = "brew install osv-scanner gitleaks"
SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
           "MEDIUM": "medium", "LOW": "low"}
SEV_ORDER = ["critical", "high", "medium", "low"]


def prereqs():
    found = {t: shutil.which(t) for t in ("osv-scanner", "gitleaks")}
    return {"tools": found, "missing": [t for t, p in found.items() if not p],
            "install": PREREQ_HINT}


def _run(cmd, out_flag, timeout=900):
    """Run cmd with a temp output file. out_flag is the flag placed before the file path."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
        path = out.name
    argv = cmd + ([out_flag] if out_flag else []) + [path]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    data = None
    p = pathlib.Path(path)
    if p.exists() and p.stat().st_size:
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            data = None
    p.unlink(missing_ok=True)
    return r.returncode, data


def osv_findings(root):
    """Dependency CVEs. Returns (ok, findings). Medium and above only."""
    if not shutil.which("osv-scanner"):
        return False, []
    rc, data = _run(["osv-scanner", "scan", "source", "-r", "--format", "json", root], "--output-file")
    if data is None:
        return rc in (0, 1, 128), []   # 1 = vulns found; 128 = no lockfiles (nothing to scan)
    out = []
    for res in data.get("results", []):
        src = res.get("source", {}).get("path", "?")
        for pkg in res.get("packages", []):
            name = pkg["package"]["name"]; ver = pkg["package"]["version"]
            for v in pkg.get("vulnerabilities", []):
                sev = SEV_MAP.get(str(v.get("database_specific", {}).get("severity", "")).upper(), "medium")
                if sev == "low":
                    continue
                cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v["id"])
                out.append({"source": "osv", "owasp": "A03", "class": cve, "severity": sev,
                            "confidence": "confirmed", "file": src, "lines": "-",
                            "evidence": f"{name}@{ver} {cve}",
                            "fix_hint": f"Upgrade {name} past {ver}. {v.get('summary', '')}".strip()})
    return True, out


def gitleaks_findings(root):
    """Secrets in committed history and tracked files. Secret values are never stored."""
    if not shutil.which("gitleaks"):
        return False, []
    rc, data = _run(["gitleaks", "git", root, "--redact", "--no-banner", "-f", "json", "-r"], "", timeout=1800)
    if rc not in (0, 1):
        return False, []
    out = []
    for f in data or []:
        commit = f.get("Commit", "")
        hist = " (in git history: rotate the secret)" if commit else ""
        out.append({"source": "gitleaks", "owasp": "A02", "class": "CWE-798", "severity": "high",
                    "confidence": "confirmed", "file": f.get("File", "?"),
                    "lines": f"{f.get('StartLine', '?')}-{f.get('EndLine', '?')}",
                    "evidence": f"{f.get('RuleID', 'secret')} {f.get('File', '?')}:{f.get('StartLine', '?')}",
                    "fix_hint": f"Remove the secret and rotate it.{hist}"})
    return True, out


def html_report(findings, meta, notes):
    rows = []
    for f in findings:
        rows.append(
            f'<tr data-sev="{html.escape(f["severity"])}" data-src="{html.escape(f.get("source", "agent"))}">'
            f'<td><span class="sev {html.escape(f["severity"])}">{html.escape(f["severity"])}</span></td>'
            f'<td>{html.escape(f["class"])}</td><td>{html.escape(f.get("owasp", ""))}</td>'
            f'<td>{html.escape(f.get("source", "agent"))}</td>'
            f'<td><code>{html.escape(f["file"])}</code> {html.escape(str(f["lines"]))}</td>'
            f'<td><code>{html.escape(f["evidence"])}</code></td>'
            f'<td>{html.escape(f.get("fix_hint", ""))}</td><td>{html.escape(f["status"])}</td></tr>')
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    cards = "".join(f'<div class="card"><b>{counts[s]}</b><span class="sev {s}">{s}</span></div>' for s in SEV_ORDER)
    note_items = "".join(f"<li>{html.escape(n)}</li>" for n in notes)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan: {html.escape(meta['repo'])}</title>
<style>
body{{font:14px -apple-system,system-ui,sans-serif;margin:24px;color:#1d2330;background:#f7f8fb}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#5b6577;margin-bottom:16px}}
.cards{{display:flex;gap:12px;margin:12px 0}} .card{{background:#fff;border:1px solid #d9dee8;border-radius:8px;padding:10px 14px;min-width:90px}}
.card b{{display:block;font-size:22px}} .sev{{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}}
.critical{{background:#7a1020;color:#fff}} .high{{background:#c2410c;color:#fff}} .medium{{background:#b45309;color:#fff}} .low{{background:#4b5563;color:#fff}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px}} th,td{{border:1px solid #d9dee8;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#eef1f7}} code{{font-size:12px}} select{{margin:8px 0}} .notes{{color:#5b6577;font-size:12px}}
</style></head><body>
<h1>Security scan: {html.escape(meta['repo'])}</h1>
<div class="sub">Mode: {html.escape(meta['mode'])} · Date: {html.escape(meta['date'])} · Scanner: {html.escape(meta['scanners'])}</div>
<div class="cards">{cards}</div>
<label>Severity <select id="f"><option value="">all</option>{''.join(f'<option>{s}</option>' for s in SEV_ORDER)}</select></label>
<table><thead><tr><th>Severity</th><th>Class</th><th>OWASP 2025</th><th>Source</th><th>File</th><th>Evidence</th><th>Fix</th><th>Status</th></tr></thead>
<tbody id="rows">{''.join(rows)}</tbody></table>
<h3>Coverage</h3><ul class="notes">{note_items}</ul>
<script>
document.getElementById('f').addEventListener('change',e=>{{const v=e.target.value;
document.querySelectorAll('#rows tr').forEach(r=>r.style.display=(!v||r.dataset.sev===v)?'':'none');}});
</script></body></html>"""


def build_html(findings, meta, notes, path):
    pathlib.Path(path).write_text(html_report(findings, meta, notes))
    return str(path)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
