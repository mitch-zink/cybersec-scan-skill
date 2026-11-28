"""External scanners and the HTML report. Stdlib only.
Each *_findings returns (status, findings); status is ran | missing | timeout | error.
Secret values are never stored: gitleaks runs with --redact and only rule, file, line are kept."""
import hashlib
import html as H
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile

import config
import enrich
import lockscope

HERE = pathlib.Path(__file__).resolve().parent
RULES = HERE.parent / "rules" / "semgrep.yml"
SKILL_CLI = pathlib.Path("~/.claude/skills/cybersec-scan/scripts/cyber_state.py")
TOOLS = ("osv-scanner", "gitleaks", "semgrep", "zizmor", "trivy")
PREREQ_HINT = "brew install " + " ".join(TOOLS)
SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
SEV_ORDER = ["critical", "high", "medium", "low"]


def prereqs():
    found = {t: shutil.which(t) for t in TOOLS}
    return {"tools": found, "missing": [t for t, p in found.items() if not p], "install": PREREQ_HINT}


def _run(cmd, out_flag, timeout):
    """Run cmd. JSON goes to a temp file (out_flag + path) or stdout (out_flag None).
    Returns (status, returncode, parsed JSON or None); status is ok | timeout | error."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    argv = cmd + ([out_flag, path] if out_flag else [])
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        pathlib.Path(path).unlink(missing_ok=True)
        return "timeout", None, None
    except OSError:
        pathlib.Path(path).unlink(missing_ok=True)
        return "error", None, None
    raw = r.stdout if out_flag is None else pathlib.Path(path).read_text()
    pathlib.Path(path).unlink(missing_ok=True)
    try:
        return "ok", r.returncode, json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        return "ok", r.returncode, None


def _call(tool, cmd, out_flag, cfg, key, ok_rcs):
    """Shared wrapper: (status, data). status ran | missing | timeout | error."""
    if not shutil.which(tool):
        return "missing", None
    st, rc, data = _run(cmd, out_flag, cfg.get(f"timeout_{key}", 600))
    if st != "ok":
        return st, None
    return ("ran" if rc in ok_rcs else "error"), data


def rel(root, p):
    """Repo-relative posix path. Relative input is already repo-relative."""
    if not os.path.isabs(str(p)):
        return str(p)
    try:
        return str(pathlib.Path(p).resolve().relative_to(pathlib.Path(root).resolve()))
    except ValueError:
        return str(p)


def _cvss_sev(score):
    try:
        x = float(score)
    except (TypeError, ValueError):
        return None
    return "critical" if x >= 9 else "high" if x >= 7 else "medium" if x >= 4 else "low" if x > 0 else None


def _fixed(vulns, name):
    out = {e["fixed"] for v in vulns for a in v.get("affected", [])
           if a.get("package", {}).get("name", "").lower() == name.lower()
           for r in a.get("ranges", []) if r.get("type") in ("ECOSYSTEM", "SEMVER")
           for e in r.get("events", []) if "fixed" in e}
    return sorted(out)


def osv_findings(root, cfg):
    """Dependency CVEs, medium and above: one finding per OSV advisory group."""
    st, data = _call("osv-scanner", ["osv-scanner", "scan", "source", "-r", "--format", "json", str(root)],
                     "--output-file", cfg, "osv", (0, 1, 128))   # 1 = found, 128 = no lockfiles
    if st != "ran":
        return st, []
    out = []
    for res in (data or {}).get("results", []):
        rp = rel(root, res.get("source", {}).get("path", "?"))
        if config.vendor_skipped(rp, cfg):
            continue
        for pkg in res.get("packages", []):
            name, ver = pkg["package"]["name"], pkg["package"]["version"]
            by_id = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            for g in pkg.get("groups") or [{"ids": [i]} for i in by_id]:
                vulns = [by_id[i] for i in g["ids"] if i in by_id]
                sev, conf = _cvss_sev(g.get("max_severity")), "confirmed"
                if sev is None:
                    sev = next((SEV_MAP[s] for v in vulns if (s := str(v.get("database_specific", {}).get("severity", "")).upper()) in SEV_MAP), None)
                if sev is None:
                    sev, conf = "medium", "likely"
                if sev == "low":
                    continue
                aliases = g.get("aliases") or [a for v in vulns for a in [v["id"], *v.get("aliases", [])]]
                cls = next((a for a in aliases if a.startswith("CVE-")), g["ids"][0])
                fixed = _fixed(vulns, name)
                out.append({"source": "osv", "owasp": "A03", "class": cls, "severity": sev, "confidence": conf,
                            "scope": lockscope.scope(pathlib.Path(root, rp), name), "file": rp, "lines": "-",
                            "evidence": f"{name}@{ver} {cls}", "fp": f"{name}|{cls}",
                            "fix_hint": f"Upgrade {name} from {ver}." + (f" Fixed in: {', '.join(fixed)}." if fixed else " No fixed version listed."),
                            "summary": next((v.get("summary", "") for v in vulns if v.get("summary")), "")})
    if cfg.get("osv_enrich", True):
        enrich.apply(out)
    return "ran", out


def gitleaks_findings(root, cfg, history):
    """Secrets. history=False: current files. history=True: git history (source gitleaks-history)."""
    conf = config.gitleaks_config(root, cfg)
    st, data = _call("gitleaks", ["gitleaks", "git" if history else "dir", str(root), "-c", conf, "--redact",
                                  "--no-banner", "-f", "json"], "-r", cfg,
                     "gitleaks_history" if history else "gitleaks", (0, 1))
    if st != "ran":
        return st, []
    src, scope = ("gitleaks-history", "history") if history else ("gitleaks", "current")
    hint = "Remove the secret and rotate it." + (" The value is in git history: rotate it even after removal." if history else "")
    out = []
    for f in data or []:
        rp = rel(root, f.get("File", "?"))
        if config.secret_skipped(rp, cfg):
            continue
        out.append({"source": src, "owasp": "A02", "class": "CWE-798", "severity": "high",
                    "confidence": "confirmed", "scope": scope, "file": rp,
                    "lines": f"{f.get('StartLine', '?')}-{f.get('EndLine', '?')}",
                    "evidence": f"{f.get('RuleID', 'secret')} {rp}:{f.get('StartLine', '?')}",
                    "fp": f.get("Fingerprint", "") if history else f"{f.get('RuleID', '')}:{rp}:{f.get('StartLine', '')}",
                    "fix_hint": hint})
    return "ran", out


def semgrep_findings(root, cfg):
    """Code rules from rules/semgrep.yml."""
    skip = ["--exclude=" + d for d in config.ALWAYS_DIRS]
    st, data = _call("semgrep", ["semgrep", "--config", str(RULES), "--json", "--metrics=off", "--quiet", *skip, str(root)],
                     "--output", cfg, "semgrep", (0, 1))
    if st != "ran" or data is None:
        return ("error" if st == "ran" else st), []
    out = []
    for r in data.get("results", []):
        rp = rel(root, r.get("path", "?"))
        if config.path_skipped(rp, cfg):
            continue
        meta = r.get("extra", {}).get("metadata", {})
        line = r.get("start", {}).get("line", "?")
        cid = r.get("check_id", "rule").split(".")[-1]
        sev = {"ERROR": "high", "WARNING": "medium"}.get(r.get("extra", {}).get("severity", ""), "low")
        out.append({"source": "semgrep", "owasp": meta.get("owasp", ""), "class": meta.get("cwe", cid),
                    "severity": sev, "confidence": "confirmed", "scope": "current", "file": rp,
                    "lines": f"{line}-{r.get('end', {}).get('line', line)}", "evidence": f"{cid} {rp}:{line}",
                    "fp": f"{cid}|{rp}|{hashlib.sha1(r.get('extra', {}).get('lines', '').encode()).hexdigest()}",
                    "fix_hint": meta.get("fix", r.get("extra", {}).get("message", ""))})
    return "ran", out


# ---------------------------------------------------------------- report

def utc_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verdict_cli():
    p = SKILL_CLI.expanduser()
    return str(SKILL_CLI) if p.exists() else str(HERE / "cyber_state.py")


def _sev_key(f):
    return (SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 9, not f.get("kev"),
            -float(f.get("epss") or 0), f.get("id", ""))


def html_report(findings, meta, notes, root=".", max_rows=500, warnings=()):
    """One static page: open findings, a fixed section, tool warnings and coverage notes."""
    e = lambda s: H.escape(str(s))  # noqa: E731
    fixed = [f for f in findings if f.get("status") == "fixed"]
    live = [f for f in findings if f.get("status") != "fixed"]
    visible = sorted((f for f in live if f.get("verdict") != "false_positive"), key=_sev_key)
    hidden = len(live) - len(visible)
    cli = verdict_cli()
    rows = []
    for f in visible[:max_rows]:
        cmd = f'python3 {cli} verdict {shlex.quote(str(root))} {f.get("id", "?")} real "reason"'
        tag = ' <span class="kev">KEV</span>' if f.get("kev") else ""
        rows.append(
            f'<tr data-sev="{e(f["severity"])}"><td><span class="sev {e(f["severity"])}">{e(f["severity"])}</span></td>'
            f'<td>{e(f.get("status", "new"))}</td><td>{e(f.get("confidence", ""))}</td>'
            f'<td>{e(f["class"])}{tag}</td><td>{e(f.get("owasp", ""))}</td><td>{e(f.get("source", "agent"))}</td>'
            f'<td>{e(f.get("scope", ""))}</td><td><code>{e(f["file"])}</code> {e(f["lines"])}</td>'
            f'<td><code>{e(f["evidence"])}</code></td><td>{e(f.get("fix_hint", ""))}</td>'
            f'<td>{e(f.get("verdict", "new"))} <button type="button" data-cmd="{e(cmd)}" onclick="cp(this)">copy verdict cmd</button></td></tr>')
    fixed_rows = "".join(
        f'<tr><td><span class="sev {e(f["severity"])}">{e(f["severity"])}</span></td><td>{e(f["class"])}</td>'
        f'<td>{e(f.get("source", "agent"))}</td><td><code>{e(f["file"])}</code></td>'
        f'<td>{e(f.get("fixed_reason", "tool ran, finding gone"))}</td></tr>' for f in fixed)
    counts = {s: sum(1 for f in visible if f["severity"] == s) for s in SEV_ORDER}
    cards = "".join(f'<div class="card"><b>{counts[s]}</b><span class="sev {s}">{s}</span></div>' for s in SEV_ORDER)
    banners = "".join(f'<div class="banner warn">{e(w)}</div>' for w in warnings)
    if not visible:
        banners += f'<div class="banner ok"><b>No open findings.</b> Hidden as false positive: {hidden}.</div>'
    table = "" if not visible else (
        '<div class="wrap"><table><thead><tr><th>Severity</th><th>Status</th><th>Confidence</th><th>Class</th>'
        '<th>OWASP 2025</th><th>Source</th><th>Scope</th><th>File</th><th>Evidence</th><th>Fix</th><th>Verdict</th>'
        f'</tr></thead><tbody id="rows">{"".join(rows)}</tbody></table></div>')
    more = f"<p>{len(visible) - max_rows} more rows not shown. Use last_findings.json.</p>" if len(visible) > max_rows else ""
    fixed_html = "" if not fixed else (
        f'<details><summary><b>Fixed since last run ({len(fixed)})</b></summary><div class="wrap"><table><thead><tr>'
        '<th>Severity</th><th>Class</th><th>Source</th><th>File</th><th>Why fixed</th></tr></thead>'
        f'<tbody>{fixed_rows}</tbody></table></div></details>')
    note_items = "".join(f"<li>{e(n)}</li>" for n in notes)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan: {e(meta['repo'])}</title>
<style>
:root{{--bg:#f6f7f9;--fg:#15212b;--muted:#566573;--card:#fff;--line:#d5dde3;--head:#eef2f4;
--crit:#9b1c31;--high:#b8430f;--med:#93600a;--low:#4b5563;--ok:#167a3e;--info:#2f5f9e;color-scheme:light}}
@media (prefers-color-scheme: dark){{:root{{--bg:#0e1418;--fg:#e2e8ec;--muted:#97a6b2;--card:#151d23;--line:#2a3741;
--head:#1b252c;--crit:#c43a52;--high:#c25a1f;--med:#a87a14;--low:#5f6b78;--ok:#2f9a5b;--info:#4d84cf;color-scheme:dark}}}}
body{{font:14px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:24px max(16px,env(safe-area-inset-right)) 32px max(16px,env(safe-area-inset-left));color:var(--fg);background:var(--bg)}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:var(--muted);margin-bottom:12px;font-size:13px}}
.cards{{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}} .card{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:80px}}
.card b{{display:block;font-size:22px;font-variant-numeric:tabular-nums}}
.sev,.kev{{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}}
.critical,.kev{{background:var(--crit)}} .high{{background:var(--high)}} .medium{{background:var(--med)}} .low{{background:var(--low)}}
.banner{{border:1px solid;border-radius:6px;padding:8px 10px;margin:8px 0;background:var(--card)}}
.banner.warn{{border-color:var(--high)}} .banner.ok{{border-color:var(--ok)}} .banner.info{{border-color:var(--info)}}
.wrap{{overflow-x:auto;max-width:100%;border:1px solid var(--line);border-radius:6px;margin:8px 0}}
table{{border-collapse:collapse;width:100%;background:var(--card);font-size:13px}}
th,td{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}} th{{background:var(--head);white-space:nowrap}}
code{{font-size:12px;word-break:break-word}} button{{font-size:11px}} .notes{{color:var(--muted);font-size:12px}}
summary{{cursor:pointer;margin:12px 0 4px}} select{{font:inherit}}
</style></head><body>
<h1>Security scan: {e(meta['repo'])}</h1>
<div class="sub">Mode: {e(meta['mode'])} · Date: {e(meta['date'])} · Scanners: {e(meta['scanners'])} · Hidden as false positive: {hidden}</div>
{banners}
<div class="cards">{cards}</div>
<label>Severity <select id="f"><option value="">all</option>{''.join(f'<option>{s}</option>' for s in SEV_ORDER)}</select></label>
{table}{more}{fixed_html}
<h3>Coverage and tools</h3><ul class="notes">{note_items}</ul>
<script>
document.getElementById('f').addEventListener('change',e=>{{const v=e.target.value;
document.querySelectorAll('#rows tr').forEach(r=>r.hidden=!!v&&r.dataset.sev!==v);}});
function cp(b){{navigator.clipboard&&navigator.clipboard.writeText(b.dataset.cmd).then(()=>{{b.textContent='copied'}},()=>{{}});}}
</script></body></html>"""


def build_html(findings, meta, notes, path, root=".", warnings=()):
    pathlib.Path(path).write_text(html_report(findings, meta, notes, root, warnings=warnings))
    return str(path)
