"""Slack alert for new high or critical findings, once per finding id. Stdlib only.
Webhook URL file: ~/.config/cybersec-scan/slack_webhook (mode 600). No file: no post."""
import json
import pathlib
import stat
import urllib.request

WEBHOOK = pathlib.Path.home() / ".config" / "cybersec-scan" / "slack_webhook"


def webhook_url(path=WEBHOOK):
    """(url, problem). problem is None, 'missing' or 'mode'."""
    if not path.exists():
        return None, "missing"
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        return None, "mode"
    return path.read_text().strip(), None


def message(repo, items, needs_full, report):
    lines = [f"*cybersec-scan · {repo}*"]
    if items:
        lines[0] += f": {len(items)} new high or critical findings"
        lines += [f"• [{f['severity']}] {f['class']} {f['file']}"
                  + (f":{f['lines']}" if f['lines'] not in ('-', '') else "")
                  + f" ({f['source']}{', KEV' if f.get('kev') else ''})" for f in items[:10]]
        if len(items) > 10:
            lines.append(f"and {len(items) - 10} more")
    if needs_full:
        lines.append("A full scan is needed (no saved state). Run: /cybersec-scan full")
    lines.append(f"Report: {report}")
    return "\n".join(lines)


def run(root, findings, path=WEBHOOK):
    """Returns a result dict. Writes .cybersec/notified.json only after HTTP 200."""
    root = pathlib.Path(root)
    sent_p, nf, nf_sent = root / ".cybersec/notified.json", root / ".cybersec/needs_full", root / ".cybersec/needs_full.notified"
    sent = set(json.loads(sent_p.read_text())) if sent_p.exists() else set()
    items = [f for f in findings if f.get("status") == "new" and f.get("verdict", "new") == "new"
             and f.get("severity") in ("critical", "high") and f["id"] not in sent]
    needs_full = nf.exists() and not nf_sent.exists()
    res = {"new_high": len(items), "notified": 0, "needs_full": needs_full}
    if not items and not needs_full:
        return res
    url, problem = webhook_url(path)
    if problem:
        return dict(res, skipped=problem)
    body = json.dumps({"text": message(root.name, items, needs_full, root / ".cybersec/report.html")}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "cybersec-scan"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            ok = r.status == 200
    except OSError:
        ok = False
    if not ok:
        return dict(res, skipped="post-failed")
    sent_p.write_text(json.dumps(sorted(sent | {f["id"] for f in items})))
    if needs_full:
        nf_sent.write_text("notified\n")
    return dict(res, notified=len(items))
