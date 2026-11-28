"""KEV and EPSS for CVE ids, cached in ~/.cache/cybersec-scan. Only CVE ids leave the machine. Stdlib only."""
import datetime
import json
import pathlib
import time
import urllib.request

CACHE = pathlib.Path.home() / ".cache" / "cybersec-scan"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
LAST_NOTE = ""


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cybersec-scan"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def kev(cache=CACHE):
    """Set of KEV CVE ids. Refresh after 24 h; on failure use a stale cache; else None."""
    p = cache / "kev.json"
    if not p.exists() or time.time() - p.stat().st_mtime > 86400:
        try:
            data = _get(KEV_URL)
            cache.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(data))
        except (OSError, ValueError):
            pass
    try:
        return {v["cveID"] for v in json.loads(p.read_text())["vulnerabilities"]}
    except (OSError, ValueError, KeyError):
        return None


def epss(cves, cache=CACHE):
    """{cve: score}. Cached per day; 100 ids per request. Missing ids stay absent."""
    p = cache / f"epss-{datetime.date.today().isoformat()}.json"
    have = json.loads(p.read_text()) if p.exists() else {}
    need = sorted(set(cves) - set(have))
    for i in range(0, len(need), 100):
        try:
            for row in _get(EPSS_URL + ",".join(need[i:i + 100])).get("data", []):
                have[row["cve"]] = float(row["epss"])
        except (OSError, ValueError, KeyError):
            break
        for c in need[i:i + 100]:
            have.setdefault(c, None)
    if need:
        cache.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(have))
    return {c: have.get(c) for c in cves if have.get(c) is not None}


def apply(findings, cache=CACHE):
    """Add kev and epss to OSV findings. KEV raises severity to critical. Sets LAST_NOTE when KEV is not available."""
    global LAST_NOTE
    cves = [f["class"] for f in findings if f["class"].startswith("CVE-")]
    if not cves:
        return ""
    k, e = kev(cache), epss(cves, cache)
    for f in findings:
        f["kev"] = bool(k and f["class"] in k)
        if f["kev"]:
            f["severity"] = "critical"
        if f["class"] in e:
            f["epss"] = e[f["class"]]
    LAST_NOTE = "" if k is not None else "KEV list not available (no network and no cache)."
    return LAST_NOTE
