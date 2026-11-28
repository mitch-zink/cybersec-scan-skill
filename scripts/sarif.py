"""SARIF 2.1.0 export of open findings. Stdlib only."""
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def build(findings):
    live = [f for f in findings if f.get("status") != "fixed" and f.get("verdict") != "false_positive"]
    rules = sorted({f"{f.get('source', 'agent')}:{f['class']}" for f in live})
    results = []
    for f in live:
        loc = {"artifactLocation": {"uri": f["file"]}}
        start = str(f.get("lines", "")).split("-")[0]
        if start.isdigit():
            loc["region"] = {"startLine": int(start)}
        results.append({"ruleId": f"{f.get('source', 'agent')}:{f['class']}", "level": LEVEL.get(f["severity"], "note"),
                        "message": {"text": f"{f['evidence']}. Fix: {f.get('fix_hint', '')}".strip()},
                        "locations": [{"physicalLocation": loc}],
                        "partialFingerprints": {"cybersecId/v1": f["id"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cybersec-scan",
                                          "informationUri": "https://github.com/mitch-zink/cybersec-scan-skill",
                                          "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules]}},
                      "results": results}]}
