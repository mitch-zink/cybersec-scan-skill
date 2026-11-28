"""prod or dev scope of a package in a lockfile: npm, poetry, uv. Others are 'unknown'. Stdlib only."""
import functools
import json
import pathlib
import tomllib


@functools.lru_cache(maxsize=64)
def _load(path):
    p = pathlib.Path(path)
    return json.loads(p.read_text()) if p.suffix == ".json" else tomllib.loads(p.read_text())


def _npm(data, name):
    entries = [v for k, v in data.get("packages", {}).items() if k.endswith("node_modules/" + name)]
    if not entries:
        return "unknown"
    return "prod" if any(not (v.get("dev") or v.get("devOptional")) for v in entries) else "dev"


def _poetry(data, name):
    for pkg in data.get("package", []):
        if pkg.get("name", "").lower() == name.lower():
            if "groups" in pkg:
                return "prod" if "main" in pkg["groups"] else "dev"
            return "prod" if pkg.get("category", "main") == "main" else "dev"
    return "unknown"


def _uv(data, name):
    pkgs = {p["name"].lower(): p for p in data.get("package", [])}
    root = next((p for p in pkgs.values()
                 if p.get("source", {}).get("editable") == "." or p.get("source", {}).get("virtual") == "."), None)
    if root is None or name.lower() not in pkgs:
        return "unknown"
    prod, todo = set(), [d["name"].lower() for d in root.get("dependencies", [])]
    while todo:
        n = todo.pop()
        if n not in prod and n in pkgs:
            prod.add(n)
            todo += [d["name"].lower() for d in pkgs[n].get("dependencies", [])]
    return "prod" if name.lower() in prod else "dev"


HANDLERS = {"package-lock.json": _npm, "poetry.lock": _poetry, "uv.lock": _uv}


def scope(lockfile, name):
    fn = HANDLERS.get(pathlib.Path(lockfile).name)
    try:
        return fn(_load(str(lockfile)), name) if fn else "unknown"
    except (OSError, ValueError, KeyError, TypeError):
        return "unknown"
