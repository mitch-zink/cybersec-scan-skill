"""AI review batches: priority from path tokens and file content; batches by bytes; direct local imports grouped. Stdlib only."""
import math
import pathlib
import re

PATH_TOKENS = re.compile(r"(?:^|[/_.\-])(auth|session|jwt|tenant|tenants|org|orgs|organization|workspace|"
                         r"role|roles|permission|permissions|admin|webhook|webhooks|invite|invites|token|tokens|"
                         r"middleware|route|routes|api|rls|policy|policies)(?:[/_.\-]|$)", re.I)
SIGNALS = [(5, r"service_role|SERVICE_ROLE|serviceRole|supabaseAdmin"),
           (3, r"req\.body|req\.query|req\.params|request\.(json|form|args|get_json)|await\s+req\.json\(\)|searchParams\.get\("),
           (3, r"Deno\.serve\(|export\s+(default\s+)?async\s+function\s+(handler|GET|POST|PUT|PATCH|DELETE)\b"
               r"|@(app|router|bp)\.(get|post|put|patch|delete|route)\(|router\.(get|post|put|patch|delete)\("
               r"|app\.(get|post|put|patch|delete)\("),
           (2, r"auth\.getUser\(|auth\.uid\(\)|jwt|getSession\(|Authorization"),
           (1, r"\.rpc\(|\.from\(['\"]|execute\(|\.query\(")]
SIGNALS = [(w, re.compile(rx)) for w, rx in SIGNALS]
JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*)['"](\.{1,2}/[^'"]+)['"]""")
PY_FROM = re.compile(r"^\s*from\s+(\.*[\w.]*)\s+import", re.M)
PY_IMPORT = re.compile(r"^\s*import\s+([\w.]+)", re.M)
JS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs")
MAX_BYTES = 300_000


def read(root, rel):
    try:
        return pathlib.Path(root, rel).read_text(errors="ignore")[:200_000]
    except OSError:
        return ""


def score(text):
    return sum(w for w, rx in SIGNALS if rx.search(text))


def rank(rel, sc):
    return 0 if PATH_TOKENS.search(rel) or sc >= 5 else 1 if sc >= 2 else 2


def local_imports(root, rel, text, pool):
    """Direct local imports of rel that are in pool."""
    base = pathlib.PurePosixPath(rel).parent
    out = []
    if rel.endswith(JS_EXT):
        for spec in JS_IMPORT.findall(text):
            stem = str(pathlib.PurePosixPath(base, spec))
            cands = [stem] + [stem + x for x in JS_EXT] + [f"{stem}/index{x}" for x in JS_EXT]
            out += [_norm(c) for c in cands if _norm(c) in pool][:1]
    elif rel.endswith(".py"):
        for mod in PY_FROM.findall(text) + PY_IMPORT.findall(text):
            dots = len(mod) - len(mod.lstrip("."))
            parts = [x for x in mod.lstrip(".").split(".") if x]
            start = base
            for _ in range(max(dots - 1, 0)):
                start = start.parent
            for b in ([start] if dots else [pathlib.PurePosixPath("")]):
                stem = str(pathlib.PurePosixPath(b, *parts)) if parts else str(b)
                out += [c for c in (stem + ".py", stem + "/__init__.py") if c in pool][:1]
    return [x for x in dict.fromkeys(out) if x != rel]


def _norm(p):
    parts = []
    for x in p.split("/"):
        if x == "..":
            parts = parts[:-1]
        elif x not in (".", ""):
            parts.append(x)
    return "/".join(parts)


def plan(root, todo, sizes, max_bytes=MAX_BYTES, max_files=150):
    """Order todo by (rank, -score, path), then build the next batch of groups. Returns (pick, info, pending_bytes)."""
    pool = set(todo)
    texts = {f: read(root, f) for f in todo}
    info = {f: {"score": score(texts[f])} for f in todo}
    for f in todo:
        info[f]["rank"] = rank(f, info[f]["score"])
    order = sorted(todo, key=lambda f: (info[f]["rank"], -info[f]["score"], f))
    pick, used = [], 0
    for seed in order:
        if seed in pick:
            continue
        group = ([seed] + [x for x in local_imports(root, seed, texts[seed], pool) if x not in pick])[:max_files]
        size = sum(sizes[x] for x in group)
        if pick and (used + size > max_bytes or len(pick) + len(group) > max_files):
            break
        pick += group
        used += size
    pending = sum(sizes[f] for f in todo)
    return pick, {f: info[f] for f in pick}, used, math.ceil(pending / max_bytes) if pending else 0
