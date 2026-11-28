"""Scan config: skip lists (code, secrets, vendor), defaults, and the generated gitleaks config. Stdlib only."""
import fnmatch
import pathlib
import re
import tomllib

TEST_DIRS = ["tests", "test", "__tests__", "fixtures", "mocks", "__mocks__"]
TEST_GLOBS = ["*.test.*", "*.spec.*", "test_*.py"]
VENDOR_DIRS = ["node_modules", ".git", "vendor", ".venv", "dist", "build", ".next", "__pycache__", ".cybersec"]
ALWAYS_DIRS = VENDOR_DIRS + ["docs", "plans", "examples", ".claude"]
ALWAYS_GLOBS = ["*.md", "CLAUDE.md", "seed*", "*.lock", "*.min.js"]
SECRET_SKIP_GLOBS = ["*.min.js", "*.lock", "package-lock.json", "pnpm-lock.yaml"]

DEFAULT = {"skip_tests": True, "osv_enrich": True,
           "timeout_osv": 600, "timeout_gitleaks": 600, "timeout_gitleaks_history": 1800,
           "timeout_semgrep": 900, "timeout_zizmor": 300, "timeout_trivy": 600,
           "sql": {"public_default_grants": True},
           "live": {"enabled": False, "url_env": "VITE_SUPABASE_URL",
                    "anon_key_env": "VITE_SUPABASE_ANON_KEY", "db_url_env": "CYBERSEC_DB_URL"}}


def _dirs(cfg, base):
    return base + (TEST_DIRS if cfg["skip_tests"] else [])


def _in_dirs(rel, dirs):
    return any(p in dirs for p in pathlib.PurePosixPath(rel).parts[:-1])


def _name_match(rel, globs):
    return any(fnmatch.fnmatch(pathlib.PurePosixPath(rel).name, g) for g in globs)


def path_skipped(rel, cfg):
    """Code skip list (AI review, semgrep). Returns a reason or None."""
    if _in_dirs(rel, _dirs(cfg, ALWAYS_DIRS)):
        return "skip-dir"
    return "skip-name" if _name_match(rel, ALWAYS_GLOBS + (TEST_GLOBS if cfg["skip_tests"] else [])) else None


def vendor_skipped(rel, cfg):
    """Tool inputs (lockfiles, migrations, IaC) skip only vendored code."""
    return "skip-dir" if _in_dirs(rel, _dirs(cfg, VENDOR_DIRS)) else None


def secret_skipped(rel, cfg):
    """Secrets scan: vendored code, minified JS and lockfiles. Docs, markdown and seeds are scanned."""
    return vendor_skipped(rel, cfg) or ("skip-name" if _name_match(rel, SECRET_SKIP_GLOBS) else None)


def load(root):
    """Read .cybersec/config.toml. Write defaults if missing. Nested tables merge over defaults."""
    path = pathlib.Path(root, ".cybersec", "config.toml")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# cybersec-scan config\nskip_tests = true\n")
    user = tomllib.loads(path.read_text())
    return {k: ({**v, **user.get(k, {})} if isinstance(v, dict) else user.get(k, v)) for k, v in DEFAULT.items()} \
        | {k: v for k, v in user.items() if k not in DEFAULT}


def glob_to_re(g):
    """Glob to a regex that Go (gitleaks) accepts: no lookarounds, no atomic groups."""
    out = "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in g)
    return f"(^|/){out}$"


def gitleaks_config(root, cfg):
    """Write .cybersec/gitleaks.toml with the secrets skip list ([[allowlists]], gitleaks v8.25+)."""
    paths = [f"(^|/){re.escape(d)}/" for d in _dirs(cfg, VENDOR_DIRS)] + [glob_to_re(g) for g in SECRET_SKIP_GLOBS]
    body = ('[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "cybersec-scan secrets skip list"\npaths = [\n'
            + "".join(f"  '{p}',\n" for p in paths) + "]\n")   # TOML literal strings: no escape rules
    out = pathlib.Path(root, ".cybersec", "gitleaks.toml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    return str(out)
