"""Scan config: what to skip, and the generated gitleaks config. Stdlib only."""
import fnmatch
import pathlib
import re
import tomllib

TEST_DIRS = ["tests", "test", "__tests__", "fixtures", "mocks", "__mocks__"]
TEST_GLOBS = ["*.test.*", "*.spec.*", "test_*.py"]
ALWAYS_DIRS = ["node_modules", ".git", "dist", "build", ".next", "vendor", "__pycache__",
               ".venv", ".cybersec", "docs", "plans", "examples", ".claude"]
ALWAYS_GLOBS = ["*.md", "CLAUDE.md", "seed*", "*.lock", "*.min.js"]

DEFAULT = {"skip_tests": True}


def path_skipped(rel, cfg):
    """Return a skip reason, or None. rel is a repo-relative posix path."""
    parts = pathlib.PurePosixPath(rel).parts
    dirs = ALWAYS_DIRS + (TEST_DIRS if cfg["skip_tests"] else [])
    globs = ALWAYS_GLOBS + (TEST_GLOBS if cfg["skip_tests"] else [])
    if any(p in dirs for p in parts[:-1]):
        return "skip-dir"
    if any(fnmatch.fnmatch(parts[-1], g) for g in globs):
        return "skip-name"
    return None


def load(root):
    """Read .cybersec/config.toml. Write defaults if missing."""
    path = pathlib.Path(root, ".cybersec", "config.toml")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# cybersec-scan config\nskip_tests = true\n")
    return {**DEFAULT, **tomllib.loads(path.read_text())}


def glob_to_re(g):
    """Glob to a regex that Go (gitleaks) accepts: no lookarounds, no atomic groups."""
    out = "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in g)
    return f"(^|/){out}$"


def gitleaks_config(root, cfg):
    """Write .cybersec/gitleaks.toml. Skipped paths become allowlist regexes."""
    dirs = ALWAYS_DIRS + (TEST_DIRS if cfg["skip_tests"] else [])
    globs = ALWAYS_GLOBS + (TEST_GLOBS if cfg["skip_tests"] else [])
    paths = [f'(^|/){re.escape(d)}/' for d in dirs]
    paths += [glob_to_re(g) for g in globs]
    body = "[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"cybersec-scan skip list\"\npaths = [\n"
    body += "".join(f"  '{p}',\n" for p in paths) + "]\n"   # TOML literal strings: no escape rules
    out = pathlib.Path(root, ".cybersec", "gitleaks.toml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    return str(out)
