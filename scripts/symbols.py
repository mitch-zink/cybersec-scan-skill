"""Enclosing symbol of a line: the name agent finding ids hash, so re-worded evidence keeps its id. Stdlib only."""
import pathlib
import re

PY = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)|^\s*class\s+(\w+)")
JS = re.compile(r"function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\(|function|\w+\s*=>)"
                r"|^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{|class\s+(\w+)")
SQL = re.compile(r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.\"]+)", re.I)
BY_EXT = {".py": PY, ".sql": SQL, **{x: JS for x in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")}}
NOT_NAMES = {"if", "for", "while", "switch", "catch", "return"}


def start_line(lines):
    try:
        return int(str(lines).split("-")[0])
    except ValueError:
        return 0


def enclosing(root, rel, line):
    """First symbol at or above line (1-based), else '<module>'."""
    rx = BY_EXT.get(pathlib.PurePosixPath(rel).suffix.lower())
    if not rx or line < 1:
        return "<module>"
    try:
        text = pathlib.Path(root, rel).read_text(errors="ignore").splitlines()
    except OSError:
        return "<module>"
    for ln in reversed(text[:line]):
        m = rx.search(ln)
        name = next((g for g in m.groups() if g), None) if m else None
        if name and name not in NOT_NAMES:
            return name
    return "<module>"
