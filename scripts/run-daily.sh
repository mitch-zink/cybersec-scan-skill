#!/usr/bin/env bash
# Daily scan for each repo in ~/.config/cybersec-scan/repos.txt.
# Tools run on every repo (whole project). The AI reader runs incremental only; it never starts a full scan.
# Exit 0 if all repos ran. Exit 2 if any repo failed. Failure does not change saved state.
set -uo pipefail
LIST="${CYBERSEC_REPOS:-$HOME/.config/cybersec-scan/repos.txt}"
LOG="${CYBERSEC_LOG:-$HOME/Library/Logs/cybersec-scan.log}"
SKILL="$HOME/.claude/skills/cybersec-scan"
PY="${CYBERSEC_PY:-$SKILL/scripts/cyber_state.py}"
ts() { date -u +%FT%TZ; }
mkdir -p "$(dirname "$LIST")" "$(dirname "$LOG")"
[ -f "$LIST" ] || { echo "$(ts) WARN no repo list at $LIST" >> "$LOG"; exit 2; }
repos=$(grep -v -e '^\s*#' -e '^\s*$' "$LIST" || true)
n=$(printf '%s' "$repos" | grep -c . || true)
echo "$(ts) RUN START repos=$n" >> "$LOG"
[ "$n" -eq 0 ] && echo "$(ts) WARN no repos listed in $LIST" >> "$LOG"
ok=0; fail=0
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  echo "$(ts) START $repo" >> "$LOG"
  if ( cd "$repo" && python3 "$PY" tools . >> "$LOG" 2>&1 \
        && claude -p "/cybersec-scan incremental-only" \
           --permission-mode dontAsk \
           --tools "Read,Glob,Grep,Write,Edit,Bash" \
           --allowedTools "Read" "Glob" "Grep" "Edit(./.cybersec/**)" "Bash(python3 $PY *)" \
             "Bash(git rev-parse *)" "Bash(git diff *)" "Bash(git status *)" "Bash(git ls-files *)" "Bash(pwd)" \
           --max-budget-usd "${CYBERSEC_DAILY_BUDGET_USD:-5}" >> "$LOG" 2>&1 ); then
    res=$(python3 "$PY" notify "$repo" 2>> "$LOG")
    tag=OK; [ -f "$repo/.cybersec/needs_full" ] && tag=NEEDS_FULL
    echo "$(ts) $tag $repo $(printf '%s' "$res" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(f"new_high={r[\"new_high\"]} notified={r[\"notified\"]}" + (f" skipped={r[\"skipped\"]}" if r.get("skipped") else ""))' 2>/dev/null)" >> "$LOG"
    ok=$((ok + 1))
  else
    echo "$(ts) FAIL $repo" >> "$LOG"; fail=$((fail + 1))
  fi
done <<< "$repos"
echo "$(ts) RUN END ok=$ok fail=$fail" >> "$LOG"
exit $(( fail ? 2 : 0 ))
