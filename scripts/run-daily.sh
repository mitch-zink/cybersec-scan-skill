#!/usr/bin/env bash
# Daily incremental scan for each repo in ~/.config/cybersec-scan/repos.txt.
# Exit 0 if all repos ran. Exit 2 if any repo failed. Never edits code or state on failure.
set -uo pipefail
LIST="${CYBERSEC_REPOS:-$HOME/.config/cybersec-scan/repos.txt}"
LOG="$HOME/Library/Logs/cybersec-scan.log"
mkdir -p "$(dirname "$LIST")" "$(dirname "$LOG")"
[ -f "$LIST" ] || { echo "$(date -u +%FT%TZ) no repo list at $LIST" >> "$LOG"; exit 2; }
fail=0
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  case "$repo" in \#*) continue ;; esac
  echo "$(date -u +%FT%TZ) START $repo" >> "$LOG"
  if ( cd "$repo" && claude -p "/cybersec-scan incremental" \
        --allowedTools "Read Glob Grep Write Bash(git:*) Bash(python3:*) Bash(mkdir:*)" \
        >> "$LOG" 2>&1 ); then
    echo "$(date -u +%FT%TZ) OK $repo" >> "$LOG"
  else
    echo "$(date -u +%FT%TZ) FAIL $repo" >> "$LOG"; fail=1
  fi
done < "$LIST"
exit $(( fail ? 2 : 0 ))
