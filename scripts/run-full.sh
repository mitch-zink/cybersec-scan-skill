#!/usr/bin/env bash
# Full AI review with a fresh Claude process for each batch.
# Usage: run-full.sh REPO [--resume]. Exit 0 when state is saved; non-zero on the first failed batch.
set -uo pipefail
REPO="${1:?usage: run-full.sh REPO [--resume]}"
SKILL="$HOME/.claude/skills/cybersec-scan"
PY="${CYBERSEC_PY:-$SKILL/scripts/cyber_state.py}"
cd "$REPO" || exit 2
[ "${2:-}" = "--resume" ] || python3 "$PY" batch-reset . >/dev/null
while :; do
  n=$(python3 "$PY" batch-next . | python3 -c 'import json,sys; print(json.load(sys.stdin)["files"])')
  [ "$n" = "0" ] && break
  before=$(python3 -c 'import json; print(json.load(open(".cybersec/progress.json")).get("batches", 0))' 2>/dev/null || echo 0)
  claude -p "/cybersec-scan batch" \
    --permission-mode dontAsk \
    --tools "Read,Glob,Grep,Write,Edit,Bash" \
    --allowedTools "Read" "Glob" "Grep" "Edit(./.cybersec/**)" "Bash(python3 $PY *)" \
      "Bash(git rev-parse *)" "Bash(git diff *)" "Bash(git status *)" "Bash(git ls-files *)" "Bash(pwd)" \
    --max-budget-usd "${CYBERSEC_BATCH_BUDGET_USD:-5}" || exit 3
  after=$(python3 -c 'import json; print(json.load(open(".cybersec/progress.json")).get("batches", 0))' 2>/dev/null || echo 0)
  [ "$after" -gt "$before" ] || { echo "batch did not finish (no batch-done); stopping" >&2; exit 4; }
done
python3 "$PY" save . FULL
