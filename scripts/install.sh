#!/usr/bin/env bash
# Link this repo as a Claude Code skill. With --daily, also load the 06:00 launchd job.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SKILLS="$HOME/.claude/skills"; mkdir -p "$SKILLS"
ln -sfn "$REPO" "$SKILLS/cybersec-scan"
echo "linked $SKILLS/cybersec-scan -> $REPO"
python3 "$REPO/scripts/cyber_state.py" prereqs
if [ "${1:-}" = "--daily" ]; then
  CLAUDE_BIN="$(command -v claude)"; CLAUDE_DIR="$(dirname "$CLAUDE_BIN")"
  PLIST="$HOME/Library/LaunchAgents/com.cybersec-scan.daily.plist"
  RUNNER_DIR="$HOME/.local/share/cybersec-scan"   # outside ~/Documents: launchd cannot read it
  mkdir -p "$HOME/Library/LaunchAgents" "$HOME/.config/cybersec-scan" "$RUNNER_DIR"
  cp "$REPO/scripts/run-daily.sh" "$RUNNER_DIR/run-daily.sh"
  sed -e "s|__RUNNER__|$RUNNER_DIR/run-daily.sh|g" -e "s|__HOME__|$HOME|g" -e "s|__CLAUDE_DIR__|$CLAUDE_DIR|g" \
    "$REPO/launchd/com.cybersec-scan.daily.plist" > "$PLIST"
  launchctl bootout "gui/$(id -u)/com.cybersec-scan.daily" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "loaded com.cybersec-scan.daily (06:00 daily)"
  echo "Projects in ~/Documents need Full Disk Access for /bin/bash:"
  echo "  System Settings > Privacy and Security > Full Disk Access > add /bin/bash"
fi
