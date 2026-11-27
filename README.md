# cybersec-scan-skill

A Claude Code skill. One agent scans a code repository for security issues.
It can also write a patch for each issue. You review and apply each patch yourself.

## Modes

| Command | Mode | What it reads |
|---|---|---|
| `/cybersec-scan full [path]` | Identify | All tracked files |
| `/cybersec-scan incremental [path]` | Identify | Changed files since last scan, plus direct dependents |
| `/cybersec-scan fix <finding-id> [path]` | Remediate | One finding's file. Writes a patch. Never applies it |

## Safety

- The skill runs with your Claude Code permissions. It does not isolate the scanned code.
- Scan code that you trust. For other code, use a disposable VM.
- The skill never commits, pushes, or edits code. Patches are files you review.
- Repository text (comments, docs, CLAUDE.md) is treated as data, not instructions.

## Install

    git clone <this-repo> ~/cybersec-scan-skill
    ~/cybersec-scan-skill/scripts/install.sh

`install.sh` links the repo into `~/.claude/skills/cybersec-scan`.

## Daily scan (macOS)

1. List project folders in `~/.config/cybersec-scan/repos.txt`, one per line.
2. Run `scripts/install.sh --daily`. This loads a launchd job at 06:00.
3. Reports go to `<project>/.cybersec/reports/`. The log is `~/Library/Logs/cybersec-scan.log`.

## Licenses and notices

- This project: MIT (see LICENSE).
- CWE numbers are used as plain identifiers. CWE titles are not copied. CWE is a trademark of The MITRE Corporation.

## Limits

- FULL scans refuse folders over 150 files. Run from a smaller folder.
- A partial FULL scan is never saved as state.
- macOS: launchd cannot read `~/Documents`. Grant Full Disk Access to `/bin/bash` (System Settings, Privacy and Security) before the daily job can scan repos there.
- Add `.cybersec/` to the `.gitignore` of every scanned repo. The skill writes its output there.
- Finding IDs can change between runs when the wording of the evidence changes. See `tests/RESULTS.md`.
