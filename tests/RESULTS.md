# Test results (2026-11-27)

Unit tests: `python3 -m unittest discover -s tests -v` → 15 passed.

## Acceptance criteria

| ID | Check | Result |
|---|---|---|
| AC1 | Full scan lists every top-level entry | PASS (discover: 200 top-level entries, scanned or skipped with reason) |
| AC2 | Incremental read set = edited file + direct dependents | PASS (edit to a module read that module and its 4 importers; nothing else) |
| AC3 | Seeded SQL injection found, full and incremental | PASS on fixture (full: found; incremental: found after edit) |
| AC4 | Parameterized query not reported | PASS on fixture (not reported) |
| AC5 | Zero-change incremental reads nothing, saves nothing | PASS (clone: "no changes", 16 s wall time, no state write) |
| AC6 | Daily job writes a dated report | PASS (run-daily.sh on a clone: OK log line, incremental state saved). Launchd load confirmed; the 06:00 trigger itself is not yet observed |
| AC7 | No sub-agent calls | PASS (`disallowed-tools: Agent`; no Agent call seen in transcripts) |
| AC8 | Repo has LICENSE, README, SKILL.md, no secrets | PASS (grep for key patterns: none) |
| AC9 | Patch for seeded SQL bug passes `git apply --check` and fixes it | PASS (check OK; injection returns 0 rows after apply, normal query 1 row) |
| AC10 | Daily job writes no patches and changes no repo files | PASS (run-daily uses incremental only; no patch files; target git status unchanged) |

## Real runs (owner repos, read-only except `.cybersec/`, removed afterward)

| Repo | Mode | Result |
|---|---|---|
| job-bot (root, 3986 files) | FULL | REFUSED: over 150-file cap. Nothing written. |
| ai-brain (root, 8339 files) | FULL | REFUSED: over cap. |
| ai-brain/scripts (5 files) | FULL | 5 of 5 read. 1 low finding. 3 candidates dropped on re-review. |
| streaming-ingest-poc (27 files, owner's repo) | FULL | 27 of 27 read. 2 low findings (CWE-89 table names from settings). |
| streaming-ingest-poc clone | INCR after edit | 5 files read (edited module + 4 importers). Matches expected set. |
| streaming-ingest-poc clone | INCR, no change | 0 files read. No save. |

Repo-specific finding details are not recorded here. This repo is public.

## Failed or partial checks

| Check | Result | Cause | Planned fix |
|---|---|---|---|
| S5: same ids across two runs on same code | FAIL on streaming-ingest-poc clone (run 1: 2 findings; run 2: 6 findings with different ids) | Finding id hashes the agent's evidence quote. The agent words the quote differently per run. | v1.1: hash class + file + enclosing function name. Until then, ids can change between runs. |
| Incremental marked a dropped finding "fixed" | FOUND and FIXED in this build | Merge treated any missing finding in a read file as fixed. | Fixed status now requires the exact evidence text to be gone from the file. Two unit tests added. |
| Partial FULL state saved | FOUND and FIXED in this build (job-bot, ai-brain runs) | Agent read a fraction of files and saved state. | Helper refuses FULL over 150 files and refuses any save where read count differs from file count. |
| Read count is self-reported | KNOWN LIMIT | The helper cannot see which files the agent opened. | v1.1: log file reads. Coverage lists each file read. |
| Real-run confirmation of the 06:00 trigger | NOT YET | The daily job first fires at the next 06:00. | Check `~/Library/Logs/cybersec-scan.log` on 2026-11-28. |
| Full scan of job-bot | NOT RUN | 3986 files exceed the cap. | Run from a folder of 150 files or fewer. |
