# Test results, v3 (2026-11-28)

| Suite | Command | Result |
|---|---|---|
| Unit | `python3 tests/test_cyber_state.py` | 22 passed |
| Regressions (20 v2 defects) | `python3 tests/test_regressions.py` | 21 passed (20 v2 defects, all failed on v2, plus agent-output checks) |
| v3 steps | `python3 tests/test_v3.py` | 35 passed |
| Bench gates | `python3 scripts/bench.py` | 9 of 9 true |
| AI bench | `python3 scripts/bench.py --ai` | recall 10 of 10, 0 false alarms in 6 safe twins |

## Real runs (clones in a scratch folder; owner repos not written)

| Run | Before (v2) | After (v3) |
|---|---|---|
| job-bot `tools` | 506 findings, 97 s; SQL 370 (R3 100, R5 264, R1 5, R4 1) | 389 findings, 117 s; SQL 39 (R5 28, R9 9, R2 2; R1/R3/R4 0); zizmor 149; secrets in current files 7 to 25 (docs and plans now scanned) |
| job-bot SQL replay vs live | 14 tables "RLS off"; 5,504 statements not parsed | 0 tables RLS off (live: 0); 20 of 6,313 relevant statements not parsed (0.32%); public policies 349 (live 323) |
| job-bot live anon probe | n/a | 205 tables, 131 readable, 0 tenant tables returned rows |
| job-bot live catalog SQL (read-only) | n/a | L1 0, L2 3 (anon INSERT `true` on three tables with `user_id`), L3 0, L4 0; R5 28 to 8 functions an API role can call |
| poetry.lock with requests 2.19.0 | 0 findings | 7 (one per advisory group), CVSS severity, fixed versions, prod/dev, EPSS |
| streaming-ingest-poc full AI scan | n/a | 13 of 13 files, state saved, 0 rejected candidates, 0 permission denials, $0.48 |
| Daily job, repo with no state | could start a full AI scan | NEEDS_FULL, no full scan, one alert, repo files unchanged |
| Slack alert (local webhook) | none | one post on the first run, none on the second |
| job-bot full AI review (run-full.sh) | not possible (never completed) | Stopped by the owner at 27 of 42 batches: 620 of 1,321 files, 0 rejected candidates; found and fixed non-CWE classes in agent output |
| Unattended `claude -p` cost, tools mode | $1.03 (all user MCP servers loaded) | $0.056 with `--strict-mcp-config` |

## Defects found during the build

| ID | Defect | Fix |
|---|---|---|
| X11 | `gitleaks dir` returns absolute paths; ids held the temp path | Paths made repo-relative |
| - | Supabase default privileges (tables and functions) and `ALTER DEFAULT PRIVILEGES` not modeled | Modeled; trigger functions skipped |
| - | Short table names in function bodies resolved to the wrong schema | Schema-qualified resolution |
| - | Semgrep `/src/` include anchored at the git root | Unanchored `src/` |
| - | SKILL.md `CS` shorthand led to compound commands that permission rules deny | Plain helper calls |
| - | Read-only commands wrote `.cybersec/config.toml` | Only `tools` writes; `.cybersec/` ignores itself |

Repo-specific finding details are not recorded here. This repo is public.

## Dogfood round 2 (job-bot clone, tools only, no AI cost)

| Change | Before | After |
|---|---|---|
| OSV: one finding per package version, one upgrade target on the same release line | 98 | 33 |
| Zizmor: one finding per audit and file | 149 | 85 |
| Secrets: history copy dropped when the key is still in current files; test files skipped | 26 + 50 | 23 + 22 |
| Semgrep: `ssrf-request-py` pattern replaced by taint rule `taint-ssrf-py` | 28 | 13 |
| `tools` wall time: gitleaks reads files up to 1 MB; scanners run in parallel | 279 s | 82 s |
| Tool findings total | 390 | 215 |
