# cybersec-scan-skill

A Claude Code skill that scans a code project for security problems and writes one HTML report.
It combines deterministic scanners with an AI reviewer. It never changes your code.

## What it finds

| Area | Check | Tool | Output |
|---|---|---|---|
| Dependencies | Known vulnerabilities (CVEs), medium and above | osv-scanner | One finding per advisory group. CVSS severity, fixed versions, `prod`/`dev` scope (npm, Poetry, uv), CISA KEV flag, EPSS score |
| Secrets, current files | Keys, tokens and passwords, including in docs and markdown | gitleaks | Rule, file, line. Secret values are never stored |
| Secrets, git history | Keys committed and later removed | gitleaks (history) | Marked "rotate": history still holds the value |
| Code rules | Taint flows from request data to SQL, shell and fetch; SQL and shell built from strings; path traversal; SSRF; weak hashes; unsafe deserialization; TLS checks off; raw HTML; Supabase service key in client code; CORS `*` | semgrep (17 rules in `rules/semgrep.yml`) | Rule, file, line, OWASP 2025 mapping |
| Supabase config | Edge functions with `verify_jwt = false` | built-in | Function name and line |
| GitHub Actions | Template injection, excessive permissions, unpinned actions and more | zizmor | Audit, file, line |
| Containers and IaC | Dockerfile, Terraform, Kubernetes, Helm misconfiguration | trivy config | Check ID, file, lines |
| Database (Postgres or Supabase migrations) | RLS off (R1), open `true` policies (R2), unguarded SECURITY DEFINER functions (R5), sign-in-only policies (R6), `user_metadata` in policies (R7), no fixed `search_path` (R8), views without `security_invoker` (R9) | SQL replay | Final state of every table, view and function |
| Database, live (opt-in) | Same rules on the real catalog (L1-L4); anon key can read rows of a tenant table (L5) | live mode, read-only | Replaces replay results it disproves |
| Logic, auth and tenant bugs | Broken access control, injection, auth bypass, cross-tenant leaks | AI reviewer, in batches | Finding with cited lines, the control it checked, and a fix hint |

Test, fixture, mock, example and documentation files are skipped for code review by default. The secrets scan reads docs and markdown.

## What it does not do

- It does not prove a bug can be exploited. It reports that code matches a pattern, a known vulnerability, or a live state.
- It does not attack running services. Live mode only reads: one row per table with the public anon key, and catalog queries in a read-only transaction.
- It does not change project files. Fixes are written as patch files for you to review (`git apply --check` only).
- It does not run the code it scans.
- The AI reviewer covers the files it reads. The coverage section says how many files it read and what it skipped.

## Install

```bash
git clone https://github.com/mitch-zink/cybersec-scan-skill ~/cybersec-scan-skill
~/cybersec-scan-skill/scripts/install.sh          # links the skill into ~/.claude/skills
brew install osv-scanner gitleaks semgrep zizmor trivy   # the scanners (each one is optional)
python3 ~/cybersec-scan-skill/scripts/cyber_state.py prereqs
```

Python 3.11 or later. No Python packages to install.

## Use

In a project folder, start Claude Code and run:

```
/cybersec-scan full
```

The skill runs in this order:

1. `tools`: runs every scanner and the SQL replay. Writes `report.html` right away.
2. AI review in batches of at most 300 KB (files with their direct imports): `batch-next`, read, `merge`, `batch-done`, until complete. More than 3 batches: run `scripts/run-full.sh <repo>`, which starts a fresh Claude process for each batch (`CYBERSEC_BATCH_BUDGET_USD`, default 5).
3. `save`: stores the scan state only when every file in scope was read at its current content.

Results land in the project under `.cybersec/`:

| File | What it is |
|---|---|
| `.cybersec/report.html` | Current report. Open it in a browser. Works offline |
| `.cybersec/reports/<date>-tools/` | Tool run, with `findings.json` and `sql_tables.json` (table inventory) |
| `.cybersec/last_findings.json` | All current findings with their ids, scope and verdicts |
| `.cybersec/config.toml` | Settings: `skip_tests`, `osv_enrich`, `timeout_<tool>`, `[sql] public_default_grants`, `[live]` |
| `.cybersec/verdicts.json` | Your verdicts. Written only by you |

Commands (`CS = python3 ~/.claude/skills/cybersec-scan/scripts/cyber_state.py`):

| Command | What it does |
|---|---|
| `CS tools . [--no-history] [--fail-on high]` | All scanners. Exit 6 when a new finding is at or above the level |
| `CS live .` | Tools plus live database checks (see below) |
| `CS incr .` | Changed files and their importers since the last saved state |
| `CS batch-reset .` / `batch-next .` / `batch-done .` | Full review loop |
| `CS sarif . out.sarif` | SARIF 2.1.0 for code scanning |
| `CS stats . --md` | Verdict counts and precision per source |
| `CS notify .` | Slack alert for new high or critical findings |
| `CS verdict . <id> real\|false_positive\|accepted_risk "reason"` | Your triage |

## Live mode (Supabase)

Off by default. Set it in `.cybersec/config.toml`:

```toml
[live]
enabled = true
url_env = "VITE_SUPABASE_URL"          # read from the environment, else from .env
anon_key_env = "VITE_SUPABASE_ANON_KEY"
db_url_env = "CYBERSEC_DB_URL"         # optional: a read-only Postgres login for catalog checks
```

The anon probe uses only the public anon key. Catalog checks need `psql` and a database URL; they run with `default_transaction_read_only=on`. Key and URL values are never written to findings or logs.

## Triage

Every finding has an id, a scope, and a verdict (`new` until you decide).

- `false_positive`: hidden from the report. The hidden count stays visible.
- `accepted_risk`: shown, marked as accepted.
- `real`: shown, marked as confirmed.

A verdict stays while the finding id stays. An AI finding id hashes class, file and enclosing function, so re-worded evidence and moved lines keep the verdict. A new class or file clears it. Verdicts from v2 ids carry over once (`migrated_from`).

The AI reviewer never sets a verdict. It can suggest one in its report. You decide.

## Daily scan (macOS)

1. List project folders in `~/.config/cybersec-scan/repos.txt`, one per line.
2. Optional Slack alert: put an incoming webhook URL in `~/.config/cybersec-scan/slack_webhook` and run `chmod 600` on it.
3. Run `scripts/install.sh --daily`. This loads a launchd job at 06:00.
4. Log: `~/Library/Logs/cybersec-scan.log`. Each run writes `RUN START repos=N` and `RUN END ok=a fail=b`.

The daily job runs `tools`, then an incremental AI review with a narrow tool allow list (the helper script, read-only git, writes under `.cybersec/` only), `--permission-mode dontAsk` and a spend cap (`CYBERSEC_DAILY_BUDGET_USD`, default 5). It never starts a full AI scan: a repo with no saved state gets `NEEDS_FULL` in the log and one alert.

Projects under `~/Documents` need Full Disk Access for `/bin/bash`:
System Settings > Privacy and Security > Full Disk Access > add `/bin/bash`.

## How it performs

`scripts/bench.py` is the scorecard. It exits 0 only when every gate passes.

| Gate | Meaning |
|---|---|
| `unit_tests`, `regressions` | All unit tests and the 20 v2 regression tests pass |
| `recall_all_planted` | Every planted bug in a seeded project is found |
| `no_false_alarm_safe_code` | Safe code and test files are not reported |
| `no_r2_on_service_role` | Policies limited to the server role are not flagged |
| `secrets_in_docs` | A key in `docs/*.md` is found |
| `osv_lockfile_not_skipped` | Lockfiles other than npm are read |
| `sql_no_r3`, `sql_do_loop` | No "missing write policy" noise; RLS turned on in a `FOREACH` loop is seen |

`python3 scripts/bench.py --ai` runs the AI reviewer on `tests/ai_bench` (10 planted tenant bugs, 6 safe twins). Gate: recall at least 9 of 10, at most 1 false alarm. It makes real Claude calls, so CI does not run it. Results are in `tests/RESULTS.md`.

Real-world precision is measured by triage: `CS stats . --md` prints real, false positive, accepted and unreviewed counts per source. Do not report a precision figure without it.

## Limits

- The SQL replay reads migration files as text. It expands `FOREACH ... IN ARRAY ARRAY[...]` loops with `format('%I')`, but not loops over catalog queries, and it cannot see tables made outside the migrations folder. Live mode covers both.
- Supabase default grants are modeled (`[sql] public_default_grants = true`). Set it to false for plain Postgres.
- `prod`/`dev` scope is not known for pnpm and yarn lockfiles (`unknown`).
- Dependency reachability is not checked.
- Two AI findings of one class in one function share a base id; a `-2` suffix keeps them apart.

## Project layout

```
SKILL.md                 instructions for the agent (the skill entry point)
docs/checklist.md        OWASP 2025 classes, multi-tenant checks, SQL rules
rules/semgrep.yml        code rules; rules/samples/ has a positive and a negative line for each
scripts/cyber_state.py   coordinator: discover, tools, batches, merge, verdicts, report commands
scripts/tools.py         scanner wrappers and the HTML report
scripts/sql_state.py     database migration replay and rules R1-R9
scripts/live.py          live anon probe and read-only catalog checks
scripts/batching.py      AI batch order and grouping
scripts/{symbols,lockscope,enrich,notify,sarif,config}.py   ids, scope, KEV/EPSS, Slack, SARIF, skip lists
scripts/bench.py         scorecard
scripts/run-full.sh      one Claude process per batch
scripts/run-daily.sh     daily runner; scripts/install.sh installs it
tests/                   unit, regression and v3 tests; ai_bench fixture
```

## Development

```bash
python3 tests/test_cyber_state.py && python3 tests/test_regressions.py && python3 tests/test_v3.py
python3 scripts/bench.py               # scorecard gates
```

CI runs all test suites and the bench gates on every pull request (`.github/workflows/test.yml`), with gitleaks 8.30.1 and semgrep 1.187.0 pinned.

## License

MIT. See LICENSE.
