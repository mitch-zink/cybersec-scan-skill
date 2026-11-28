# cybersec-scan-skill

A Claude Code skill that scans a code project for security problems and writes one HTML report.
It combines deterministic scanners with an AI reviewer. It never changes your code.

## What it finds

| Area | Check | Tool | Output |
|---|---|---|---|
| Dependencies | Known vulnerabilities (CVEs), medium and above | osv-scanner | Each CVE, package, version, and fix hint. Labeled production or dev-only |
| Secrets, current files | Keys, tokens, and passwords in code | gitleaks | Rule, file, line. Secret values are never stored |
| Secrets, git history | Keys committed and later removed | gitleaks (history) | Marked "rotate": history still holds the value |
| Code rules | SQL built from strings, shell from input, path traversal, SSRF, weak hashes, unsafe deserialization, TLS checks off, raw HTML | semgrep (11 rules in `rules/semgrep.yml`) | Rule, file, line, OWASP 2025 mapping |
| Database access (Postgres or Supabase migrations) | Row-level security off on tenant tables, open `USING (true)` policies, missing write policies, grants to `anon`/`public`, `SECURITY DEFINER` functions | Built-in SQL replay | Final state of every table |
| Logic, auth, and tenant bugs | Broken access control, injection, auth bypass, cross-tenant leaks | AI reviewer, in batches | Finding with cited lines and a source-to-sink note |

Dependency findings are labeled `prod` when the package ships to production and `dev` when it does not.
Test, fixture, mock, example, and documentation files are skipped by default.

## What it does not do

- It does not prove a bug can be exploited. It reports that code matches a pattern or a known vulnerability.
- It does not check running servers, cloud accounts, or third-party services.
- It does not change project files. Fixes are written as patch files for you to review (`git apply --check` only).
- It does not run the code it scans.
- The AI reviewer covers the files it reads. The coverage section says how many files it read and what it skipped.

## Install

```bash
git clone https://github.com/mitch-zink/cybersec-scan-skill ~/cybersec-scan-skill
~/cybersec-scan-skill/scripts/install.sh          # links the skill into ~/.claude/skills
brew install osv-scanner gitleaks semgrep        # the scanners
python3 ~/cybersec-scan-skill/scripts/cyber_state.py prereqs
```

Python 3.11 or later. No Python packages to install.

## Use

In a project folder, start Claude Code and run:

```
/cybersec-scan full
```

The skill runs in this order:

1. `tools`: runs osv-scanner, gitleaks, semgrep, and the SQL replay. Writes `report.html` right away.
2. AI review in batches of 150 files: `batch-next`, read, `merge`, `batch-done`, until complete.
3. `save`: stores the scan state only when every file in scope was read.

Results land in the project under `.cybersec/`:

| File | What it is |
|---|---|
| `.cybersec/report.html` | Current report. Open it in a browser. Works offline |
| `.cybersec/reports/<date>-tools/` | Tool-only run, with `findings.json` and `sql_tables.json` (table inventory) |
| `.cybersec/last_findings.json` | All current findings with their ids, scope, and verdicts |
| `.cybersec/config.toml` | Skip settings. `skip_tests = false` includes test files |
| `.cybersec/verdicts.json` | Your verdicts. Written only by you |

Other commands:

```bash
python3 ~/.claude/skills/cybersec-scan/scripts/cyber_state.py incr .          # changed files only
python3 ~/.claude/skills/cybersec-scan/scripts/cyber_state.py tools .         # tools only
python3 ~/.claude/skills/cybersec-scan/scripts/cyber_state.py verdict . <finding-id> real|false_positive|accepted_risk "reason"
```

## Triage

Every finding has an id, a scope, and a verdict (`new` until you decide).

- `false_positive`: hidden from the report. The hidden count stays visible.
- `accepted_risk`: shown, marked as accepted.
- `real`: shown, marked as confirmed.

A verdict stays while the finding id stays. If the code at that place changes, the id changes, and the verdict clears on purpose.

The AI reviewer never sets a verdict. It can suggest one in its report. You decide.

## Daily scan (macOS)

1. List project folders in `~/.config/cybersec-scan/repos.txt`, one per line.
2. Run `scripts/install.sh --daily`. This loads a launchd job at 06:00.
3. Log: `~/Library/Logs/cybersec-scan.log`.

Projects under `~/Documents` need Full Disk Access for `/bin/bash`:
System Settings > Privacy and Security > Full Disk Access > add `/bin/bash`.
The installer prints this step.

## How it performs

The scorecard is `scripts/bench.py`. Run it with `python3 scripts/bench.py`. It exits 0 only when every gate passes.

| Gate | Meaning |
|---|---|
| `unit_tests` | 21 unit tests pass |
| `recall_all_planted` | Every planted bug in a seeded test project is found |
| `no_false_alarm_safe_code` | Safe code and test files are not reported |
| `no_r2_on_service_role` | Policies limited to the server role are not flagged |

Gates prove the tool finds what it should and does not report what it should not. They do not prove how many real bugs a real project has.

Real-world precision (share of findings that are real) is measured by triage. It is reported as the verdict counts per source:

| Source | Findings | Real | False positive | Accepted risk | Unreviewed |
|---|---|---|---|---|---|
| osv (dependencies) | to be measured | | | | |
| gitleaks (secrets) | to be measured | | | | |
| semgrep (code rules) | to be measured | | | | |
| sql (database rules) | to be measured | | | | |
| agent (AI review) | to be measured | | | | |

Fill this table from `.cybersec/last_findings.json` after triage. Do not report a precision figure without it.

## Limits

- The 150-file batch limit applies to the AI reviewer. Tools cover the whole project.
- Database rules read migration files as text. Statements the parser does not recognize are counted in the report, not guessed.
- Finding ids for AI findings come from the quoted evidence text. Re-wording changes the id.
- Verdicts clear when code moves. This is intended, and it means old verdicts do not hide new code.
- Dependency reachability is not checked. A vulnerable package that is installed but not called is still reported.

## Project layout

```
SKILL.md              instructions for the agent (the skill entry point)
docs/checklist.md     OWASP 2025 classes and multi-tenant checks
rules/semgrep.yml     code rules
rules/samples/        one positive and one negative sample per rule (tested)
scripts/cyber_state.py   coordinator: discover, tools, batches, merge, verdicts, report
scripts/tools.py      scanner wrappers and the HTML report
scripts/sql_state.py  database migration replay
scripts/config.py     skip rules and the gitleaks config
scripts/bench.py      scorecard
scripts/install.sh    install the skill and the daily job
scripts/run-daily.sh  daily runner
tests/                unit tests and a fixture builder
```

## Development

```bash
python3 tests/test_cyber_state.py      # unit tests
python3 scripts/bench.py               # scorecard gates
```

CI runs the unit tests on every pull request (`.github/workflows/test.yml`).

## License

MIT. See LICENSE.
