# Scan checklist (used by SKILL.md)

Labels: OWASP Top 10:2025 names (owasp.org/Top10/2025). CWE numbers are plain IDs.

## Classes

| OWASP 2025 | Look for | CWE examples |
|---|---|---|
| A01 Broken Access Control | Missing ownership or role check (IDOR); authz bypass; SSRF; path traversal; open redirect; CSRF on state change | 22, 639, 862, 918, 601, 352 |
| A02 Security Misconfiguration | Debug on in production; permissive CORS; default credentials; verbose errors to users; public storage buckets; wildcard IAM; broad CI token permissions | 16, 942, 1188, 732 |
| A03 Software Supply Chain Failures | Dependencies with known CVEs (see Dependency rule); unpinned or typosquatted packages; install scripts that fetch remote code; risky CI actions; `pull_request_target` misuse | 1104, 829, 494 |
| A04 Cryptographic Failures | MD5 or SHA1 for passwords; static IV or nonce; disabled TLS verification; hand-rolled crypto; secrets stored in plain text | 327, 328, 295, 319 |
| A05 Injection | SQL, NoSQL, OS command, template, LDAP injection; XSS; prompt injection in LLM code | 89, 78, 79, 94 |
| A06 Insecure Design | Sensitive action with no rate limit; trust of a client-side control | 307, 840 |
| A07 Authentication Failures | Weak session handling; no MFA on sensitive action; JWT accepted without verification or with `alg=none`; weak reset flow | 287, 384, 613 |
| A08 Software or Data Integrity Failures | Unsafe deserialization (pickle, `yaml.load`, PHP or Java objects); unsigned update or artifact used as code | 502, 345, 494 |
| A09 Security Logging and Alerting Failures | Secret or PII in logs; no log of auth failure or privilege change | 532, 778 |
| A10 Mishandling of Exceptional Conditions | Error path that fails open; error path that skips an auth check; stack trace returned to caller | 703, 636, 209 |

Secrets: a hardcoded key or token is CWE-798. Map it to A04 or A02 by context.

## Dependency rule
Dependency CVE findings come from a deterministic tool (for example OSV-Scanner), not from the agent. The agent does not guess CVE IDs.

## Do not report
- Speculation with no attack path
- Style or lint
- Pre-existing issues outside the changed code (incremental mode)
- Anything a verified control blocks: auth check, schema validation, framework escaping, ORM parameters, allowlist
- Placeholder or test-only credentials (for example `testing`, `pubkey`, `example`)
- Code proven unreachable in the production config

## Confidence
- confirmed: source traced to sink; no control found; path needs no special access
- likely: path traced; a control might exist; not verified
- refuted: a control found (do not report)

Report medium, high, and critical. Put low findings in Coverage only.

## Output fields (per finding)
id, severity, class (CWE), owasp (A-code), file, lines, source-to-sink path, evidence quote, attack scenario (one sentence), fix hint, confidence.

## Fix patch rules
- Smallest change that removes the class. Keep behavior for valid input.
- One file. No new dependency. At most 80 changed lines.
- Never run the patch or the code. Check the diff with `git apply --check` only.
- Include one command that shows the fix (for example a grep that returns nothing).
