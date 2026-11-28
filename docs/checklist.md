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

## Multi-tenant isolation (SaaS)
Map to A01 unless noted. Check every tenant-scoped resource.

| # | Check | Look for |
|---|---|---|
| T1 | Tenant ID source | Tenant ID read from request body, URL, or header instead of the verified session or token claim |
| T2 | Query scope | ORM, raw SQL, or RPC on a tenant table with no tenant filter |
| T3 | RLS enabled | Table with a tenant column and RLS disabled (see SQL pass) |
| T4 | RLS policy strength | Policy `USING (true)`, missing policy for INSERT, UPDATE, or DELETE, or policy based on a client value |
| T5 | Privileged bypass | Service-role or admin key used on a user-facing path; `SECURITY DEFINER` function with no tenant check |
| T6 | Shared keys | Cache key, rate-limit key, queue payload, storage path, search index, or object key without tenant ID |
| T7 | Bulk and admin | Export, list, or admin endpoint that takes a tenant parameter without a membership check |
| T8 | Context leakage | Session setting (for example `SET app.tenant`) not reset; worker or background job without tenant context; singleton holding per-user state |
| T9 | Membership and invites | Invite accepted for a tenant the user does not belong to; role change that crosses tenants |
| T10 | Webhooks and callbacks | Inbound webhook not bound to one tenant before the write |
| T11 | Enumeration | Sequential IDs or distinct errors that reveal another tenant's record exists |
| T12 | Leakage | Tenant data in logs, error messages, analytics events, emails, or cross-tenant search results |

## SQL and RLS pass (A01, A05)
Read migrations and schema files directly. Do not rely on the code graph for SQL.
1. Find every `CREATE TABLE` or `ALTER TABLE` with a tenant column (`tenant_id`, `org_id`, `workspace_id`, or similar).
2. Confirm `ENABLE ROW LEVEL SECURITY` and at least one policy per command used by the app.
3. Read each policy. Flag `USING (true)`, `WITH CHECK (true)`, or a predicate that uses a client-supplied value.
4. List every `SECURITY DEFINER` function. Confirm it checks the caller's tenant before it reads or writes tenant data.
5. Flag grants to `anon` or `public` roles on tenant tables.
6. Record each table as: RLS on or off, policies found, risk.
