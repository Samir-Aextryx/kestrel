# Security model

## Assets

Model keys, session cookies, imported source, evidence, reports and the SQLite
database.

## Boundaries

1. Browser → API: session cookie + CSRF, or bearer token. RBAC on mutations.
2. API → target: `ScopeGate` with pinned DNS, allow/deny, ports, schemes, private-IP
   policy, redirect checks and request budget.
3. API → model: keys encrypted at rest; tool output wrapped as untrusted.
4. API → project files: `safeJoin` root confinement; size caps.
5. API → plugin: worker + manifest permissions + timeout.

## Threats considered

- Scope escape via redirect, DNS rebinding or CNAME to private space
- Prompt injection in source, headers or HTTP bodies
- Malicious ZIP path traversal
- Plugin reading outside the project or calling arbitrary hosts
- Secret leakage in reports
- Model cost runaway
- CSRF and session theft
- Supply-chain substitution

## Mitigations

- redirect re-validation, IP pinning, private/metadata block
- nonce-delimited untrusted blocks, JSON-only model contracts, line checks
- ZIP entry normalization and `safeJoin`
- plugin permission manifests, worker isolation, heap/time caps
- redacted secret evidence
- per-scan call and cost budgets
- SameSite cookies, HttpOnly, constant-time CSRF comparison, CSP, HSTS, COOP/CORP
- login throttling per IP and per IP+account with bounded limiter state;
  `trust proxy` is off unless explicitly configured
- graceful shutdown drains running jobs; finished jobs and audit rows expire
- pinned dependencies, SBOM, license policy, signed reports

## Residual risk

An authorized target can still be hostile. The lab executes project code; a
determined payload can consume CPU until the timeout. Web checks are unauthenticated
by default. The server process itself is trusted.
