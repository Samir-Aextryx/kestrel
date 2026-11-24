# ARTEX gap analysis

Sources: CERT-EU advisory (2026-11-05), Check Point Research (2026-11-05), Google
Threat Intelligence (2026-10-30), FBI FLASH (2026-11-13), upstream README and
SECURITY.md.

ARTEX established that an LLM planner plus real workers can run a penetration test
and keep evidence. Its limits are architectural, not cosmetic:

| Gap | Consequence | KESTREL response |
| --- | --- | --- |
| Scope is rules plus model judgment | Scope escape depends on model compliance | Hard `ScopeGate` in the request path |
| Scanner output is trusted | Ingested out-of-scope assets | Re-check every asset and request |
| No code/fuzz/zero-day pipeline | Blind to source-level and unknown bugs | 18 engines, coverage fuzzing, differential lab |
| No independent verification | Plausible but false findings | Replay, reachability, manifest checks, lab |
| No precision feedback | Noisy rules stay noisy | Fingerprint dedupe, critic, learned rule weights |
| External model only, no budgets | Cost and guardrail surprises | Router, budgets, fallbacks, encrypted keys |
| Forks and vanished upstream | Supply-chain uncertainty | Self-contained source, SBOM, signed reports |
| Exposed consoles | Admin takeover | Auth everywhere, CSRF, RBAC, rate limits, headers |
| No chain of custody | Weak evidentiary value | SHA-256 evidence, finding hashes, HMAC reports |
| No attack-path synthesis | Findings stay isolated | Correlation and ranked paths |
| No permissioned plugin contract | Extension risk | Worker isolation + manifest permissions |

The benchmark in `fixtures/vulnlab` measures the result: 100 % precision and
100 % recall on 78 seeded issues, with every finding traceable to a rule, file and
evidence record.
