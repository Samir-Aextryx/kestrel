# KESTREL

**Autonomous, evidence-first security research.**

KESTREL is a self-hosted platform for authorized security research. It is built for
machines first: an autonomous agent submits a goal, the planner derives a hard scope
and an engine set, the run executes, a verifier reproduces findings, and a signed
report is produced. Humans can steer, approve and triage at any point.

ARTEX was the baseline. KESTREL keeps the useful ideas — planner/worker separation,
evidence-linked findings, approvals, a live console — and replaces the weak parts:
scope is enforced in code, findings are verified, code and fuzzing are first-class,
and every action is budgeted and recorded.

## What is inside

- **18 real engines** across secrets, JS/TS/Python/Go taint analysis, dependencies,
  Docker, Kubernetes, Terraform, GitHub Actions, Nginx, OpenAPI, GraphQL, TLS,
  web surface, containers, native binaries, SBOM, licenses and patch diffs.
- **Coverage-guided fuzzing** for JavaScript and Python with V8/Python coverage,
  corpus evolution, crash/hang detection and delta minimization.
- **Differential zero-day lab**: discovers ESM/CommonJS/Python functions, infers
  parameter roles from names *and* sink dataflow, tests 18 attack families with
  benign, sanitized and hostile inputs,
  confirms effects through oracles (file escape, execution, private network,
  prototype pollution, unescaped HTML, XXE, CRLF, CSV, mass assignment, timing,
  numeric boundaries), replays deterministically and writes a PoC bundle.
- **Interprocedural taint** across function and file boundaries, plus invariant
  mining at length/numeric/regex guards.
- **Active exploit verification** for LFI, RCE, SSTI, SQLi, SSRF, redirect, XSS,
  CRLF and XXE with read-only payloads and response oracles.
- **Foothold collection**: safe `id`/`whoami`/`hostname`/`uname`/`env`/`/etc/hosts`
  reads through confirmed RCE/LFI, system-node mapping and credential extraction.
- **Network and auth tools**: scope-pinned port/banner map, anonymous service
  checks, default Basic/form credentials, JWT weak-secret and alg:none tests.
- **Verification and critique**: replay, reachability, manifest checks, test-file
  downgrades, fingerprint dedupe and an optional AI critic.
- **Autonomy layer**: goal-first API, policy caps, autonomy levels, decision
  receipts, escalations, retries, budget stops, agent identities and webhooks.
- **MCP server** at `POST /api/mcp` with 14 tools for external agents.
- **Agent quickstart** at `POST /api/agent/quickstart`: one call creates an agent
  identity, a goal and a ready MCP config. Discovery at `/.well-known/agent.json`
  and `/llms.txt`.
- **Live console** with SSE event stream, agent DAG, attack graph, findings ledger,
  operations console, fuzzing lab, benchmark and signed report exports.
- **Hard scope gate**: DNS resolution, domain/CIDR allow-list, deny rules, port and
  scheme policy, private-IP block, redirect re-validation, request budget and rate
  limiting. Requests are pinned to the resolved IP.

## Quick start

Requirements: Node.js 24+, Python 3.11+ (for Python analysis), Git (for history and
patch diffs), Docker (optional, for image inspection).

```bash
npm install
npm run build
npm start
```

On Windows you can double-click `start-kestrel.cmd` after `npm install && npm run build`.

Open `http://127.0.0.1:8787`. On first boot the administrator email and a generated
password are printed once. Set `KESTREL_ADMIN_PASSWORD` before the first start to
choose your own.

For development:

```bash
npm run dev
```

The API runs on `:8787`, Vite on `:5173`.

## Docker

```bash
cp .env.example .env
# set KESTREL_ADMIN_PASSWORD
docker compose up -d --build
```

The service binds to `127.0.0.1` by default. Put a TLS reverse proxy in front for
remote access. Data lives in the `kestrel-data` volume.

## First run

1. Sign in.
2. Open **Benchmark** and run it. This proves the pipeline end to end and gives you
   a precision/recall baseline.
3. Create a project (ZIP upload or path import) or scope a web target.
4. Prefer **Autonomy → New goal** for machine-style operation, or **New scan** for
   explicit control.

## Autonomy

Autonomy levels:

| Level | Behavior |
| --- | --- |
| `observe` | Plan only, no scan |
| `propose` | Plan and wait for approval |
| `supervised` | Start when policy allows, escalate on risk |
| `autonomous` | Plan, run, verify and close within hard caps |

Hard caps: concurrent goals, requests per goal, model cost, duration, allowed
surfaces and optional domain allow-list. The controller retries a failed scan once,
stops on budget/deadline, and writes every decision with actor, rationale and
confidence to the decision log.

### MCP

Create an agent identity under **Autonomy → Machine access**. Then:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
  "name":"kestrel_create_goal",
  "arguments":{"objective":"Prove tenant isolation on the orders API",
    "target":"https://staging.example.com","targetType":"api","autonomyLevel":"propose"}
}}
```

`Authorization: Bearer kag_…`. Tools: `create_goal`, `get_goal`, `list_goals`,
`approve_goal`, `get_scan`, `list_findings`, `retest_finding`, `export_report`,
`get_coverage`, `get_policy`, `add_decision`, `start_research`, `get_research`,
`list_hypotheses`, `get_poc`.

The fastest path for an agent is **Agent → Quickstart** in the UI or
`POST /api/agent/quickstart`. It returns a one-time token and MCP config.
See `AGENT.md` and `docs/AGENT-QUICKSTART.md`.

### Webhooks

Register an HTTPS endpoint in the same tab. Payloads are signed with
`x-kestrel-signature: sha256=…` using the per-hook secret. Events include
`scan.done`, `scan.failed`, `goal.complete` and `*`.

## API

OpenAPI: `GET /api/openapi.json`. Bearer tokens are created under
**Settings → API tokens** or as an agent identity. Health is public:
`GET /api/health`.

Primary resources: `/goals`, `/scans`, `/findings`, `/autonomy/policy`,
`/webhooks`, `/agent-identities`, `/reports`.

## Benchmark

`fixtures/vulnlab` contains 78 seeded issues across source, Python, secrets,
dependencies, Docker, Kubernetes, Terraform, CI, OpenAPI and Nginx. The benchmark
runner copies the fixture, executes the full pipeline, matches findings by rule and
file, and stores precision, recall and F1. Latest local baseline: **100 %
precision, 100 % recall, F1 100** on the curated corpus.

## Security model

- scrypt password hashing, HttpOnly session cookies, CSRF tokens, RBAC, rate limits
- CSP, HSTS (when TLS), COOP/CORP, nosniff, frame denial
- AES-256-GCM for provider keys, master key on disk with `0600`
- root-confined file access, worker-isolated plugins with explicit permissions
- untrusted tool output wrapped in nonce delimiters before any model call
- SHA-256 evidence and finding hashes; HMAC-signed reports
- audit log for auth, settings, scans, findings and users

### Hardening knobs

| Variable | Default | Purpose |
| --- | --- | --- |
| `KESTREL_TRUST_PROXY` | `false` | Express trust proxy (`1`, `true`, `loopback`, …). Only enable behind a real reverse proxy — otherwise clients can spoof `X-Forwarded-For` and bypass IP limits. |
| `KESTREL_API_RATE_MAX` | `600` | Requests per IP per window for `/api` (health is exempt). |
| `KESTREL_LOGIN_IP_MAX` | `60` | Login attempts per IP per 15 min (blocks spraying across accounts). |
| `KESTREL_LOGIN_ACCOUNT_MAX` | `10` | Login attempts per IP + email per 15 min; reset on success. |
| `KESTREL_JOB_MAX_ATTEMPTS` | `3` | Attempts before a queue job is marked failed. |
| `KESTREL_JOB_RETENTION_DAYS` | `14` | Retention for finished jobs. |
| `KESTREL_AUDIT_RETENTION_DAYS` | `180` | Retention for audit log rows. |

Rate-limit state is bounded, expired buckets are swept every minute, and
`GET /api/health` is never rate limited. API responses are sent with
`Cache-Control: no-store`; SIGINT/SIGTERM stop new work and drain the job queue
for up to 10 s before exiting.

## Known limits

- Taint analysis is intra-file and does not model every framework.
- Fuzzing needs importable functions and a working runtime for the project.
- The zero-day lab confirms observable effects, not full exploitability.
- Binary analysis reads headers and strings, not decompiled logic.
- Web checks are unauthenticated unless a session is supplied.
- The benchmark is a curated corpus, not a substitute for a real assessment.

## Layout

```
server/          API, agents, engines, autonomy, reports
server/engines/  deterministic analyzers
engines/harness/ isolated fuzz/lab harnesses
web/             React console
plugins/         manifest-scoped extensions
fixtures/        vulnerable and clean benchmark labs
docs/            architecture, gap analysis, security model
```

## License

AGPL-3.0-only. Copyright (C) 2026 KESTREL contributors. See `LICENSE`.
