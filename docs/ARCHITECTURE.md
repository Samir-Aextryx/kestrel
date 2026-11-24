# Architecture

## Execution

`goal → planner → policy → scan → agents → engines → verifier → critic → correlator → reporter → optimizer`

The planner is a deterministic heuristic with optional model refinement. It may only
select engines valid for the surface. The policy layer clamps scope, requests, cost
and duration. A goal can wait for approval, run supervised, or run autonomously
within the caps.

Scans are persisted jobs. A job queue with concurrency 2 executes them; running jobs
are requeued on restart. Every agent run, event, finding, evidence record and report
is stored in SQLite (WAL).

## Evidence

Every network request goes through `ScopeGate`. It resolves DNS, checks all addresses
against allow/deny rules and private ranges, pins the connection to the resolved IP,
re-validates redirects, enforces port/scheme policy and a request budget. Request and
response bodies are hashed and stored as evidence.

Findings carry a fingerprint, SHA-256 hash and verification record. Reports are
hashed and HMAC-signed.

## Isolation

- Engines run in the server process but only receive a file list and a root-confined
  reader.
- Fuzzing and the zero-day lab run in child processes with memory caps and timeouts.
- Plugins run in worker threads with manifest permissions (`fs`, `net`), a 60 s
  timeout and a 256 MB heap cap.
- Model output is data. Tool output is wrapped with nonce delimiters.

## Autonomy

The controller ticks every 15 s. It starts eligible goals, enforces concurrency,
detects completion/failure, retries once, stops on budget/deadline, and records each
decision. It never expands scope without a new plan.

## Data model

`users`, `sessions`, `workspaces`, `projects`, `scans`, `assets`, `findings`,
`evidence`, `events`, `agent_runs`, `fuzz_runs`, `fuzz_crashes`, `plugins`,
`settings`, `audit_log`, `llm_calls`, `rule_stats`, `benchmarks`, `reports`,
`api_tokens`, `approvals`, `jobs`, `agent_identities`, `policies`, `goals`,
`decisions`, `webhooks`, `experiments`, `goal_events`.
