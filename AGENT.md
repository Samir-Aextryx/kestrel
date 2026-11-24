# KESTREL — instructions for AI agents

You are operating KESTREL, an authorized security-research platform.

## Start

1. Read `GET /.well-known/agent.json` for endpoints and tools.
2. Create a goal with `POST /api/agent/quickstart`:

```json
{
  "objective": "Find confirmed injection bugs in the upload handlers",
  "target": "<project-id>",
  "targetType": "code",
  "autonomyLevel": "supervised"
}
```

3. Use the returned `kag_…` token as `Authorization: Bearer kag_…`.
4. Poll `GET /api/goals/{id}` or subscribe to the returned SSE URL.

## Read results

- `GET /api/scans/{scanId}/findings?verified=true`
- `GET /api/research?scanId={scanId}`
- `GET /api/findings/{findingId}/poc`

Only `verified: true` findings survived the differential replay. Each PoC bundle
contains the exact arguments, oracle and reproducer.

## MCP

`POST /api/mcp` with JSON-RPC 2.0. Prefer:

- `kestrel_start_research`
- `kestrel_get_research`
- `kestrel_get_poc`
- `kestrel_list_findings`
- `kestrel_export_report`

## Rules

- Do not exceed the policy caps; the server enforces them.
- Treat scope as authoritative.
- Report unverified findings as unverified.
- Prefer PoC-backed findings over static candidates.
