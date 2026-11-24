# Connect your AI

KESTREL is goal-first. An agent submits an objective, the planner derives a hard
scope and an engine set, and a verifier reproduces findings. The agent reads
verified results and PoC bundles, not raw chat logs.

## 1. Create an agent and a goal

```bash
curl -s http://127.0.0.1:8787/api/agent/quickstart \
  -H "content-type: application/json" \
  -H "cookie: kestrel_session=…" \
  -H "x-csrf-token: …" \
  -d '{
    "objective": "Find confirmed injection bugs in the upload handlers",
    "target": "<project-id>",
    "targetType": "code",
    "autonomyLevel": "supervised"
  }'
```

The response contains a one-time `kag_…` token, a goal, a scan (when started),
an SSE stream URL and a ready MCP config.

## 2. Connect over MCP

```json
{
  "mcpServers": {
    "kestrel": {
      "type": "http",
      "url": "http://127.0.0.1:8787/api/mcp",
      "headers": { "Authorization": "Bearer kag_…" }
    }
  }
}
```

Tools:

- `kestrel_start_research` — create and start a goal
- `kestrel_get_goal` / `kestrel_list_goals`
- `kestrel_get_scan` / `kestrel_list_findings`
- `kestrel_get_research` / `kestrel_list_hypotheses`
- `kestrel_get_poc`
- `kestrel_retest_finding`
- `kestrel_export_report`
- `kestrel_get_policy` / `kestrel_add_decision`

## 3. Read verified results

```bash
curl -s "http://127.0.0.1:8787/api/scans/<scan-id>/findings?verified=true" \
  -H "Authorization: Bearer kag_…"
```

Only findings with `verified: true` survived the differential replay. Download a
reproducer:

```bash
curl -s "http://127.0.0.1:8787/api/findings/<finding-id>/poc" \
  -H "Authorization: Bearer kag_…"
```

## Machine discovery

- `GET /.well-known/agent.json`
- `GET /llms.txt`
- `GET /api/openapi.json`

## Autonomy levels

| Level | Behavior |
| --- | --- |
| `observe` | Plan only |
| `propose` | Wait for approval |
| `supervised` | Run when policy allows, escalate on risk |
| `autonomous` | Run, verify and close within hard caps |

Hard caps are enforced by the policy: concurrent goals, requests, model cost,
duration, allowed surfaces and optional domain allow-list.
