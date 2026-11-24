import { useMemo } from "react";
import { Workflow } from "lucide-react";
import { AGENT_LABELS } from "../labels";

type Run = { agent: string; status: string; summary?: string };

const COLUMNS: { stage: string; agents: string[] }[] = [
  { stage: "Plan", agents: ["orchestrator"] },
  { stage: "Surface", agents: ["recon", "code", "secrets", "supply", "iac", "api", "plugins"] },
  { stage: "Dynamic", agents: ["fuzz", "zeroday"] },
  { stage: "Verify", agents: ["verifier", "critic"] },
  { stage: "Deliver", agents: ["correlator", "reporter", "optimizer"] },
];

export function AgentGraph({ runs }: { runs: Run[] }) {
  const statusOf = useMemo(() => {
    const map = new Map<string, { status: string; summary?: string }>();
    for (const run of runs) {
      const current = map.get(run.agent);
      if (current?.status === "done") continue;
      map.set(run.agent, { status: run.status, summary: run.summary });
    }
    return map;
  }, [runs]);
  const running = runs.filter((r) => r.status === "running").length;
  const done = new Set(runs.filter((r) => r.status === "done").map((r) => r.agent)).size;
  const total = COLUMNS.reduce((n, c) => n + c.agents.length, 0);
  return (
    <div className="panel">
      <div className="panel-head">
        <Workflow size={14} color="#2f6f3e" />
        <h2>Agent pipeline</h2>
        <span className="sub">{done}/{total} done</span>
        <div className="right">{running > 0 && <span className="tag">{running} running</span>}</div>
      </div>
      <div className="panel-body" style={{ overflowX: "auto" }}>
        <div className="dag">
          {COLUMNS.map((column) => (
            <div key={column.stage} className="dag-col">
              <div className="dag-stage">{column.stage}</div>
              {column.agents.map((agent) => {
                const entry = statusOf.get(agent);
                const status = entry?.status || "idle";
                return (
                  <div key={agent} className={`agent ${status}`} title={entry?.summary || `${AGENT_LABELS[agent] || agent} · ${status}`}>
                    <span className={`dot ${status}`} />
                    <span className="truncate">{AGENT_LABELS[agent] || agent}</span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
