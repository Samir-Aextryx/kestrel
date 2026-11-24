import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Bot, Check, GitBranch, Plus, ShieldCheck, Webhook, X } from "lucide-react";
import { api } from "../api";
import { useToast } from "../components/Toast";
import { CopyButton, EmptyState, Modal, StatusBadge, TimeAgo, useTitle } from "../components/ui";
import type { Project } from "../types";

type Policy = { level: string; maxConcurrent: number; maxRequests: number; maxCost: number; maxDurationMin: number; allowedTypes: string[]; allowedDomains: string[]; autoApprove: boolean; escalateOn: string[] };
type Goal = { id: string; title: string; objective: string; target: string; target_type: string; autonomy_level: string; status: string; created_at: string; decisions: number; plan: { engines: string[]; rationale: string }; scan?: { id: string; status: string } };
type Decision = { id: string; goal_id: string; goal_title: string; actor: string; kind: string; rationale: string; confidence: string; created_at: string };
type Agent = { id: string; name: string; scopes_json: string; enabled: number; last_seen?: string; created_at: string };
type Hook = { id: string; url: string; events: string[]; enabled: number; last_status?: number; created_at: string };

const LEVELS = [
  ["observe", "Observe", "Plan only; never starts a scan."],
  ["propose", "Propose", "Plan and wait for explicit approval."],
  ["supervised", "Supervised", "Run automatically when policy allows, escalate on risk."],
  ["autonomous", "Autonomous", "Plan, run, verify and close within hard caps."],
];

export default function Autonomy() {
  useTitle("Autonomy");
  const toast = useToast();
  const [tab, setTab] = useState<"goals" | "policy" | "decisions" | "access">("goals");
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [goals, setGoals] = useState<Goal[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [hooks, setHooks] = useState<Hook[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [modal, setModal] = useState(false);
  const [newToken, setNewToken] = useState("");
  const [form, setForm] = useState<Record<string, string>>({ targetType: "code", autonomyLevel: "supervised" });

  const load = () => {
    api.get<Policy>("/autonomy/policy").then(setPolicy).catch(() => {});
    api.get<Goal[]>("/goals").then(setGoals).catch(() => {});
    api.get<Agent[]>("/agent-identities").then(setAgents).catch(() => {});
    api.get<Hook[]>("/webhooks").then(setHooks).catch(() => {});
    api.get<Project[]>("/projects").then(setProjects).catch(() => {});
  };
  useEffect(() => {
    load();
    const timer = setInterval(load, 6000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (tab === "decisions") api.get<Decision[]>("/decisions").then(setDecisions).catch(() => {});
  }, [tab]);

  async function savePolicy() {
    if (!policy) return;
    try {
      setPolicy(await api.put<Policy>("/autonomy/policy", policy));
      toast.push("success", "Policy saved");
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Save failed");
    }
  }

  async function createGoal() {
    try {
      const goal = await api.post<Goal>("/goals", {
        title: form.title,
        objective: form.objective,
        target: ["code", "binary", "iac", "mixed"].includes(form.targetType) ? form.projectId : form.target,
        targetType: form.targetType,
        projectId: form.projectId || null,
        autonomyLevel: form.autonomyLevel,
        maxRequests: form.maxRequests ? Number(form.maxRequests) : undefined,
        maxCost: form.maxCost ? Number(form.maxCost) : undefined,
      });
      toast.push("success", "Goal created");
      setModal(false);
      setForm({ targetType: "code", autonomyLevel: "supervised" });
      setGoals(await api.get<Goal[]>("/goals"));
      if (goal.scan?.id) window.location.href = `/scans/${goal.scan.id}`;
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Goal failed");
    }
  }

  async function act(id: string, action: "approve" | "reject" | "start") {
    try {
      await api.post(`/goals/${id}/${action}`, action === "reject" ? { reason: "Rejected in console" } : {});
      toast.push("success", `Goal ${action}d`);
      load();
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Action failed");
    }
  }

  async function createAgent() {
    try {
      const result = await api.post<{ token: string }>("/agent-identities", { name: form.agentName, scopes: ["read", "write", "goals"] });
      setNewToken(result.token);
      setAgents(await api.get<Agent[]>("/agent-identities"));
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Create failed");
    }
  }

  async function createHook() {
    try {
      await api.post("/webhooks", { url: form.hookUrl, events: ["scan.done", "scan.failed", "goal.complete"] });
      toast.push("success", "Webhook created");
      setHooks(await api.get<Hook[]>("/webhooks"));
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Create failed");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Machine operation</div>
          <h1>Autonomy</h1>
          <p>Goal-first control for autonomous agents: policy caps, machine identity, decision receipts, escalation and MCP.</p>
        </div>
        <div className="actions"><button className="btn btn-primary" onClick={() => setModal(true)}><Plus size={14} /> New goal</button></div>
      </div>
      <div className="tabs">
        {[["goals", "Goals"], ["policy", "Policy"], ["decisions", "Decision log"], ["access", "Machine access"]].map(([id, label]) => (
          <button key={id} className={`tab ${tab === id ? "on" : ""}`} onClick={() => setTab(id as typeof tab)}>{label}</button>
        ))}
      </div>

      {tab === "goals" && (
        <div className="grid" style={{ gap: 10 }}>
          {goals.length ? goals.map((goal) => (
            <div key={goal.id} className="panel">
              <div className="panel-head">
                <Bot size={15} color="#2f6f3e" />
                <h2>{goal.title}</h2>
                <span className={`badge level-${goal.autonomy_level}`}>{goal.autonomy_level}</span>
                <div className="right"><StatusBadge status={goal.status === "running" ? "running" : goal.status === "complete" ? "done" : goal.status === "failed" ? "failed" : "queued"} /><span className="dim small">{goal.status}</span></div>
              </div>
              <div className="panel-body">
                <p className="small muted">{goal.objective}</p>
                <div className="flex small mt-8"><span className="mono dim truncate">{goal.target}</span><span className="tag ml-auto">{goal.plan.engines.length} engines</span><span className="dim">{goal.decisions} decisions</span></div>
                <div className="callout mt-8 small">{goal.plan.rationale}</div>
                {goal.status === "running" && <div className="progress thin mt-8"><span style={{ width: "45%" }} /></div>}
                <div className="flex mt-8">
                  {goal.status === "awaiting_approval" && <><button className="btn btn-sm btn-primary" onClick={() => act(goal.id, "approve")}><Check size={12} /> Approve</button><button className="btn btn-sm btn-danger" onClick={() => act(goal.id, "reject")}><X size={12} /> Reject</button></>}
                  {goal.status === "planned" && <button className="btn btn-sm" onClick={() => act(goal.id, "start")}>Start</button>}
                  {goal.scan && <Link className="btn btn-sm ml-auto" to={`/scans/${goal.scan.id}`}><GitBranch size={12} /> Open scan</Link>}
                  <span className="dim small ml-auto"><TimeAgo value={goal.created_at} /></span>
                </div>
              </div>
            </div>
          )) : <EmptyState icon={<Bot size={28} />} title="No goals" text="Create a goal and let the planner build the scope." />}
        </div>
      )}

      {tab === "policy" && policy && (
        <div className="grid grid-2">
          <div className="panel">
            <div className="panel-head"><ShieldCheck size={15} color="#2f6f3e" /><h2>Autonomy level</h2></div>
            <div className="panel-body grid" style={{ gap: 8 }}>
              {LEVELS.map(([id, label, desc]) => (
                <label key={id} className="check"><input type="radio" checked={policy.level === id} onChange={() => setPolicy({ ...policy, level: id })} /><span><span className="t">{label}</span><span className="d">{desc}</span></span></label>
              ))}
            </div>
          </div>
          <div className="panel">
            <div className="panel-head"><h2>Hard caps</h2></div>
            <div className="panel-body grid grid-2">
              <div className="field"><label>Concurrent goals</label><input className="input" type="number" min={1} max={8} value={policy.maxConcurrent} onChange={(e) => setPolicy({ ...policy, maxConcurrent: Number(e.target.value) })} /></div>
              <div className="field"><label>Requests / goal</label><input className="input" type="number" value={policy.maxRequests} onChange={(e) => setPolicy({ ...policy, maxRequests: Number(e.target.value) })} /></div>
              <div className="field"><label>Model cost / goal (USD)</label><input className="input" type="number" step="0.1" value={policy.maxCost} onChange={(e) => setPolicy({ ...policy, maxCost: Number(e.target.value) })} /></div>
              <div className="field"><label>Max duration (min)</label><input className="input" type="number" value={policy.maxDurationMin} onChange={(e) => setPolicy({ ...policy, maxDurationMin: Number(e.target.value) })} /></div>
              <label className="check" style={{ gridColumn: "span 2" }}><input type="checkbox" checked={policy.autoApprove} onChange={(e) => setPolicy({ ...policy, autoApprove: e.target.checked })} /><span><span className="t">Auto-approve supervised goals</span><span className="d">Autonomous level always starts within caps.</span></span></label>
              <div className="field" style={{ gridColumn: "span 2" }}><label>Policy domain allow-list</label><textarea className="textarea" value={policy.allowedDomains.join("\n")} onChange={(e) => setPolicy({ ...policy, allowedDomains: e.target.value.split("\n").filter(Boolean) })} placeholder="example.com" /></div>
            </div>
          </div>
          <div className="span-2"><button className="btn btn-primary" onClick={savePolicy}>Save policy</button></div>
        </div>
      )}

      {tab === "decisions" && (
        <div className="panel">
          <div className="panel-head"><h2>Decision log</h2><span className="sub">signed actor + rationale</span></div>
          {decisions.length ? <div className="table-wrap"><table className="data"><thead><tr><th>Time</th><th>Actor</th><th>Goal</th><th>Decision</th><th>Rationale</th><th>Confidence</th></tr></thead><tbody>
            {decisions.map((d) => <tr key={d.id}><td className="dim"><TimeAgo value={d.created_at} /></td><td className="mono small">{d.actor}</td><td>{d.goal_title}</td><td><span className="tag">{d.kind}</span></td><td className="small">{d.rationale}</td><td>{d.confidence}</td></tr>)}
          </tbody></table></div> : <EmptyState title="No decisions" text="Planner and policy decisions appear here." />}
        </div>
      )}

      {tab === "access" && (
        <div className="grid grid-2">
          <div className="panel">
            <div className="panel-head"><Bot size={15} color="#2f6f3e" /><h2>Agent identities</h2></div>
            <div className="panel-body grid" style={{ gap: 8 }}>
              <div className="field"><label>Agent name</label><div className="flex"><input className="input" value={form.agentName || ""} onChange={(e) => setForm({ ...form, agentName: e.target.value })} placeholder="triage-agent" /><button className="btn" onClick={createAgent}><Plus size={13} /></button></div></div>
              {newToken && <div className="callout warn"><div className="small">Token shown once</div><div className="flex mt-8"><code className="code" style={{ flex: 1 }}>{newToken}</code><CopyButton value={newToken} /></div></div>}
              {agents.map((a) => <div key={a.id} className="callout flex"><b>{a.name}</b><span className="tag">{a.scopes_json}</span><span className="ml-auto dim small">{a.last_seen ? <TimeAgo value={a.last_seen} /> : "never used"}</span></div>)}
              <div className="callout small">MCP endpoint: <span className="mono">POST /api/mcp</span> with <span className="mono">Authorization: Bearer kag_…</span>. Tools: create_goal, approve_goal, list_findings, retest, export.</div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-head"><Webhook size={15} color="#0f766e" /><h2>Webhooks</h2></div>
            <div className="panel-body grid" style={{ gap: 8 }}>
              <div className="field"><label>HTTPS endpoint</label><div className="flex"><input className="input" value={form.hookUrl || ""} onChange={(e) => setForm({ ...form, hookUrl: e.target.value })} placeholder="https://agent.example/hook" /><button className="btn" onClick={createHook}><Plus size={13} /></button></div></div>
              {hooks.map((h) => <div key={h.id} className="callout"><div className="flex"><span className="mono small truncate">{h.url}</span><span className="tag ml-auto">{h.last_status ?? "—"}</span></div><div className="small dim">{h.events.join(", ")}</div></div>)}
              <div className="callout small">Payloads are HMAC-SHA256 signed in <span className="mono">x-kestrel-signature</span>.</div>
            </div>
          </div>
        </div>
      )}

      {modal && (
        <Modal title="New autonomous goal" onClose={() => setModal(false)} footer={<><button className="btn" onClick={() => setModal(false)}>Cancel</button><button className="btn btn-primary" onClick={createGoal}>Plan goal</button></>}>
          <div className="grid" style={{ gap: 10 }}>
            <div className="field"><label>Title</label><input className="input" value={form.title || ""} onChange={(e) => setForm({ ...form, title: e.target.value })} /></div>
            <div className="field"><label>Objective</label><textarea className="textarea" value={form.objective || ""} onChange={(e) => setForm({ ...form, objective: e.target.value })} placeholder="Prove whether the checkout API leaks another tenant's orders" /></div>
            <div className="field"><label>Surface</label><select className="select" value={form.targetType} onChange={(e) => setForm({ ...form, targetType: e.target.value })}>{["code", "web", "api", "container", "iac", "binary", "mixed"].map((t) => <option key={t}>{t}</option>)}</select></div>
            {["code", "binary", "iac", "mixed"].includes(form.targetType) ? (
              <div className="field"><label>Project</label><select className="select" value={form.projectId || ""} onChange={(e) => setForm({ ...form, projectId: e.target.value })}><option value="">Select…</option>{projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></div>
            ) : (
              <div className="field"><label>Target</label><input className="input" value={form.target || ""} onChange={(e) => setForm({ ...form, target: e.target.value })} /></div>
            )}
            <div className="field"><label>Autonomy level</label><select className="select" value={form.autonomyLevel} onChange={(e) => setForm({ ...form, autonomyLevel: e.target.value })}>{LEVELS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></div>
            <div className="grid grid-2">
              <div className="field"><label>Max requests</label><input className="input" type="number" value={form.maxRequests || ""} onChange={(e) => setForm({ ...form, maxRequests: e.target.value })} /></div>
              <div className="field"><label>Max cost</label><input className="input" type="number" step="0.1" value={form.maxCost || ""} onChange={(e) => setForm({ ...form, maxCost: e.target.value })} /></div>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}
