import { Fragment, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Bot, ExternalLink, KeyRound, Plug, Wrench } from "lucide-react";
import { api } from "../api";
import { useToast } from "../components/Toast";
import { CopyButton, EmptyState, Skeleton, useTitle } from "../components/ui";
import type { Project } from "../types";

type Manifest = {
  name: string;
  version: string;
  description: string;
  endpoints: Record<string, string>;
  tools: string[];
  autonomyLevels: string[];
  transports: string[];
  limits: Record<string, number>;
};

type Quickstart = {
  agent: { id: string; name: string; token: string };
  goal: { id: string; title: string; status: string; scan_id?: string | null };
  endpoints: Record<string, string | null>;
  mcpConfig: unknown;
};

const SURFACES = ["code", "web", "api", "container", "iac", "binary", "mixed"];
const PROJECT_SURFACES = ["code", "binary", "iac", "mixed"];
const LEVELS = ["observe", "propose", "supervised", "autonomous"];

export default function Agent() {
  useTitle("Agent access");
  const toast = useToast();
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [form, setForm] = useState({ objective: "", targetType: "code", projectId: "", target: "", autonomyLevel: "supervised" });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Quickstart | null>(null);

  useEffect(() => {
    api.get<Manifest>("/agent/capabilities").then(setManifest).catch(() => {});
    api.get<Project[]>("/projects").then(setProjects).catch(() => {});
  }, []);

  const usesProject = PROJECT_SURFACES.includes(form.targetType);
  const target = usesProject ? form.projectId : form.target.trim();
  const valid = form.objective.trim() && target;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid) return;
    setBusy(true);
    try {
      const data = await api.post<Quickstart>("/agent/quickstart", {
        objective: form.objective.trim(),
        target,
        targetType: form.targetType,
        projectId: usesProject ? form.projectId : undefined,
        autonomyLevel: form.autonomyLevel,
      });
      setResult(data);
      toast.push("success", "Agent and goal created");
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Quickstart failed");
    } finally {
      setBusy(false);
    }
  }

  const mcpJson = result ? JSON.stringify(result.mcpConfig, null, 2) : "";

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Machine access</div>
          <h1>Agent</h1>
          <p>Create a goal and an agent token in one step, then connect your agent over MCP.</p>
        </div>
        <div className="actions"><a className="btn btn-ghost" href="/api/llms.txt" target="_blank" rel="noreferrer">llms.txt <ExternalLink size={12} /></a></div>
      </div>

      <div className="grid grid-2">
        <form className="panel" onSubmit={submit}>
          <div className="panel-head"><Bot size={14} color="#2f6f3e" /><h2>Quickstart</h2><span className="sub">POST /api/agent/quickstart</span></div>
          <div className="panel-body grid" style={{ gap: 12 }}>
            <div className="field">
              <label htmlFor="ag-objective">Objective</label>
              <textarea id="ag-objective" className="textarea" value={form.objective} onChange={(e) => setForm({ ...form, objective: e.target.value })} placeholder="Find injection bugs in the upload handlers" required />
            </div>
            <div className="field">
              <label htmlFor="ag-surface">Surface</label>
              <select id="ag-surface" className="select" value={form.targetType} onChange={(e) => setForm({ ...form, targetType: e.target.value })}>
                {SURFACES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            {usesProject ? (
              <div className="field">
                <label htmlFor="ag-project">Project</label>
                <select id="ag-project" className="select" value={form.projectId} onChange={(e) => setForm({ ...form, projectId: e.target.value })} required>
                  <option value="">Select…</option>
                  {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
                {!projects.length && <span className="hint">Upload a project under <Link to="/scans/new">New scan</Link> first.</span>}
              </div>
            ) : (
              <div className="field">
                <label htmlFor="ag-target">URL</label>
                <input id="ag-target" className="input" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} placeholder="https://staging.example.com" required />
                <span className="hint">Only targets you are authorized to test.</span>
              </div>
            )}
            <div className="field">
              <label htmlFor="ag-level">Autonomy</label>
              <select id="ag-level" className="select" value={form.autonomyLevel} onChange={(e) => setForm({ ...form, autonomyLevel: e.target.value })}>
                {(manifest?.autonomyLevels ?? LEVELS).map((l) => <option key={l}>{l}</option>)}
              </select>
            </div>
            <div><button className="btn btn-primary" type="submit" disabled={busy || !valid}>{busy ? <span className="spinner" /> : <KeyRound size={14} />} Create agent & goal</button></div>
          </div>
        </form>

        <div className="panel">
          <div className="panel-head"><Plug size={14} color="#0f766e" /><h2>Connection</h2></div>
          <div className="panel-body grid" style={{ gap: 12 }}>
            {result ? (
              <>
                <div className="callout warn">
                  <b>Token shown once.</b> Store it now; it cannot be retrieved later.
                  <div className="secret-box"><code className="code">{result.agent.token}</code><CopyButton value={result.agent.token} /></div>
                </div>
                <div>
                  <div className="flex"><b className="small">MCP config</b><span className="ml-auto"><CopyButton value={mcpJson} /></span></div>
                  <pre className="code mt-8">{mcpJson}</pre>
                </div>
                <dl className="kv">
                  <dt>Agent</dt><dd className="mono small">{result.agent.name}</dd>
                  <dt>Goal</dt><dd>{result.goal.title} <span className="tag">{result.goal.status}</span></dd>
                </dl>
                <div className="flex flex-wrap">
                  <Link to="/autonomy" className="btn btn-sm">Goals</Link>
                  {result.goal.scan_id && <Link to={`/scans/${result.goal.scan_id}`} className="btn btn-sm">Open scan</Link>}
                  {result.goal.scan_id && <Link to={`/research?scanId=${result.goal.scan_id}`} className="btn btn-sm">Research</Link>}
                </div>
                <div className="grid" style={{ gap: 6 }}>
                  {Object.entries(result.endpoints).filter(([, v]) => v).map(([k, v]) => (
                    <div key={k} className="flex small"><span className="dim" style={{ width: 70 }}>{k}</span><span className="mono truncate">{v}</span></div>
                  ))}
                </div>
              </>
            ) : (
              <EmptyState compact icon={<KeyRound size={18} />} title="No token yet" text="Submit the form to get a one-time token and a ready-to-paste MCP config." />
            )}
          </div>
        </div>
      </div>

      <div className="panel mt-16">
        <div className="panel-head">
          <Wrench size={14} color="#2f6f3e" /><h2>Tools</h2><span className="sub">GET /api/agent/capabilities</span>
          <div className="right"><span className="tag">{manifest?.tools.length ?? 0}</span></div>
        </div>
        <div className="panel-body">
          {manifest ? (
            <>
              <div className="flex flex-wrap">{manifest.tools.map((t) => <span key={t} className="tag mono">{t}</span>)}</div>
              <dl className="kv mt-16">
                {Object.entries(manifest.endpoints).map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd className="mono small">{v}</dd></Fragment>)}
                <dt>Transports</dt><dd>{manifest.transports.join(", ")}</dd>
                <dt>llms.txt</dt><dd><a href="/api/llms.txt" target="_blank" rel="noreferrer" className="mono small">/api/llms.txt</a></dd>
              </dl>
            </>
          ) : <div className="grid" style={{ gap: 8 }}><Skeleton height={12} /><Skeleton height={12} width="70%" /></div>}
        </div>
      </div>
    </>
  );
}
