import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  ArrowLeft, ArrowRight, Boxes, Braces, Check, Cloud, Code2, Container, FileArchive, Gauge, Globe, Layers, Radar, ShieldCheck, Upload,
} from "lucide-react";
import { api } from "../api";
import { useToast } from "../components/Toast";
import { EmptyState, Orb, SkeletonRows, useTitle } from "../components/ui";
import type { Engine, Project } from "../types";

const TYPES = [
  { id: "code", label: "Source code", icon: Code2, desc: "SAST, secrets, supply chain, fuzzing, zero-day lab" },
  { id: "web", label: "Web surface", icon: Globe, desc: "Headers, TLS, cookies, CORS, exposed files" },
  { id: "api", label: "API contract", icon: Braces, desc: "OpenAPI/GraphQL auth, bounds and exposure" },
  { id: "container", label: "Container image", icon: Container, desc: "Image config, history and runtime hardening" },
  { id: "iac", label: "Infrastructure", icon: Cloud, desc: "Docker, K8s, Terraform, CI, Nginx" },
  { id: "binary", label: "Native binary", icon: Layers, desc: "ELF/PE/Mach-O hardening and embedded secrets" },
  { id: "mixed", label: "Mixed", icon: Boxes, desc: "Code + live surface in one correlated run" },
];

const STEPS = [
  { label: "Target", hint: "Surface and asset" },
  { label: "Scope & engines", hint: "Budget and coverage" },
  { label: "Review", hint: "Confirm and launch" },
];

export default function ScanNew() {
  useTitle("New scan");
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const toast = useToast();
  const [step, setStep] = useState(0);
  const [type, setType] = useState("code");
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [projectId, setProjectId] = useState(params.get("project") || "");
  const [projects, setProjects] = useState<Project[]>([]);
  const [engines, setEngines] = useState<Engine[]>([]);
  const [enginesLoaded, setEnginesLoaded] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [allow, setAllow] = useState("");
  const [ports, setPorts] = useState("443");
  const [budget, setBudget] = useState(400);
  const [rate, setRate] = useState(8);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [approval, setApproval] = useState(false);
  const [fuzzIterations, setFuzzIterations] = useState(180);
  const [labFunctions, setLabFunctions] = useState(6);
  const [llmReview, setLlmReview] = useState(true);
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    api.get<Project[]>("/projects").then(setProjects).catch(() => {});
    api.get<Engine[]>("/engines").then(setEngines).catch(() => {}).finally(() => setEnginesLoaded(true));
  }, []);

  const available = useMemo(() => engines.filter((e) => e.targetTypes.includes(type) || e.targetTypes.includes("*")), [engines, type]);
  useEffect(() => {
    setSelected(available.map((e) => e.id));
  }, [available]);

  const needsProject = ["code", "binary", "iac", "mixed"].includes(type);
  const needsUrl = ["web", "api"].includes(type);
  const needsImage = type === "container";
  const surface = TYPES.find((t) => t.id === type) ?? TYPES[0];
  const projectName = projects.find((p) => p.id === projectId)?.name;

  function next() {
    if (step === 0) {
      if (!name.trim()) return toast.push("warn", "Give the scan a name");
      if (needsProject && !projectId) return toast.push("warn", "Select or upload a project");
      if (needsUrl && !/^https?:\/\//.test(target)) return toast.push("warn", "Enter an http(s) URL");
      if (needsImage && !target.trim()) return toast.push("warn", "Enter an image reference");
    }
    setStep((s) => Math.min(2, s + 1));
  }

  async function upload(file: File) {
    setUploading(true);
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("name", file.name.replace(/\.zip$/i, ""));
      const result = await api.post<{ id: string }>("/projects/upload", form);
      const list = await api.get<Project[]>("/projects");
      setProjects(list);
      setProjectId(result.id);
      toast.push("success", "Project uploaded");
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  async function launch() {
    setBusy(true);
    try {
      const scope = needsUrl
        ? {
            allow: allow.split(/[\s,]+/).filter(Boolean),
            ports: ports.split(",").map(Number).filter(Boolean),
            schemes: ["https", "http"],
            allowPrivate,
            maxRequests: budget,
            ratePerSec: rate,
          }
        : {};
      const result = await api.post<{ id: string }>("/scans", {
        name,
        targetType: type,
        target: needsUrl || needsImage ? target : projectId,
        projectId: needsProject ? projectId : null,
        scope,
        requireApproval: approval,
        config: {
          engines: selected,
          fuzzIterations,
          labMaxFunctions: labFunctions,
          llmCodeReview: llmReview,
          llmCritic: llmReview,
        },
      });
      toast.push("success", "Scan queued");
      navigate(`/scans/${result.id}`);
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Could not create scan");
    } finally {
      setBusy(false);
    }
  }

  let allowLabel = allow.trim();
  if (needsUrl && !allowLabel) {
    try { allowLabel = new URL(target).hostname; } catch { allowLabel = "—"; }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">New research run</div>
          <h1>Scope a scan</h1>
          <p>Pick a surface, set a hard budget and choose the engines. Active tests wait for approval when requested.</p>
        </div>
      </div>

      <nav className="stepper" aria-label="Wizard progress">
        {STEPS.map((item, idx) => (
          <button
            key={item.label}
            type="button"
            className={`step ${idx === step ? "on" : ""} ${idx < step ? "done" : ""}`}
            disabled={idx >= step}
            onClick={() => setStep(idx)}
            aria-current={idx === step ? "step" : undefined}
          >
            <span className="step-n">{idx < step ? <Check size={13} /> : idx + 1}</span>
            <span className="step-t"><b>{item.label}</b><span>{item.hint}</span></span>
          </button>
        ))}
      </nav>

      {step === 0 && (
        <div className="grid grid-2">
          <div className="panel">
            <div className="panel-head"><Radar size={15} color="#2f6f3e" /><h2>Surface</h2><span className="sub">{TYPES.length} kinds</span></div>
            <div className="panel-body">
              <div className="surface-grid" role="radiogroup" aria-label="Target surface">
                {TYPES.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    role="radio"
                    aria-checked={type === item.id}
                    className={`surface ${type === item.id ? "on" : ""}`}
                    onClick={() => { setType(item.id); setTarget(""); }}
                  >
                    <span className="surface-icon"><item.icon size={16} /></span>
                    <span><span className="t">{item.label}</span><span className="d">{item.desc}</span></span>
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-head"><ShieldCheck size={15} color="#0f766e" /><h2>Target</h2><span className="sub">{surface.label.toLowerCase()}</span></div>
            <div className="panel-body grid" style={{ gap: 16 }}>
              <div className="field">
                <label htmlFor="scan-name">Scan name</label>
                <input id="scan-name" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Checkout service — pre-release" />
              </div>
              {needsProject && (
                <div className="field">
                  <label htmlFor="scan-project">Project</label>
                  <select id="scan-project" className="select" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
                    <option value="">Select a project…</option>
                    {projects.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.files} files</option>)}
                  </select>
                  <div className="flex flex-wrap" style={{ marginTop: 4 }}>
                    <label className="btn btn-sm" aria-disabled={uploading}>
                      {uploading ? <span className="spinner" /> : <Upload size={13} />} {uploading ? "Uploading…" : "Upload ZIP"}
                      <input type="file" accept=".zip" hidden disabled={uploading} onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
                    </label>
                    {projectName && <span className="tag"><Check size={10} /> {projectName}</span>}
                  </div>
                  {!projects.length && <span className="hint"><FileArchive size={11} /> Upload a ZIP or import a path under Settings → Projects.</span>}
                </div>
              )}
              {needsUrl && (
                <div className="field">
                  <label htmlFor="scan-url">Base URL</label>
                  <input id="scan-url" className="input mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://staging.example.com" inputMode="url" />
                  <span className="hint">DNS is resolved and every redirect is re-validated against scope.</span>
                </div>
              )}
              {needsImage && (
                <div className="field">
                  <label htmlFor="scan-image">Image reference</label>
                  <input id="scan-image" className="input mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="registry/app:tag" />
                  <span className="hint">Requires a local Docker daemon.</span>
                </div>
              )}
              <div className="callout flex small">
                <Orb tone={enginesLoaded && available.length ? "cyan" : "dim"} size={6} />
                {enginesLoaded ? `${available.length} engines support this surface. Narrow them in the next step.` : "Loading engine catalog…"}
              </div>
            </div>
          </div>
        </div>
      )}

      {step === 1 && (
        <div className="grid grid-2">
          <div className="panel">
            <div className="panel-head"><ShieldCheck size={15} color="#0f766e" /><h2>Hard scope</h2><span className="sub">{needsUrl ? "network" : "filesystem"}</span></div>
            <div className="panel-body grid" style={{ gap: 14 }}>
              {needsUrl ? (
                <>
                  <div className="field">
                    <label htmlFor="scope-allow">Allow-list</label>
                    <textarea id="scope-allow" className="textarea" value={allow} onChange={(e) => setAllow(e.target.value)} placeholder={"example.com\napi.example.com\n10.0.0.0/24"} />
                    <span className="hint">Domains include subdomains. CIDR and IP entries are supported.</span>
                  </div>
                  <div className="grid grid-3">
                    <div className="field"><label htmlFor="scope-ports">Ports</label><input id="scope-ports" className="input mono" value={ports} onChange={(e) => setPorts(e.target.value)} /></div>
                    <div className="field"><label htmlFor="scope-budget">Requests</label><input id="scope-budget" className="input mono" type="number" min={1} max={20000} value={budget} onChange={(e) => setBudget(Number(e.target.value))} /></div>
                    <div className="field"><label htmlFor="scope-rate">Per second</label><input id="scope-rate" className="input mono" type="number" min={1} max={100} value={rate} onChange={(e) => setRate(Number(e.target.value))} /></div>
                  </div>
                  <label className="check"><input type="checkbox" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} /><span><span className="t">Allow private addresses</span><span className="d">Needed for localhost, Docker and RFC1918 targets.</span></span></label>
                </>
              ) : <div className="callout">This surface has no network scope. File access stays inside the imported project.</div>}
              <label className="check"><input type="checkbox" checked={approval} onChange={(e) => setApproval(e.target.checked)} /><span><span className="t">Require approval before active tests</span><span className="d">The run pauses until an analyst approves.</span></span></label>
            </div>
          </div>
          <div className="panel">
            <div className="panel-head">
              <Layers size={15} color="#2f6f3e" /><h2>Engines</h2><span className="sub">{selected.length}/{available.length}</span>
              <div className="right">
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setSelected(available.map((e) => e.id))}>All</button>
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setSelected([])}>None</button>
              </div>
            </div>
            <div className="panel-body grid" style={{ gap: 8, maxHeight: 440, overflow: "auto" }}>
              {!enginesLoaded ? <SkeletonRows rows={5} cols={1} /> : available.length ? available.map((engine) => (
                <label key={engine.id} className="check">
                  <input type="checkbox" checked={selected.includes(engine.id)} onChange={(e) => setSelected((list) => e.target.checked ? [...list, engine.id] : list.filter((id) => id !== engine.id))} />
                  <span><span className="t">{engine.name} {engine.dynamic && <span className="tag">dynamic</span>}</span><span className="d">{engine.description}</span></span>
                </label>
              )) : <EmptyState compact icon={<Layers size={18} />} title="No engines for this surface" text="Install a plugin or choose a different surface." />}
            </div>
          </div>
          <div className="panel span-2">
            <div className="panel-head"><Gauge size={15} color="#9a6a00" /><h2>Depth</h2><span className="sub">time vs coverage</span></div>
            <div className="panel-body grid grid-3">
              <div className="field"><label htmlFor="depth-fuzz">Fuzz iterations / function</label><input id="depth-fuzz" className="input mono" type="number" min={20} max={3000} value={fuzzIterations} onChange={(e) => setFuzzIterations(Number(e.target.value))} /></div>
              <div className="field"><label htmlFor="depth-lab">Zero-day lab functions</label><input id="depth-lab" className="input mono" type="number" min={0} max={12} value={labFunctions} onChange={(e) => setLabFunctions(Number(e.target.value))} /></div>
              <label className="check" style={{ alignSelf: "end" }}><input type="checkbox" checked={llmReview} onChange={(e) => setLlmReview(e.target.checked)} /><span><span className="t">AI review & critic</span><span className="d">Uses configured models; falls back cleanly.</span></span></label>
            </div>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="panel">
          <div className="panel-head"><ShieldCheck size={15} color="#2f6f3e" /><h2>Review</h2><span className="sub">nothing runs until you launch</span></div>
          <div className="review-sheet">
            <dl className="kv">
              <dt>Name</dt><dd>{name}</dd>
              <dt>Surface</dt><dd><surface.icon size={14} /> {surface.label}</dd>
              <dt>Target</dt><dd className="mono">{(needsProject ? projectName : target) || "—"}</dd>
              <dt>Engines</dt><dd>{selected.length} of {available.length} selected</dd>
              {needsUrl && (
                <>
                  <dt>Allow-list</dt><dd className="mono">{allowLabel}</dd>
                  <dt>Budget</dt><dd className="mono">{budget} requests · {rate}/s · ports {ports || "—"}</dd>
                  <dt>Private IPs</dt><dd>{allowPrivate ? "Allowed" : "Blocked"}</dd>
                </>
              )}
              <dt>Approval</dt><dd>{approval ? <span className="badge sev-medium">required</span> : "Automatic"}</dd>
              <dt>Fuzzing</dt><dd className="mono">{fuzzIterations} iterations · {labFunctions} lab functions</dd>
              <dt>AI review</dt><dd>{llmReview ? "Enabled" : "Off"}</dd>
            </dl>
            <aside className="review-side">
              <div className="flex"><Orb tone="lime" pulse /><span className="mono small" style={{ letterSpacing: "0.14em" }}>READY TO LAUNCH</span></div>
              <div className="callout lime small"><ShieldCheck size={13} /> Only authorized targets. Active engines honor the scope gate, request budget and redirect re-validation.</div>
              <p className="small dim" style={{ margin: 0 }}>The run opens in a live view. You can cancel at any time; partial evidence is kept.</p>
            </aside>
          </div>
        </div>
      )}

      <div className="wizard-foot">
        {step > 0 && <button type="button" className="btn" onClick={() => setStep((s) => s - 1)}><ArrowLeft size={14} /> Back</button>}
        <span className="small dim mono">Step {step + 1} / 3</span>
        <div className="ml-auto flex">
          {step < 2
            ? <button type="button" className="btn btn-primary" onClick={next}>Continue <ArrowRight size={14} /></button>
            : <button type="button" className="btn btn-primary" onClick={launch} disabled={busy}>{busy ? <span className="spinner" /> : <Radar size={14} />} {busy ? "Launching…" : "Launch scan"}</button>}
        </div>
      </div>
    </>
  );
}
