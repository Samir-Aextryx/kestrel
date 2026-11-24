import { Link } from "react-router-dom";
import { ArrowUpRight, Bot, ChartNoAxesCombined, KeyRound, Lock, Radar, ShieldCheck, Workflow } from "lucide-react";
import { useTitle } from "../components/ui";

const GAPS = [
  ["Scope enforcement", "Configurable rules plus model judgment; CERT-EU notes no hard technical enforcement. Scanner scope is trusted as-is.", "Every request passes a ScopeGate: DNS resolution, CIDR/domain allow-list, deny rules, port/scheme checks, private-IP block, redirect re-validation and a hard request budget."],
  ["Verification", "Findings are LLM-produced and evidence-linked, but not independently reproduced.", "A verifier re-reads code, replays HTTP, checks manifests and reachability. The differential lab reruns benign vs hostile inputs. Unverified items are labeled."],
  ["Code analysis", "Network/offensive focus; no SAST, taint tracking, SCA, IaC or SBOM.", "AST taint analysis for JS/TS, Python and Go; secrets with Git history; OSV SCA; Docker/K8s/Terraform/CI/Nginx; SBOM; license policy; binary hardening."],
  ["Zero-day research", "Exploit execution in a lab, but no hypothesis generation or differential confirmation.", "A controlled lab discovers exported functions, infers parameter roles, executes payload pairs in isolated processes and confirms effects (file, exec, network, prototype, timing)."],
  ["Fuzzing", "No coverage-guided fuzzing.", "V8 and Python line-coverage feedback, corpus evolution, crash/hang detection, delta minimization and reproducible inputs."],
  ["False positives", "No deterministic dedupe or precision feedback loop.", "Fingerprint dedupe, reachability checks, test/generated downgrades, LLM critic with code context, and per-rule precision weights learned across runs."],
  ["Model layer", "Brings its own external model; guardrail failures force provider swaps; no budget-aware routing.", "Provider-agnostic router with priority/round-robin/cheapest strategies, per-scan call and cost budgets, encrypted keys, retries, JSON repair and deterministic fallbacks."],
  ["Supply chain", "AGPL upstream disappeared; forks diverge; a backdoored Docker Hub image was reported.", "Self-contained source, pinned dependencies, SBOM generation, license policy, plugin permission manifests and signed report hashes."],
  ["Deployment exposure", "1,600+ panels publicly reachable; ten databases exposed in one study.", "Auth on every API route, HttpOnly sessions, CSRF, RBAC, rate limits, CSP/HSTS/COOP, audit log and encrypted secrets at rest."],
  ["Evidence integrity", "Traffic capture exists, but no cryptographic chain of custody.", "SHA-256 evidence records, finding hashes and HMAC-signed report exports (MD, HTML, JSON, SARIF)."],
  ["Correlation", "Dual graph of assets and exploration, but no attack-path synthesis.", "Cross-engine dedupe and tag-based chain correlation produce ranked attack paths and a graph view."],
  ["Extensibility", "MCP/skills, but no permissioned in-process plugin contract.", "Manifest plugins run in a worker with explicit fs/net permissions, memory cap and timeout."],
];

const PIPELINE: { stage: string; agents: string; note: string }[] = [
  { stage: "Scope", agents: "scope gate", note: "Validated allow-list, budget and approval policy" },
  { stage: "Plan", agents: "orchestrator", note: "Selects agents for the surface" },
  { stage: "Surface", agents: "recon · code · secrets · supply · iac · api · plugins", note: "Deterministic engines in parallel" },
  { stage: "Dynamic", agents: "fuzz · zero-day lab", note: "Coverage feedback and differential execution" },
  { stage: "Verify", agents: "verifier", note: "Replay and reachability" },
  { stage: "Critique", agents: "critic", note: "Dedupe, downgrade, AI review" },
  { stage: "Correlate", agents: "correlator", note: "Attack paths" },
  { stage: "Report", agents: "reporter", note: "MD / HTML / JSON / SARIF, HMAC" },
  { stage: "Learn", agents: "optimizer", note: "Per-rule precision weights" },
];

const TRUST = [
  "Operator input is validated with schemas.",
  "Tool output is untrusted data, wrapped with nonce delimiters before any model sees it.",
  "Network egress is pinned to a resolved IP and re-checked on every redirect.",
  "Project files are read through a root-confined path resolver.",
  "Plugins receive only manifest-granted fs/net access.",
  "Model keys are AES-256-GCM encrypted with a local master key.",
  "Reports are hashed and HMAC-signed.",
];

const DETERMINISM = [
  { title: "Deterministic", tone: "lime", text: "Scope decisions, secret signatures, AST taint paths, dependency version matching, IaC rules, API contract checks, fuzzing coverage, crash minimization, verification replays, dedupe, scoring, report hashes." },
  { title: "Model-assisted", tone: "cyan", text: "Plan refinement, code review hypotheses, false-positive critique, executive summary. Every model finding must cite a file and line; the line is checked against source before insertion. Without a key, all of these degrade to deterministic behavior." },
  { title: "Known limits", tone: "warn", text: "The taint engine is intra-file and does not model every framework; fuzzing needs importable functions; the zero-day lab confirms observable effects, not full exploitability; binary analysis reads headers and strings, not decompiled logic; web checks are unauthenticated unless a session is supplied." },
] as const;

export default function Docs() {
  useTitle("Method");
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Design record</div>
          <h1>Method & ARTEX gap analysis</h1>
          <p>What ARTEX established, where it stops, and the concrete mechanism KESTREL uses instead. Sources: CERT-EU, Check Point Research, Google Threat Intelligence, the FBI flash and the upstream README/security policy.</p>
        </div>
      </div>

      <div className="callout lime flex" style={{ marginBottom: 18, alignItems: "flex-start" }}>
        <ShieldCheck size={14} style={{ flex: "0 0 auto", marginTop: 2 }} />
        <span>KESTREL is an authorized-research framework. It does not assume permission; it enforces the scope you give it and records every request.</span>
      </div>

      <div className="panel">
        <div className="panel-head"><Radar size={14} color="#2f6f3e" /><h2>Gap matrix</h2><span className="sub">baseline → mechanism · {GAPS.length} dimensions</span></div>
        <div className="table-wrap">
          <table className="matrix">
            <thead><tr><th>Dimension</th><th>ARTEX baseline</th><th>KESTREL mechanism</th></tr></thead>
            <tbody>
              {GAPS.map(([dim, gap, fix]) => (
                <tr key={dim}>
                  <td data-label="Dimension">{dim}</td>
                  <td data-label="ARTEX baseline">{gap}</td>
                  <td data-label="KESTREL mechanism" className="better">{fix}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-2 mt-16">
        <div className="panel">
          <div className="panel-head"><Workflow size={14} color="#0f766e" /><h2>Pipeline</h2><span className="sub">{PIPELINE.length} stages</span></div>
          <div className="panel-body">
            <ol className="pipeline">
              {PIPELINE.map((p, i) => (
                <li key={p.stage}>
                  <span className="pipeline-n">{String(i + 1).padStart(2, "0")}</span>
                  <div style={{ minWidth: 0 }}>
                    <div className="flex" style={{ gap: 10 }}><b>{p.stage}</b><span className="mono small" style={{ color: "var(--cyan)" }}>{p.agents}</span></div>
                    <div className="small dim">{p.note}</div>
                  </div>
                </li>
              ))}
            </ol>
            <p className="small muted mt-16" style={{ marginBottom: 0 }}>Agents are deterministic functions with optional model augmentation. A failed model call never stops the run.</p>
          </div>
        </div>
        <div className="panel">
          <div className="panel-head"><Lock size={14} color="#2f6f3e" /><h2>Trust boundaries</h2><span className="sub">{TRUST.length} controls</span></div>
          <div className="panel-body">
            <ol className="trust-list">
              {TRUST.map((t, i) => <li key={t}><span className="pipeline-n">{i + 1}</span><span>{t}</span></li>)}
            </ol>
          </div>
        </div>
      </div>

      <div className="panel mt-16">
        <div className="panel-head"><h2>What is deterministic — and what is not</h2></div>
        <div className="panel-body grid grid-3">
          {DETERMINISM.map((d) => (
            <div key={d.title} className={`callout ${d.tone === "warn" ? "warn" : d.tone === "lime" ? "lime" : ""}`} style={d.tone === "cyan" ? { boxShadow: "inset 3px 0 0 var(--cyan)" } : undefined}>
              <div className="eyebrow" style={{ marginBottom: 8, color: "inherit" }}>{d.title}</div>
              <span style={{ color: "var(--text-2)", lineHeight: 1.65 }}>{d.text}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel mt-16">
        <div className="panel-head"><Bot size={14} color="#2f6f3e" /><h2>AI agents</h2><span className="sub">goal-first · MCP</span></div>
        <div className="panel-body">
          <ol className="trust-list">
            <li><span className="pipeline-n">1</span><span>Create a goal and a one-time agent token on the <Link to="/agent">Agent</Link> page (<span className="mono">POST /api/agent/quickstart</span>).</span></li>
            <li><span className="pipeline-n">2</span><span>Paste the MCP config into your client. It calls <span className="mono">POST /api/mcp</span> with <span className="mono">Authorization: Bearer kag_…</span>.</span></li>
            <li><span className="pipeline-n">3</span><span>Read hypotheses and confirmed findings on <Link to="/research">Research</Link>; fetch PoC bundles with <span className="mono">GET /api/findings/:id/poc</span>.</span></li>
          </ol>
          <p className="small muted mt-16" style={{ marginBottom: 0 }}>Agents get the same scope gate, budgets and approvals as people. Machine-readable summary: <a href="/api/llms.txt" target="_blank" rel="noreferrer" className="mono">/api/llms.txt</a>.</p>
        </div>
      </div>

      <div className="grid grid-3 mt-16">
        <Link to="/benchmark" className="panel doc-link">
          <ChartNoAxesCombined size={18} color="#0f766e" />
          <b>Benchmark</b>
          <p>74 seeded issues across 13 files. Precision, recall and F1 are computed from real output, not self-reported.</p>
          <span className="doc-link-cta">Open benchmark <ArrowUpRight size={12} /></span>
        </Link>
        <Link to="/scans/new" className="panel doc-link">
          <Radar size={18} color="#2f6f3e" />
          <b>Scope gate</b>
          <p>Allow-list domains/CIDRs, deny overrides, port and scheme policy, request budget, rate limit and private-IP control.</p>
          <span className="doc-link-cta">Scope a scan <ArrowUpRight size={12} /></span>
        </Link>
        <Link to="/settings" className="panel doc-link">
          <KeyRound size={18} color="#9a6a00" />
          <b>API</b>
          <p>Bearer tokens with read/write scopes. SARIF output feeds CI. <span className="mono">GET /api/health</span> is public.</p>
          <span className="doc-link-cta">Create a token <ArrowUpRight size={12} /></span>
        </Link>
      </div>
    </>
  );
}
