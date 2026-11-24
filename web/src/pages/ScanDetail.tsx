import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Ban, Bug, Check, ChevronRight, Download, FileText, FlaskConical, GitBranch, Radar, RotateCcw, Settings2, ShieldCheck, Terminal, X,
} from "lucide-react";
import { api, streamScan } from "../api";
import { AgentGraph } from "../components/AgentGraph";
import { FindingDrawer } from "../components/FindingDrawer";
import { ResearchPanel } from "../components/ResearchPanel";
import { useToast } from "../components/Toast";
import { EmptyState, Orb, RiskRing, SEV_COLOR, SeverityChip, SeverityMeter, Skeleton, SkeletonRows, StatusBadge, TimeAgo, useTitle } from "../components/ui";
import type { Event, Finding, ScanDetail as ScanDetailType } from "../types";

const TABS = ["Live", "Findings", "Research", "Assets", "Fuzzing", "Reports", "Config"] as const;
type Tab = (typeof TABS)[number];
type FuzzRun = { id: string; target: string; status: string; execs: number; coverage: number; crashes: number };
type FuzzCrash = { id: string; signal: string; sha256: string; input: string };

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [loadError, setLoadError] = useState("");
  const [events, setEvents] = useState<Event[]>([]);
  const [tab, setTab] = useState<Tab>("Live");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<{ id: string; kind: string; value: string; first_seen: string }[]>([]);
  const [fuzz, setFuzz] = useState<{ runs: FuzzRun[]; crashes: FuzzCrash[] }>({ runs: [], crashes: [] });
  const [loaded, setLoaded] = useState<Partial<Record<Tab, boolean>>>({});
  const [drawer, setDrawer] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const feedRef = useRef<HTMLDivElement>(null);
  useTitle(scan?.name || "Scan");

  const load = useCallback(() => {
    if (!id) return;
    api.get<ScanDetailType>(`/scans/${id}`)
      .then((data) => { setScan(data); setLoadError(""); })
      .catch((err) => setLoadError(err instanceof Error ? err.message : "Scan unavailable"));
  }, [id]);

  useEffect(() => {
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!id) return;
    api.get<Event[]>(`/scans/${id}/events?after=0`).then((list) => setEvents(list.slice(-300))).catch(() => {});
    const close = streamScan(id, 0, (event) => {
      setEvents((list) => [...list.slice(-500), event as Event]);
    });
    return close;
  }, [id]);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [events]);

  useEffect(() => {
    if (!id) return;
    const done = () => setLoaded((map) => ({ ...map, [tab]: true }));
    if (tab === "Findings") api.get<Finding[]>(`/scans/${id}/findings?limit=500`).then(setFindings).catch(() => {}).finally(done);
    if (tab === "Assets") api.get<typeof assets>(`/scans/${id}/assets`).then(setAssets).catch(() => {}).finally(done);
    if (tab === "Fuzzing") api.get<typeof fuzz>(`/scans/${id}/fuzz`).then(setFuzz).catch(() => {}).finally(done);
  }, [tab, id, scan?.status]);

  async function action(path: string, method: "post" | "del" = "post") {
    if (!id) return;
    setBusy(true);
    try {
      await (method === "post" ? api.post(`/scans/${id}/${path}`) : api.del(`/scans/${id}`));
      toast.push("success", "Action completed");
      load();
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(false);
    }
  }

  async function decide(approvalId: string, decision: string) {
    if (!id) return;
    await api.post(`/scans/${id}/approvals/${approvalId}`, { decision });
    load();
  }

  async function exportReport(format: string) {
    if (!id) return;
    const report = await api.post<{ id: string }>(`/scans/${id}/reports`, { format });
    window.location.href = `/api/reports/${report.id}/download`;
  }

  if (!scan && loadError) {
    return (
      <div className="panel">
        <EmptyState icon={<Radar size={20} />} title="Scan unavailable" text={loadError} action={<Link to="/scans" className="btn btn-primary btn-sm">Back to scans</Link>} />
      </div>
    );
  }

  if (!scan) {
    return (
      <div aria-busy="true" aria-label="Loading scan">
        <div className="page-head">
          <div className="grid" style={{ gap: 10, flex: 1 }}>
            <Skeleton height={10} width="120px" />
            <Skeleton height={28} width="40%" />
            <Skeleton height={12} width="55%" />
          </div>
        </div>
        <div className="panel run-hero">
          <Skeleton height={96} width="96px" />
          <div className="grid" style={{ gap: 12, flex: 1 }}>
            <Skeleton height={12} width="30%" />
            <Skeleton height={6} />
            <Skeleton height={40} />
          </div>
        </div>
        <div className="panel mt-16"><SkeletonRows rows={6} cols={4} /></div>
      </div>
    );
  }

  const pending = scan.approvals.filter((a) => a.status === "pending");
  const active = scan.status === "running" || scan.status === "queued";
  const counts: Partial<Record<Tab, number>> = {
    Findings: scan.stats?.findings ?? scan.findings,
    Assets: scan.stats?.assets,
    Fuzzing: scan.fuzz.length,
    Reports: scan.reports.length,
  };

  return (
    <>
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <nav className="flex small dim" style={{ marginBottom: 8, gap: 6 }} aria-label="Scan path">
            <Link to="/scans">Scans</Link><ChevronRight size={12} /><span className="mono">{scan.id.slice(0, 8)}</span>
          </nav>
          <h1>{scan.name}</h1>
          <p className="mono truncate" title={scan.target}>{scan.target}</p>
          <div className="flex flex-wrap small mt-8">
            <StatusBadge status={scan.status} />
            <span className="tag">{scan.target_type}</span>
            <span className="tag">phase · {scan.phase}</span>
            {scan.project && <Link to={`/scans/new?project=${scan.project.id}`} className="tag" title="Scan this project again">{scan.project.name}</Link>}
            <span className="dim"><TimeAgo value={scan.created_at} /></span>
          </div>
        </div>
        <div className="actions">
          {active ? (
            <button className="btn btn-danger" onClick={() => action("cancel")} disabled={busy}><Ban size={14} /> Cancel</button>
          ) : (
            <button className="btn" onClick={() => action("retest")} disabled={busy}><RotateCcw size={14} /> Retest</button>
          )}
          <div className="seg" role="group" aria-label="Export report">
            {["md", "html", "json", "sarif"].map((format) => <button key={format} onClick={() => exportReport(format)} title={`Export ${format.toUpperCase()} report`}>{format.toUpperCase()}</button>)}
          </div>
          <button className="btn btn-ghost" onClick={() => navigate("/graph")}><GitBranch size={14} /> Graph</button>
        </div>
      </div>

      <section className="panel ticked run-hero" aria-label="Run summary">
        <RiskRing score={scan.risk_score} size={104} />
        <div className="run-hero-body">
          <div className="run-hero-top">
            <span className="hero-state" style={{ margin: 0 }}><Orb tone={active ? "lime" : scan.status === "failed" ? "red" : "cyan"} pulse={active} /> {active ? "Agents operating" : `Run ${scan.status}`}</span>
            <span className="ml-auto mono small"><b>{scan.progress}%</b> <span className="dim">complete</span></span>
          </div>
          <div className="progress"><span style={{ width: `${scan.progress}%` }} /></div>
          {scan.stats?.severity && (
            <div className="run-hero-sev">
              <SeverityMeter counts={scan.stats.severity} height={4} />
              <div className="hero-meter-legend">
                {(["critical", "high", "medium", "low", "info"] as const).map((s) => <span key={s}><i style={{ background: SEV_COLOR[s] }} />{s} <b>{scan.stats?.severity[s] ?? 0}</b></span>)}
              </div>
            </div>
          )}
        </div>
        <div className="stat-row run-stats">
          <div className="stat-cell"><div className="k">Findings</div><div className="v">{scan.stats?.findings ?? 0}</div></div>
          <div className="stat-cell"><div className="k">Verified</div><div className="v ok">{scan.stats?.verified ?? 0}</div></div>
          <div className="stat-cell"><div className="k">Assets</div><div className="v">{scan.stats?.assets ?? 0}</div></div>
          <div className="stat-cell"><div className="k">Fuzz execs</div><div className="v">{(scan.stats?.fuzzExecs ?? 0).toLocaleString()}</div></div>
          <div className="stat-cell"><div className="k">Crashes</div><div className={`v ${scan.stats?.crashes ? "warn" : ""}`}>{scan.stats?.crashes ?? 0}</div></div>
          <div className="stat-cell"><div className="k">Model</div><div className="v">{scan.llm.calls}<small className="dim mono"> · ${scan.llm.cost.toFixed(3)}</small></div></div>
        </div>
      </section>

      {pending.map((approval) => (
        <div key={approval.id} className="callout warn mt-16 approval-row" role="alert">
          <ShieldCheck size={15} />
          <div style={{ minWidth: 0 }}>
            <b>Approval required · {approval.action}</b>
            <div className="mono small truncate" title={approval.payload_json}>{approval.payload_json}</div>
          </div>
          <div className="ml-auto flex">
            <button className="btn btn-sm btn-primary" onClick={() => decide(approval.id, "approved")}><Check size={12} /> Approve</button>
            <button className="btn btn-sm btn-danger" onClick={() => decide(approval.id, "rejected")}><X size={12} /> Reject</button>
          </div>
        </div>
      ))}

      <div className="tabs mt-16" role="tablist">
        {TABS.map((item) => (
          <button key={item} role="tab" aria-selected={tab === item} className={`tab ${tab === item ? "on" : ""}`} onClick={() => setTab(item)}>
            {item}
            {item === "Live" && active && <Orb tone="lime" pulse size={6} />}
            {counts[item] !== undefined && <span className="count">{counts[item]}</span>}
          </button>
        ))}
      </div>

      {tab === "Live" && (
        <div className="grid grid-2">
          <div className="grid" style={{ alignContent: "start" }}>
            <AgentGraph runs={scan.agents} />
            <div className="panel">
              <div className="panel-head"><GitBranch size={14} color="#c45a00" /><h2>Attack paths</h2><span className="sub">correlated</span><div className="right"><span className="tag">{scan.paths.length}</span></div></div>
              <div className="panel-body grid" style={{ gap: 10 }}>
                {scan.paths.length ? scan.paths.map((path) => (
                  <div key={path.id} className="path-card">
                    <div className="flex"><b className="truncate">{path.name}</b><span className="tag ml-auto">score {path.score}</span></div>
                    <ol className="path-steps">
                      {path.steps.map((step) => (
                        <li key={step.id} style={{ "--rail": SEV_COLOR[step.severity] } as CSSProperties}>
                          <span className="truncate">{step.title}</span>
                          {step.asset && <span className="mono dim small truncate">{step.asset}</span>}
                        </li>
                      ))}
                    </ol>
                  </div>
                )) : <EmptyState compact icon={<GitBranch size={18} />} title="No paths yet" text="Paths appear after the correlator links findings across engines." />}
              </div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-head">
              <Terminal size={14} color="#0f766e" /><h2>Event stream</h2><span className="sub">SSE · {events.length}</span>
              <div className="right">{active && <span className="live-pill" style={{ height: 22 }}><span className="dot" /> LIVE</span>}</div>
            </div>
            <div className="feed terminal" ref={feedRef} style={{ maxHeight: 640 }} aria-live="polite">
              {events.map((event) => (
                <div key={event.id} className={`feed-item ${event.level}`}>
                  <span className="time">{new Date(event.at).toLocaleTimeString()}</span>
                  <span className="msg">{event.agent && <span className="agent">[{event.agent}] </span>}{event.message}</span>
                </div>
              ))}
              {!events.length && <EmptyState compact icon={<Terminal size={18} />} title="Waiting for events" text="The orchestrator emits its plan first." />}
            </div>
          </div>
        </div>
      )}

      {tab === "Findings" && (
        <div className="panel">
          <div className="panel-head"><Bug size={14} color="#c45a00" /><h2>Findings</h2><span className="sub">click a row for evidence</span><div className="right"><span className="tag">{findings.length}</span></div></div>
          {!loaded.Findings ? <SkeletonRows rows={6} cols={5} /> : findings.length ? (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Confidence</th><th>Verified</th><th>Status</th></tr></thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id} className={`row-link rail-${finding.severity}`} onClick={() => setDrawer(finding.id)}>
                      <td><SeverityChip severity={finding.severity} /></td>
                      <td><div className="cell-title"><b>{finding.title}</b><span className="mono dim small">{finding.ruleId}</span></div></td>
                      <td className="mono small dim">{finding.file}{finding.line ? `:${finding.line}` : ""}</td>
                      <td className="small">{finding.confidence}</td>
                      <td>{finding.verified ? <span className="badge sev-low"><ShieldCheck size={10} /> yes</span> : <span className="dim">—</span>}</td>
                      <td><span className="tag">{finding.status}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <EmptyState icon={<Bug size={20} />} title="No findings yet" text={active ? "Engines write findings as they complete." : "This run finished without findings."} />}
        </div>
      )}

      {tab === "Research" && id && <ResearchPanel scanId={id} refreshKey={scan.status} />}

      {tab === "Assets" && (
        <div className="panel">
          <div className="panel-head"><Radar size={14} color="#0f766e" /><h2>Assets</h2><div className="right"><span className="tag">{assets.length}</span></div></div>
          {!loaded.Assets ? <SkeletonRows rows={5} cols={3} /> : assets.length ? (
            <div className="table-wrap"><table className="data"><thead><tr><th>Kind</th><th>Value</th><th>First seen</th></tr></thead><tbody>
              {assets.map((asset) => <tr key={asset.id}><td><span className="tag">{asset.kind}</span></td><td className="mono">{asset.value}</td><td className="dim nowrap"><TimeAgo value={asset.first_seen} /></td></tr>)}
            </tbody></table></div>
          ) : <EmptyState icon={<Radar size={20} />} title="No assets" text="Assets are discovered by recon and engines." />}
        </div>
      )}

      {tab === "Fuzzing" && (
        <div className="grid grid-2">
          <div className="panel">
            <div className="panel-head"><FlaskConical size={14} color="#2f6f3e" /><h2>Runs</h2><div className="right"><span className="tag">{fuzz.runs.length}</span></div></div>
            <div className="panel-body grid" style={{ gap: 8 }}>
              {!loaded.Fuzzing ? <SkeletonRows rows={3} cols={1} /> : fuzz.runs.length ? fuzz.runs.map((run) => (
                <div key={run.id} className="panel fuzz-card">
                  <div className="top"><StatusBadge status={run.status} /><span className="name">{run.target}</span></div>
                  <div className="nums"><span><b>{run.execs.toLocaleString()}</b> execs</span><span><b>{run.coverage}%</b> coverage</span><span><b>{run.crashes}</b> crashes</span></div>
                  <div className="progress thin mt-8"><span style={{ width: `${Math.min(100, run.coverage)}%` }} /></div>
                </div>
              )) : <EmptyState compact icon={<FlaskConical size={18} />} title="No fuzz runs" text="Fuzzing runs on code scans with importable functions." />}
            </div>
          </div>
          <div className="panel">
            <div className="panel-head"><X size={14} color="#c62828" /><h2>Crashes</h2><div className="right"><span className="tag">{fuzz.crashes.length}</span></div></div>
            <div className="panel-body grid" style={{ gap: 8 }}>
              {!loaded.Fuzzing ? <SkeletonRows rows={3} cols={1} /> : fuzz.crashes.length ? fuzz.crashes.map((crash) => (
                <div key={crash.id} className="callout danger">
                  <div className="flex"><span className="tag">{crash.signal}</span><span className="mono small">{crash.sha256.slice(0, 12)}</span></div>
                  <pre className="code mt-8">{crash.input}</pre>
                </div>
              )) : <EmptyState compact icon={<ShieldCheck size={18} />} title="No crashes recorded" text="Crashes and hangs are minimized into reproducible inputs." />}
            </div>
          </div>
        </div>
      )}

      {tab === "Reports" && (
        <div className="panel">
          <div className="panel-head"><FileText size={14} color="#2f6f3e" /><h2>Reports</h2><span className="sub">HMAC-signed</span></div>
          <div className="panel-body grid" style={{ gap: 8 }}>
            {scan.reports.map((report) => (
              <div key={report.id} className="list-row">
                <span className="tag">{report.format}</span>
                <span className="mono small dim truncate">{report.sha256.slice(0, 20)}…</span>
                <span className="ml-auto dim small nowrap"><TimeAgo value={report.created_at} /></span>
                <a className="btn btn-sm" href={`/api/reports/${report.id}/download`}><Download size={12} /> Download</a>
              </div>
            ))}
            {!scan.reports.length && <EmptyState compact icon={<FileText size={18} />} title="No reports yet" text="The reporter agent writes one at the end of a run, or export one above." />}
          </div>
        </div>
      )}

      {tab === "Config" && (
        <div className="grid grid-2">
          <div className="panel"><div className="panel-head"><ShieldCheck size={14} color="#0f766e" /><h2>Scope</h2></div><div className="panel-body"><pre className="code">{JSON.stringify(scan.scope, null, 2)}</pre></div></div>
          <div className="panel"><div className="panel-head"><Settings2 size={14} color="#2f6f3e" /><h2>Config</h2></div><div className="panel-body"><pre className="code">{JSON.stringify(scan.config, null, 2)}</pre></div></div>
        </div>
      )}

      {drawer && <FindingDrawer id={drawer} onClose={() => setDrawer(null)} />}
    </>
  );
}
