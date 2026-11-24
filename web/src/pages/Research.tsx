import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FlaskConical, Microscope, ShieldCheck } from "lucide-react";
import { api } from "../api";
import { PocDrawer } from "../components/PocDrawer";
import { ResearchPanel } from "../components/ResearchPanel";
import { EmptyState, SeverityChip, SkeletonRows, useTitle } from "../components/ui";
import type { ResearchOverview, Scan } from "../types";

export default function Research() {
  useTitle("Research");
  const [params, setParams] = useSearchParams();
  const [overview, setOverview] = useState<ResearchOverview | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState("");
  const [poc, setPoc] = useState<{ id: string; title?: string } | null>(null);
  const scanId = params.get("scanId") || "";

  useEffect(() => {
    api.get<ResearchOverview>("/research/overview").then(setOverview).catch((err) => setError(err.message));
    api.get<Scan[]>("/scans").then(setScans).catch(() => {});
  }, []);

  // Default to the most recent scan with a confirmed hypothesis, otherwise the latest scan.
  useEffect(() => {
    if (scanId || !scans.length || !overview) return;
    const pick = overview.confirmed[0]?.scan_id || scans[0].id;
    setParams({ scanId: pick }, { replace: true });
  }, [scanId, scans, overview, setParams]);

  const confirmed = overview?.confirmed ?? [];
  const scanOptions = scans.some((s) => s.id === scanId) || !scanId ? scans : [{ id: scanId, name: scanId } as Scan, ...scans];

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Zero-day lab</div>
          <h1>Research</h1>
          <p>Hypotheses from the differential lab, confirmed findings and reproducible PoC bundles.</p>
        </div>
      </div>

      {error && <div className="callout danger" style={{ marginBottom: 16 }}>{error}</div>}

      <div className="panel">
        <div className="stat-row research-stats">
          <div className="stat-cell"><div className="k">Confirmed (all scans)</div><div className="v ok">{overview ? confirmed.length : "—"}</div></div>
          <div className="stat-cell"><div className="k">Families</div><div className="v">{overview ? overview.families.length : "—"}</div></div>
          <div className="stat-cell"><div className="k">Corpus entries</div><div className="v">{overview ? overview.corpus.entries : "—"}</div></div>
          <div className="stat-cell"><div className="k">Scans</div><div className="v">{scans.length}</div></div>
        </div>
        {overview && overview.families.length > 0 && (
          <div className="panel-body flex flex-wrap small" style={{ borderTop: "1px solid var(--line)" }}>
            {overview.families.map((f) => <span key={f.family} className="tag">{f.family} · {f.n}</span>)}
          </div>
        )}
      </div>

      <div className="panel mt-16">
        <div className="panel-head"><ShieldCheck size={14} color="#2f6f3e" /><h2>Confirmed findings</h2><span className="sub">across accessible workspaces</span><div className="right"><span className="tag">{confirmed.length}</span></div></div>
        {!overview && !error ? <SkeletonRows rows={4} cols={5} /> : confirmed.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Severity</th><th>Finding</th><th>Family</th><th>Exploitability</th><th>Scan</th><th>PoC</th></tr></thead>
              <tbody>
                {confirmed.map((c) => (
                  <tr key={c.id}>
                    <td>{c.severity ? <SeverityChip severity={c.severity} /> : <span className="dim">—</span>}</td>
                    <td>
                      <div className="cell-title">
                        {c.finding_id ? <Link to={`/findings/${c.finding_id}`}><b>{c.title || c.function}</b></Link> : <b>{c.title || c.function}</b>}
                        <span className="mono dim small">{c.file} · {c.function}</span>
                      </div>
                    </td>
                    <td><span className="tag">{c.family}</span></td>
                    <td className="mono">{c.exploitability}/10</td>
                    <td><button className="btn btn-sm btn-ghost" onClick={() => setParams({ scanId: c.scan_id })}>{c.scan_name}</button></td>
                    <td>{c.finding_id ? <button className="btn btn-sm" onClick={() => setPoc({ id: c.finding_id as string, title: c.title || undefined })}><FlaskConical size={12} /> PoC</button> : <span className="dim">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState compact icon={<ShieldCheck size={18} />} title="No confirmed findings" text="Run a code scan with the zero-day lab enabled." action={<Link to="/agent" className="btn btn-sm btn-primary">Start research</Link>} />}
      </div>

      <div className="toolbar mt-16">
        <label className="small dim" htmlFor="research-scan">Scan</label>
        <select id="research-scan" className="select" value={scanId} onChange={(e) => setParams({ scanId: e.target.value })} disabled={!scanOptions.length}>
          {!scanOptions.length && <option value="">No scans</option>}
          {scanOptions.map((s) => <option key={s.id} value={s.id}>{s.name}{s.target_type ? ` · ${s.target_type}` : ""}</option>)}
        </select>
        {scanId && <Link to={`/scans/${scanId}`} className="btn btn-sm btn-ghost">Open scan</Link>}
      </div>

      {scanId ? <ResearchPanel scanId={scanId} /> : (
        <div className="panel"><EmptyState icon={<Microscope size={20} />} title="No scan selected" text="Pick a scan to see its hypotheses." /></div>
      )}

      {poc && <PocDrawer findingId={poc.id} title={poc.title} onClose={() => setPoc(null)} />}
    </>
  );
}
