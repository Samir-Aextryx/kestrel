import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Bug, Search, ShieldCheck, X } from "lucide-react";
import { api } from "../api";
import { FindingDrawer } from "../components/FindingDrawer";
import { EmptyState, SEV_COLOR, SEV_ORDER, SeverityChip, SeverityMeter, SkeletonRows, TimeAgo, useTitle } from "../components/ui";
import type { Finding, Severity } from "../types";

type Row = Finding & { scanName: string };

export default function Findings() {
  useTitle("Findings");
  const [params, setParams] = useSearchParams();
  const [rows, setRows] = useState<Row[]>([]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState(params.get("severity") || "");
  const [status, setStatus] = useState("");
  const [drawer, setDrawer] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    const load = () => {
      const search = new URLSearchParams();
      if (severity) search.set("severity", severity);
      if (status) search.set("status", status);
      if (query) search.set("q", query);
      api.get<Row[]>(`/findings?${search}`).then((data) => alive && setRows(data)).finally(() => alive && setLoading(false));
    };
    load();
    const timer = setInterval(load, 6000);
    return () => { alive = false; clearInterval(timer); };
  }, [severity, status, query]);

  function toggleSeverity(value: string) {
    const next = severity === value ? "" : value;
    setSeverity(next);
    if (next) params.set("severity", next); else params.delete("severity");
    setParams(params, { replace: true });
  }

  function clearFilters() {
    setSeverity("");
    setStatus("");
    setQuery("");
    params.delete("severity");
    setParams(params, { replace: true });
  }

  const counts = useMemo(() => {
    const out: Partial<Record<Severity, number>> = {};
    for (const row of rows) out[row.severity] = (out[row.severity] || 0) + 1;
    return out;
  }, [rows]);
  const verified = rows.filter((r) => r.verified).length;
  const filtered = Boolean(severity || status || query);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Evidence ledger</div>
          <h1>Findings</h1>
          <p>Every item is linked to a scan, rule and evidence record. Verified items survived an independent check.</p>
        </div>
      </div>

      <div className="panel ledger-summary">
        <div className="ledger-stat"><span className="k">In view</span><b>{loading ? "—" : rows.length}</b></div>
        <div className="ledger-stat"><span className="k">Verified</span><b style={{ color: "var(--lime)" }}>{loading ? "—" : verified}</b></div>
        <div className="ledger-meter">
          <SeverityMeter counts={counts} height={6} />
          <div className="hero-meter-legend">
            {SEV_ORDER.map((s) => <span key={s}><i style={{ background: SEV_COLOR[s] }} />{s} <b>{counts[s] || 0}</b></span>)}
          </div>
        </div>
      </div>

      <div className="toolbar mt-16">
        <div className="seg" role="group" aria-label="Severity filter">
          {SEV_ORDER.map((sev) => (
            <button key={sev} className={severity === sev ? "on" : ""} onClick={() => toggleSeverity(sev)} aria-pressed={severity === sev}><i className="sev-pip" style={{ background: SEV_COLOR[sev] }} />{sev}</button>
          ))}
        </div>
        <select className="select" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status filter">
          <option value="">Any status</option>
          {["open", "confirmed", "false_positive", "fixed", "accepted_risk", "triaged"].map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
        </select>
        <div className="search-field">
          <Search size={14} />
          <input className="input" placeholder="Search title, rule or file" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search findings" />
        </div>
        {filtered && <button className="btn btn-sm btn-ghost" onClick={clearFilters}><X size={12} /> Clear</button>}
        <span className="ml-auto toolbar-count"><b>{rows.length}</b> results</span>
      </div>

      <div className="panel">
        {loading ? <SkeletonRows rows={8} cols={6} /> : rows.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Severity</th><th>Finding</th><th>Scan</th><th>Location</th><th>Confidence</th><th>Verified</th><th>Status</th><th>Age</th></tr></thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id} className={`row-link rail-${row.severity}`} onClick={() => setDrawer(row.id)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setDrawer(row.id)}>
                    <td><SeverityChip severity={row.severity} /></td>
                    <td style={{ minWidth: 260 }}><div className="cell-title"><b>{row.title}</b><span className="mono dim small">{row.ruleId} · {row.engine}</span></div></td>
                    <td><Link to={`/scans/${row.scanId}`} className="small" onClick={(e) => e.stopPropagation()}>{row.scanName}</Link></td>
                    <td className="mono small dim truncate" style={{ maxWidth: 260 }} title={row.file ? `${row.file}${row.line ? `:${row.line}` : ""}` : undefined}>{row.file ? `${row.file}${row.line ? `:${row.line}` : ""}` : "—"}</td>
                    <td className="small">{row.confidence}</td>
                    <td>{row.verified ? <span className="badge sev-low"><ShieldCheck size={10} /> yes</span> : <span className="dim">—</span>}</td>
                    <td><span className="tag">{row.status.replace(/_/g, " ")}</span></td>
                    <td className="dim nowrap"><TimeAgo value={row.createdAt} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : filtered ? (
          <EmptyState icon={<Search size={20} />} title="No findings match these filters" text="Widen the severity or status filter, or search for a different rule or file." action={<button className="btn btn-sm" onClick={clearFilters}><X size={12} /> Clear filters</button>} />
        ) : (
          <EmptyState icon={<Bug size={20} />} title="The ledger is empty" text="Findings appear here as soon as engines report them. Start a scan or run the benchmark lab." action={<Link to="/scans/new" className="btn btn-primary btn-sm">New scan</Link>} />
        )}
      </div>
      {drawer && <FindingDrawer id={drawer} onClose={() => setDrawer(null)} />}
    </>
  );
}
