import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Radar, Search } from "lucide-react";
import { api } from "../api";
import { EmptyState, SkeletonRows, StatusBadge, TimeAgo, riskColor, useTitle } from "../components/ui";
import type { Scan } from "../types";

export default function Scans() {
  useTitle("Scans");
  const [scans, setScans] = useState<Scan[]>([]);
  const [status, setStatus] = useState("");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    let alive = true;
    const load = () => {
      const params = new URLSearchParams();
      if (status) params.set("status", status);
      if (query) params.set("q", query);
      api.get<Scan[]>(`/scans?${params}`).then((data) => alive && setScans(data)).finally(() => alive && setLoading(false));
    };
    load();
    const timer = setInterval(load, 4000);
    return () => { alive = false; clearInterval(timer); };
  }, [status, query]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Research queue</div>
          <h1>Scans</h1>
          <p>Every run is scoped, budgeted and evidence-linked. Open a run to watch agents and approve active steps.</p>
        </div>
        <div className="actions"><Link to="/scans/new" className="btn btn-primary"><Radar size={14} /> New scan</Link></div>
      </div>
      <div className="toolbar">
        <div className="seg">
          {[["", "All"], ["running", "Running"], ["queued", "Queued"], ["done", "Done"], ["failed", "Failed"]].map(([value, label]) => (
            <button key={value} className={status === value ? "on" : ""} onClick={() => setStatus(value)}>{label}</button>
          ))}
        </div>
        <div className="search-field">
          <Search size={14} />
          <input className="input" placeholder="Filter by name or target" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Filter scans" />
        </div>
        {!loading && <span className="ml-auto toolbar-count"><b>{scans.length}</b> runs</span>}
      </div>
      <div className="panel">
        {loading ? (
          <SkeletonRows rows={7} cols={6} />
        ) : scans.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Scan</th><th>Project</th><th>Type</th><th>Status</th><th>Progress</th><th>Risk</th><th>Findings</th><th>Created</th></tr></thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} className="row-link" onClick={() => navigate(`/scans/${scan.id}`)}>
                    <td><div className="cell-title"><b>{scan.name}</b><span className="mono dim truncate" style={{ maxWidth: 380 }}>{scan.target}</span></div></td>
                    <td className="dim">{scan.project_name || "—"}</td>
                    <td><span className="tag">{scan.target_type}</span></td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td style={{ minWidth: 130 }}><div className="flex" style={{ gap: 10 }}><div className="progress thin" style={{ flex: 1 }}><span style={{ width: `${scan.progress}%` }} /></div><span className="mono small dim">{scan.progress}%</span></div></td>
                    <td><span className="risk-num" style={{ color: riskColor(scan.risk_score) }}>{scan.risk_score}<i><span style={{ width: `${Math.min(100, scan.risk_score)}%`, background: riskColor(scan.risk_score) }} /></i></span></td>
                    <td className="mono">{scan.findings}</td>
                    <td className="dim nowrap"><TimeAgo value={scan.created_at} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState icon={<Radar size={28} />} title="No scans match" text="Adjust the filters or start a new research run." action={<Link to="/scans/new" className="btn btn-primary btn-sm">New scan</Link>} />}
      </div>
    </>
  );
}
