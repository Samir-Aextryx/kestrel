import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Bomb, FlaskConical } from "lucide-react";
import { api } from "../api";
import { EmptyState, SkeletonRows, StatusBadge, TimeAgo, useTitle } from "../components/ui";

type Run = { id: string; target: string; engine: string; status: string; iterations: number; execs: number; coverage: number; crashes: number; scan_id: string; scan_name: string; started_at: string };
type Crash = { id: string; input: string; signal: string; sha256: string; created_at: string; target: string; scan_id: string };

export default function Fuzzing() {
  useTitle("Fuzzing Lab");
  const [data, setData] = useState<{ runs: Run[]; crashes: Crash[] }>({ runs: [], crashes: [] });
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const load = () => api.get<typeof data>("/fuzz").then(setData).catch(() => {}).finally(() => setLoading(false));
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);
  const execs = data.runs.reduce((n, r) => n + r.execs, 0);
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Dynamic analysis</div>
          <h1>Fuzzing Lab</h1>
          <p>Coverage-guided mutation runs, minimized crash inputs and execution budgets.</p>
        </div>
        <div className="actions">
          <span className="tag">{data.runs.length} runs</span>
          <span className="tag">{execs.toLocaleString()} execs</span>
          <span className={`badge ${data.crashes.length ? "sev-critical" : "sev-info"}`}>{data.crashes.length} crashes</span>
        </div>
      </div>
      <div className="grid grid-2">
        <div className="panel">
          <div className="panel-head"><FlaskConical size={14} color="#2f6f3e" /><h2>Recent runs</h2></div>
          <div className="panel-body grid" style={{ gap: 8 }}>
            {loading ? <SkeletonRows rows={4} cols={1} /> : data.runs.length ? data.runs.map((run) => (
              <Link key={run.id} to={`/scans/${run.scan_id}`} className="panel fuzz-card" style={{ color: "inherit", textDecoration: "none" }}>
                <div className="top"><StatusBadge status={run.status} /><span className="name" title={run.target}>{run.target}</span><span className="tag ml-auto">{run.engine}</span></div>
                <div className="nums">
                  <span><b>{run.execs.toLocaleString()}</b> execs</span>
                  <span><b>{run.coverage}%</b> coverage</span>
                  <span><b style={{ color: run.crashes ? "#c62828" : undefined }}>{run.crashes}</b> crashes</span>
                  <span className="ml-auto"><TimeAgo value={run.started_at} /></span>
                </div>
                <div className="progress thin mt-8"><span style={{ width: `${Math.min(100, run.coverage)}%` }} /></div>
              </Link>
            )) : <EmptyState compact icon={<FlaskConical size={18} />} title="No fuzz runs" text="Enable the fuzz engines on a code scan." action={<Link to="/scans/new" className="btn btn-sm btn-primary">New scan</Link>} />}
          </div>
        </div>
        <div className="panel">
          <div className="panel-head"><Bomb size={14} color="#c62828" /><h2>Minimized inputs</h2><span className="sub">reproducible</span></div>
          <div className="panel-body grid" style={{ gap: 8 }}>
            {loading ? <SkeletonRows rows={3} cols={1} /> : data.crashes.length ? data.crashes.map((crash) => (
              <div key={crash.id} className="callout danger">
                <div className="flex"><span className="tag">{crash.signal}</span><span className="mono small">{crash.sha256.slice(0, 12)}</span><span className="ml-auto dim small nowrap"><TimeAgo value={crash.created_at} /></span></div>
                <div className="mono small dim mt-8 truncate">{crash.target}</div>
                <pre className="code mt-8">{crash.input}</pre>
              </div>
            )) : <EmptyState compact icon={<Bomb size={18} />} title="No crashes" text="Crashes and hangs are recorded with a reproducible input." />}
          </div>
        </div>
      </div>
    </>
  );
}
