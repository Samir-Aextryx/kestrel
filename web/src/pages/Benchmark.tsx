import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChartNoAxesCombined, FlaskConical, Play, Search } from "lucide-react";
import { api } from "../api";
import { useToast } from "../components/Toast";
import { EmptyState, Modal, SeverityChip, SkeletonRows, Sparkline, TimeAgo, useTitle } from "../components/ui";
import type { Finding } from "../types";

type Benchmark = { id: string; name: string; scan_id: string; precision: number; recall: number; f1: number; tp: number; fp: number; fn: number; created_at: string };

function metricColor(v: number) {
  return v >= 85 ? "#2f6f3e" : v >= 65 ? "#0f766e" : v >= 45 ? "#9a6a00" : "#c62828";
}

function Metric({ value }: { value: number }) {
  const color = metricColor(value);
  return (
    <span className="metric-bar">
      <span style={{ minWidth: 42 }}>{value}%</span>
      <i><span style={{ width: `${Math.min(100, value)}%`, background: color }} /></i>
    </span>
  );
}

export default function Benchmark() {
  useTitle("Benchmark");
  const [rows, setRows] = useState<Benchmark[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [inspecting, setInspecting] = useState<string | null>(null);
  const [detail, setDetail] = useState<(Benchmark & { findings: Finding[] }) | null>(null);
  const toast = useToast();

  const load = () => api.get<Benchmark[]>("/benchmarks").then(setRows).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  async function run() {
    setBusy(true);
    try {
      await api.post("/benchmarks/run");
      toast.push("info", "Benchmark queued — this takes a few minutes");
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Could not start benchmark");
    } finally {
      setBusy(false);
    }
  }

  async function inspect(id: string) {
    setInspecting(id);
    try {
      setDetail(await api.get<Benchmark & { findings: Finding[] }>(`/benchmarks/${id}`));
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Could not load benchmark");
    } finally {
      setInspecting(null);
    }
  }

  const latest = rows[0];
  const previous = rows[1];
  const history = [...rows].reverse();
  const delta = (key: "precision" | "recall" | "f1") => {
    if (!latest || !previous) return null;
    const d = Math.round((latest[key] - previous[key]) * 10) / 10;
    return <span style={{ color: d > 0 ? "#2f6f3e" : d < 0 ? "#c62828" : undefined }}>{d > 0 ? "+" : ""}{d} pts vs previous run</span>;
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Quality measurement</div>
          <h1>Benchmark</h1>
          <p>A seeded vulnerable lab with 74 known issues. Precision, recall and F1 are computed from real engine output.</p>
        </div>
        <div className="actions">
          <button className="btn btn-primary" onClick={run} disabled={busy}>{busy ? <span className="spinner" /> : <Play size={14} />} Run benchmark</button>
        </div>
      </div>

      {latest && (
        <div className="grid grid-4" style={{ marginBottom: 16 }}>
          {(["f1", "precision", "recall"] as const).map((key) => (
            <div key={key} className="panel score-card ticked">
              <div className="label">{key === "f1" ? "F1 score" : key} · latest</div>
              <div className="value" style={{ color: metricColor(latest[key]) }}>{latest[key]}<small>%</small></div>
              <div className="delta">{delta(key) ?? "First recorded run"}</div>
              {history.length > 1 && <Sparkline data={history.map((r) => r[key])} color={metricColor(latest[key])} width={160} height={26} />}
            </div>
          ))}
          <div className="panel score-card">
            <div className="label">Outcome</div>
            <div className="confusion">
              <div><b style={{ color: "#2f6f3e" }}>{latest.tp}</b><span>TP</span></div>
              <div><b style={{ color: "#9a6a00" }}>{latest.fp}</b><span>FP</span></div>
              <div><b style={{ color: "#c62828" }}>{latest.fn}</b><span>FN</span></div>
            </div>
            <div className="delta"><TimeAgo value={latest.created_at} /> · <Link to={`/scans/${latest.scan_id}`}>open scan</Link></div>
          </div>
        </div>
      )}

      <div className="callout lime flex" style={{ marginBottom: 16, alignItems: "flex-start" }}>
        <FlaskConical size={14} style={{ flex: "0 0 auto", marginTop: 2 }} />
        <span>The lab covers injection, traversal, SSRF, secrets, dependency CVEs, Docker, Kubernetes, Terraform, CI, OpenAPI, Nginx and Python. It is intentionally vulnerable and never touches the network.</span>
      </div>

      <div className="panel">
        <div className="panel-head"><ChartNoAxesCombined size={14} color="#0f766e" /><h2>Run history</h2><div className="right"><span className="tag">{rows.length} runs</span></div></div>
        {loading ? <SkeletonRows rows={4} cols={7} /> : rows.length ? (
          <div className="table-wrap"><table className="data">
            <thead><tr><th>Run</th><th>F1</th><th>Precision</th><th>Recall</th><th>TP</th><th>FP</th><th>FN</th><th>Created</th><th></th></tr></thead>
            <tbody>{rows.map((row) => (
              <tr key={row.id}>
                <td><div className="cell-title"><b>{row.name}</b><span className="mono dim small">{row.id.slice(0, 8)}</span></div></td>
                <td><Metric value={row.f1} /></td>
                <td><Metric value={row.precision} /></td>
                <td><Metric value={row.recall} /></td>
                <td className="mono">{row.tp}</td><td className="mono">{row.fp}</td><td className="mono">{row.fn}</td>
                <td className="dim nowrap"><TimeAgo value={row.created_at} /></td>
                <td><button className="btn btn-sm" onClick={() => inspect(row.id)} disabled={inspecting === row.id}>{inspecting === row.id ? <span className="spinner" /> : <Search size={12} />} Inspect</button></td>
              </tr>
            ))}</tbody>
          </table></div>
        ) : (
          <EmptyState
            icon={<ChartNoAxesCombined size={20} />}
            title="No benchmark runs"
            text="Run the lab to establish a precision and recall baseline. Results appear here when the scan finishes."
            action={<button className="btn btn-primary btn-sm" onClick={run} disabled={busy}><Play size={12} /> Run benchmark</button>}
          />
        )}
      </div>

      {detail && (
        <Modal wide title={`Benchmark · ${detail.name}`} onClose={() => setDetail(null)} footer={<button className="btn" onClick={() => setDetail(null)}>Close</button>}>
          <div className="grid grid-4" style={{ marginBottom: 16 }}>
            {([["Precision", detail.precision], ["Recall", detail.recall], ["F1", detail.f1]] as const).map(([label, v]) => (
              <div key={label} className="panel score-card" style={{ padding: 14 }}>
                <div className="label">{label}</div>
                <div className="value" style={{ fontSize: 28, color: metricColor(v) }}>{v}<small>%</small></div>
              </div>
            ))}
            <div className="panel score-card" style={{ padding: 14 }}>
              <div className="label">Misses</div>
              <div className="value" style={{ fontSize: 28, color: detail.fn ? "#c62828" : "#2f6f3e" }}>{detail.fn}</div>
            </div>
          </div>
          <div className="section-title">Findings · {detail.findings.length} · scan <Link to={`/scans/${detail.scan_id}`}>{detail.scan_id.slice(0, 8)}</Link></div>
          <div className="grid" style={{ gap: 4, maxHeight: 340, overflow: "auto" }}>
            {detail.findings.slice(0, 80).map((f) => (
              <div key={f.id} className="list-row" style={{ padding: "8px 12px" }}>
                <SeverityChip severity={f.severity} /><span className="truncate">{f.title}</span><span className="ml-auto mono dim small nowrap">{f.ruleId}</span>
              </div>
            ))}
            {!detail.findings.length && <EmptyState compact title="No findings recorded" text="The run produced no output to score." />}
          </div>
        </Modal>
      )}
    </>
  );
}
