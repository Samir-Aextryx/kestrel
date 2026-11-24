import { useEffect, useState } from "react";
import { FlaskConical, Microscope } from "lucide-react";
import { api } from "../api";
import type { ScanResearch } from "../types";
import { EmptyState, SeverityChip, SkeletonRows } from "./ui";
import { PocDrawer } from "./PocDrawer";

const STATUS_CLASS: Record<string, string> = { confirmed: "sev-low", testing: "sev-medium", rejected: "sev-info", error: "sev-critical" };
const STATUSES = ["", "confirmed", "testing", "rejected", "error"];

/** Summary counts + hypothesis table for one scan (GET /api/research?scanId=). */
export function ResearchPanel({ scanId, refreshKey }: { scanId: string; refreshKey?: unknown }) {
  const [data, setData] = useState<ScanResearch | null>(null);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [poc, setPoc] = useState<{ id: string; title?: string } | null>(null);

  useEffect(() => {
    let alive = true;
    setError("");
    api.get<ScanResearch>(`/research?scanId=${encodeURIComponent(scanId)}`)
      .then((d) => alive && setData(d))
      .catch((err) => alive && setError(err instanceof Error ? err.message : "Research unavailable"));
    return () => { alive = false; };
  }, [scanId, refreshKey]);

  if (error) return <div className="callout danger">{error}</div>;
  if (!data || data.scanId !== scanId) return <div className="panel"><SkeletonRows rows={5} cols={5} /></div>;

  const testing = data.hypotheses.filter((h) => h.status === "testing").length;
  const rows = status ? data.hypotheses.filter((h) => h.status === status) : data.hypotheses;

  return (
    <>
      <div className="panel">
        <div className="stat-row research-stats">
          <div className="stat-cell"><div className="k">Hypotheses</div><div className="v">{data.hypotheses.length}</div></div>
          <div className="stat-cell"><div className="k">Confirmed</div><div className="v ok">{data.confirmed}</div></div>
          <div className="stat-cell"><div className="k">Testing</div><div className="v">{testing}</div></div>
          <div className="stat-cell"><div className="k">Rejected</div><div className="v">{data.rejected}</div></div>
          <div className="stat-cell"><div className="k">Errors</div><div className={`v ${data.errors ? "warn" : ""}`}>{data.errors}</div></div>
          <div className="stat-cell"><div className="k">Corpus</div><div className="v">{data.corpus.entries}<small className="dim mono"> · {data.corpus.hits} hits</small></div></div>
        </div>
      </div>

      <div className="panel mt-16">
        <div className="panel-head">
          <Microscope size={14} color="#2f6f3e" /><h2>Hypotheses</h2><span className="sub">ranked by exploitability</span>
          <div className="right">
            <div className="seg" role="group" aria-label="Filter by status">
              {STATUSES.map((s) => (
                <button key={s || "all"} className={status === s ? "on" : ""} onClick={() => setStatus(s)}>{s || "all"}</button>
              ))}
            </div>
          </div>
        </div>
        {rows.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Status</th><th>Family</th><th>Function</th><th>Oracle</th><th>Confidence</th><th>Exploitability</th><th>Zero-day</th><th>PoC</th></tr></thead>
              <tbody>
                {rows.map((h) => (
                  <tr key={h.id}>
                    <td><span className={`badge ${STATUS_CLASS[h.status] || "sev-info"}`}>{h.status}</span></td>
                    <td><span className="tag">{h.family}</span></td>
                    <td><div className="cell-title"><b className="mono">{h.function}{h.param ? `(${h.param})` : ""}</b><span className="mono dim small">{h.file}</span></div></td>
                    <td className="small">{h.oracle}</td>
                    <td className="small">{h.confidence}</td>
                    <td className="mono">{h.exploitability}/10</td>
                    <td className="mono">{typeof h.evidence?.zeroDayScore === "number" ? h.evidence.zeroDayScore : "—"}</td>
                    <td className="nowrap">
                      {h.finding_id ? (
                        <span className="flex">
                          {h.finding_severity && <SeverityChip severity={h.finding_severity} />}
                          <button className="btn btn-sm" onClick={() => setPoc({ id: h.finding_id as string, title: h.finding_title || undefined })}><FlaskConical size={12} /> PoC</button>
                        </span>
                      ) : <span className="dim">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState icon={<Microscope size={20} />} title="No hypotheses" text="The zero-day lab records hypotheses on code scans with exported functions." />}
      </div>

      {poc && <PocDrawer findingId={poc.id} title={poc.title} onClose={() => setPoc(null)} />}
    </>
  );
}
