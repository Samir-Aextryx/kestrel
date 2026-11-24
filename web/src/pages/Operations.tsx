import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Crosshair, KeyRound, Network, Package } from "lucide-react";
import { api } from "../api";
import { EmptyState, SkeletonRows, StatusBadge, TimeAgo, useTitle } from "../components/ui";
import type { Scan } from "../types";

type Node = { id: string; kind: string; value: string; created_at: string };
type Credential = { id: string; kind: string; username: string | null; secret: string | null; source: string | null; valid: number; created_at: string };
type Run = { id: string; engine: string; family: string; status: string; finding_id: string | null; evidence_json: string; created_at: string };
type Operations = { scanId: string; nodes: Node[]; credentials: Credential[]; runs: Run[]; counts: Record<string, number>; confirmed: number; foothold: boolean };
type Payload = { id: string; name: string; cwe: string; method: string; param: string; safe: boolean; oracle: string; description: string; count: number };

const TABS = ["Nodes", "Credentials", "Runs", "Payloads"] as const;
type Tab = (typeof TABS)[number];

export default function Operations() {
  useTitle("Operations");
  const [params, setParams] = useSearchParams();
  const scanId = params.get("scanId") || "";
  const [scans, setScans] = useState<Scan[]>([]);
  const [ops, setOps] = useState<Operations | null>(null);
  const [payloads, setPayloads] = useState<Payload[]>([]);
  const [tab, setTab] = useState<Tab>("Nodes");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get<Scan[]>("/scans").then((list) => {
      setScans(list);
      if (!params.get("scanId") && list[0]) setParams({ scanId: list[0].id }, { replace: true });
      else if (!list.length) setLoading(false);
    }).catch((e) => { setError(e.message); setLoading(false); });
    api.get<Payload[]>("/payloads").then(setPayloads).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    setError("");
    const load = () => api.get<Operations>(`/operations?scanId=${encodeURIComponent(scanId)}`)
      .then((data) => alive && setOps(data))
      .catch((e) => alive && (setOps(null), setError(e.message)))
      .finally(() => alive && setLoading(false));
    setLoading(true);
    load();
    const timer = setInterval(load, 5000);
    return () => { alive = false; clearInterval(timer); };
  }, [scanId]);

  const tabCount: Record<Tab, number | undefined> = {
    Nodes: ops?.nodes.length, Credentials: ops?.credentials.length, Runs: ops?.runs.length, Payloads: payloads.length,
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Exploitation</div>
          <h1>Operations</h1>
          <p>Discovered system nodes, credentials, exploit runs and the payload library for a scan.</p>
        </div>
        <div className="actions">
          <select className="select" aria-label="Scan" value={scanId} onChange={(e) => setParams({ scanId: e.target.value })}>
            {scans.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <span className={`badge ${ops?.foothold ? "sev-high" : "sev-info"}`}>{ops?.foothold ? "foothold" : "no foothold"}</span>
        </div>
      </div>

      {error && <div className="callout danger mb-16" role="alert">{error}</div>}

      <div className="grid grid-3 mb-16">
        <div className="panel"><div className="panel-body"><div className="dim small">Nodes</div><b>{ops?.nodes.length ?? 0}</b></div></div>
        <div className="panel"><div className="panel-body"><div className="dim small">Valid credentials</div><b>{ops?.credentials.filter((c) => c.valid).length ?? 0}</b></div></div>
        <div className="panel"><div className="panel-body"><div className="dim small">Confirmed exploits</div><b>{ops?.confirmed ?? 0}</b></div></div>
      </div>

      <div className="tabs" role="tablist">
        {TABS.map((item) => (
          <button key={item} role="tab" aria-selected={tab === item} className={`tab ${tab === item ? "on" : ""}`} onClick={() => setTab(item)}>
            {item}
            {tabCount[item] !== undefined && <span className="count">{tabCount[item]}</span>}
          </button>
        ))}
      </div>

      <div className="panel">
        {tab === "Nodes" && (loading ? <div className="panel-body"><SkeletonRows rows={4} cols={3} /></div> : ops?.nodes.length ? (
          <div className="table-wrap"><table className="data"><thead><tr><th>Kind</th><th>Value</th><th>Found</th></tr></thead><tbody>
            {ops.nodes.map((n) => <tr key={n.id}><td><span className="tag">{n.kind}</span></td><td className="mono truncate">{n.value}</td><td><TimeAgo value={n.created_at} /></td></tr>)}
          </tbody></table></div>
        ) : <EmptyState compact icon={<Network size={18} />} title="No nodes" text="Nodes appear as exploitation maps the target." />)}

        {tab === "Credentials" && (loading ? <div className="panel-body"><SkeletonRows rows={4} cols={4} /></div> : ops?.credentials.length ? (
          <div className="table-wrap"><table className="data"><thead><tr><th>Kind</th><th>Username</th><th>Secret</th><th>Source</th><th>Valid</th><th>Found</th></tr></thead><tbody>
            {ops.credentials.map((c) => <tr key={c.id}><td><span className="tag">{c.kind}</span></td><td className="mono">{c.username || "—"}</td><td className="mono truncate" style={{ maxWidth: 260 }}>{c.secret || "—"}</td><td className="truncate">{c.source || "—"}</td><td><span className={`badge ${c.valid ? "sev-high" : "sev-info"}`}>{c.valid ? "valid" : "untested"}</span></td><td><TimeAgo value={c.created_at} /></td></tr>)}
          </tbody></table></div>
        ) : <EmptyState compact icon={<KeyRound size={18} />} title="No credentials" text="Secrets are stored server-side and not shown here." />)}

        {tab === "Runs" && (loading ? <div className="panel-body"><SkeletonRows rows={4} cols={4} /></div> : ops?.runs.length ? (
          <div className="table-wrap"><table className="data"><thead><tr><th>Status</th><th>Engine</th><th>Family</th><th>Target</th><th>When</th></tr></thead><tbody>
            {ops.runs.map((r) => {
              let evidence: { url?: string; param?: string; oracle?: string } = {};
              try { evidence = JSON.parse(r.evidence_json || "{}"); } catch { /* ignore */ }
              return <tr key={r.id}><td><StatusBadge status={r.status} /></td><td>{r.engine}</td><td><span className="tag">{r.family}</span></td><td className="mono small truncate" style={{ maxWidth: 320 }}>{evidence.param ? `?${evidence.param}=` : ""}{evidence.url || "—"}</td><td><TimeAgo value={r.created_at} /></td></tr>;
            })}
          </tbody></table></div>
        ) : <EmptyState compact icon={<Crosshair size={18} />} title="No exploit runs" text="Runs are recorded when exploit engines execute." />)}

        {tab === "Payloads" && (payloads.length ? (
          <div className="table-wrap"><table className="data"><thead><tr><th>Family</th><th>CWE</th><th>Request</th><th>Oracle</th><th>Payloads</th></tr></thead><tbody>
            {payloads.map((p) => <tr key={p.id}><td><b>{p.name}</b><div className="dim small">{p.description}</div></td><td>{p.cwe}</td><td className="mono">{p.method} ?{p.param}=</td><td className="mono small">{p.oracle}</td><td>{p.count}{p.safe && <span className="tag ml-8">safe</span>}</td></tr>)}
          </tbody></table></div>
        ) : <EmptyState compact icon={<Package size={18} />} title="No payloads" text="The payload library is unavailable." />)}
      </div>
    </>
  );
}
