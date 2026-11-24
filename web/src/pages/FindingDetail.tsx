import { useEffect, useState, type CSSProperties } from "react";
import { Link, useParams } from "react-router-dom";
import { Bug, Check, ExternalLink, FileCode2, Fingerprint, Link2, RotateCcw, ShieldCheck, X } from "lucide-react";
import { api } from "../api";
import { useToast } from "../components/Toast";
import { PocView } from "../components/PocDrawer";
import { BackButton, CopyButton, EmptyState, SEV_COLOR, SeverityChip, Skeleton, TimeAgo, useTitle } from "../components/ui";
import type { Finding } from "../types";

type FullFinding = Finding & { scan?: { id: string; name: string; target: string; target_type: string }; evidenceRows?: { id: string; kind: string; sha256: string; content: string; created_at: string }[] };

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const [finding, setFinding] = useState<FullFinding | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const toast = useToast();
  useTitle(finding?.title || "Finding");

  const load = () => {
    if (!id) return;
    api.get<FullFinding>(`/findings/${id}`).then(setFinding).catch((err) => setError(err.message));
  };
  useEffect(load, [id]);

  async function patch(body: Record<string, unknown>) {
    if (!id) return;
    try {
      await api.patch(`/findings/${id}`, body);
      toast.push("success", "Finding updated");
      load();
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Update failed");
    }
  }

  async function retest() {
    if (!id) return;
    setBusy("retest");
    try {
      const result = await api.post<{ ok: boolean }>(`/findings/${id}/retest`);
      toast.push(result.ok ? "success" : "warn", result.ok ? "Finding reproduced" : "Finding not reproduced");
      load();
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Retest failed");
    } finally {
      setBusy(null);
    }
  }

  if (error) {
    return (
      <div className="panel">
        <EmptyState icon={<Bug size={20} />} title="Finding unavailable" text={error} action={<Link to="/findings" className="btn btn-primary btn-sm">Back to findings</Link>} />
      </div>
    );
  }
  if (!finding) {
    return (
      <div aria-busy="true" aria-label="Loading finding">
        <div className="panel finding-hero grid" style={{ gap: 12 }}>
          <Skeleton height={20} width="180px" />
          <Skeleton height={28} width="60%" />
          <Skeleton height={12} width="40%" />
        </div>
        <div className="grid grid-3">
          <div className="panel span-2 panel-body grid" style={{ gap: 10 }}><Skeleton height={12} /><Skeleton height={12} width="80%" /><Skeleton height={140} /></div>
          <div className="panel panel-body grid" style={{ gap: 10 }}><Skeleton height={12} /><Skeleton height={12} /><Skeleton height={12} /></div>
        </div>
      </div>
    );
  }

  const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "";
  const ev = finding.evidence || {};
  const zeroDayScore = typeof ev.zeroDayScore === "number" ? ev.zeroDayScore : null;
  const exploitability = typeof ev.exploitability === "number" ? ev.exploitability : null;
  const hasPoc = typeof ev.poc === "string";

  return (
    <>
      <div style={{ marginBottom: 12 }}><BackButton /></div>
      <section className="panel finding-hero" style={{ "--rail": SEV_COLOR[finding.severity] } as CSSProperties}>
        <div className="flex flex-wrap">
          <SeverityChip severity={finding.severity} />
          {finding.verified ? <span className="badge sev-low"><ShieldCheck size={10} /> verified</span> : <span className="badge sev-info">unverified</span>}
          <span className="tag">{finding.ruleId}</span>
          <span className="tag">{finding.engine}</span>
        </div>
        <h1>{finding.title}</h1>
        <div className="loc">
          {finding.scan && <Link to={`/scans/${finding.scan.id}`} className="flex" style={{ gap: 5 }}><Link2 size={12} />{finding.scan.name}</Link>}
          {location && <span className="flex" style={{ gap: 5 }}><FileCode2 size={12} />{location}</span>}
        </div>
        <div className="actions">
          <button className="btn" onClick={retest} disabled={busy === "retest"}>{busy === "retest" ? <span className="spinner" /> : <RotateCcw size={14} />} Retest</button>
          <button className="btn" onClick={() => patch({ status: "confirmed" })}><Check size={14} /> Confirm</button>
          <button className="btn btn-danger" onClick={() => patch({ status: "false_positive" })}><X size={14} /> False positive</button>
        </div>
        <div className="finding-facts">
          <div><div className="k">CVSS</div><div className="v" style={{ color: SEV_COLOR[finding.severity] }}>{finding.cvss}</div></div>
          <div><div className="k">CWE</div><div className="v">{finding.cwe || "—"}</div></div>
          <div><div className="k">Confidence</div><div className="v">{finding.confidence}</div></div>
          <div><div className="k">Status</div><div className="v">{finding.status.replace(/_/g, " ")}</div></div>
        </div>
      </section>

      <div className="grid grid-3">
        <div className="panel span-2">
          <div className="panel-head"><ShieldCheck size={14} color="#2f6f3e" /><h2>Analysis</h2></div>
          <div className="panel-body">
            <p className="prose">{finding.description}</p>
            {finding.snippet && <><div className="section-title">Code</div><pre className="code">{finding.snippet}</pre></>}
            {finding.taint && (
              <>
                <div className="section-title">Taint path</div>
                <div className="taint">
                  <div className="taint-node">
                    <div className="k">Source{finding.taint.source?.line ? ` · line ${finding.taint.source.line}` : ""}</div>
                    <pre className="code">{finding.taint.source?.code}</pre>
                  </div>
                  <div className="taint-node sink">
                    <div className="k">Sink{finding.taint.sink?.line ? ` · line ${finding.taint.sink.line}` : ""}</div>
                    <pre className="code">{finding.taint.sink?.code}</pre>
                  </div>
                </div>
              </>
            )}
            {finding.remediation && <><div className="section-title">Remediation</div><div className="callout lime"><p className="prose" style={{ color: "inherit" }}>{finding.remediation}</p></div></>}
            {finding.evidence && Object.keys(finding.evidence).length > 0 && (
              <>
                <div className="section-title">Evidence</div>
                <pre className="code">{JSON.stringify(finding.evidence, null, 2)}</pre>
              </>
            )}
            {hasPoc && (
              <>
                <div className="section-title">Proof of concept</div>
                <PocView findingId={finding.id} />
              </>
            )}
            {finding.evidenceRows?.length ? (
              <>
                <div className="section-title">Evidence records</div>
                <div className="grid" style={{ gap: 8 }}>
                  {finding.evidenceRows.map((row) => (
                    <div key={row.id} className="callout">
                      <div className="flex small"><span className="tag">{row.kind}</span><Fingerprint size={12} /><span className="mono dim truncate">{row.sha256.slice(0, 24)}</span><span className="ml-auto dim nowrap"><TimeAgo value={row.created_at} /></span></div>
                      <pre className="code mt-8">{row.content?.slice(0, 4000)}</pre>
                    </div>
                  ))}
                </div>
              </>
            ) : null}
          </div>
        </div>
        <div className="grid" style={{ alignContent: "start" }}>
          <div className="panel">
            <div className="panel-head"><h2>Triage</h2><span className="sub">changes are audited</span></div>
            <div className="panel-body">
              <dl className="kv">
                <dt>Severity</dt><dd><select className="select" aria-label="Severity" value={finding.severity} onChange={(e) => patch({ severity: e.target.value })}>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select></dd>
                <dt>Status</dt><dd><select className="select" aria-label="Status" value={finding.status} onChange={(e) => patch({ status: e.target.value })}>{["open", "triaged", "confirmed", "false_positive", "fixed", "accepted_risk"].map((s) => <option key={s}>{s}</option>)}</select></dd>
                <dt>Confidence</dt><dd><select className="select" aria-label="Confidence" value={finding.confidence} onChange={(e) => patch({ confidence: e.target.value })}>{["high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></dd>
                <dt>CVSS</dt><dd className="mono">{finding.cvss} <span className="dim small truncate">{finding.cvssVector}</span></dd>
                <dt>OWASP</dt><dd>{finding.owasp || "—"}</dd>
                <dt>Created</dt><dd><TimeAgo value={finding.createdAt} /></dd>
                <dt>Hash</dt><dd className="mono small">{finding.hash.slice(0, 20)}…</dd>
              </dl>
              <div className="flex flex-wrap mt-16"><CopyButton value={finding.id} label="Copy ID" /><CopyButton value={finding.hash} label="Copy hash" /></div>
            </div>
          </div>
          {(zeroDayScore !== null || exploitability !== null) && (
            <div className="panel">
              <div className="panel-head"><h2>Zero-day lab</h2><span className="sub">differential confirmation</span></div>
              <div className="panel-body">
                <dl className="kv">
                  <dt>Zero-day score</dt><dd className="mono">{zeroDayScore ?? "—"}<span className="dim small">/100</span></dd>
                  <dt>Exploitability</dt><dd className="mono">{exploitability ?? "—"}<span className="dim small">/10</span></dd>
                  {typeof ev.deterministic === "boolean" && <><dt>Deterministic</dt><dd>{ev.deterministic ? "yes" : "no"}</dd></>}
                  {typeof ev.oracle === "string" && <><dt>Oracle</dt><dd className="small">{ev.oracle}</dd></>}
                </dl>
                {zeroDayScore !== null && <div className="progress thin mt-8"><span style={{ width: `${Math.min(100, zeroDayScore)}%` }} /></div>}
              </div>
            </div>
          )}
          {finding.verification && (
            <div className="panel">
              <div className="panel-head"><ShieldCheck size={14} color="#0f766e" /><h2>Verification</h2></div>
              <div className="panel-body"><pre className="code">{JSON.stringify(finding.verification, null, 2)}</pre></div>
            </div>
          )}
          {finding.references?.length ? (
            <div className="panel">
              <div className="panel-head"><h2>References</h2></div>
              <div className="panel-body grid" style={{ gap: 8 }}>
                {finding.references.map((ref) => <a key={ref} href={ref} target="_blank" rel="noreferrer" className="small flex" style={{ wordBreak: "break-all" }}><ExternalLink size={11} style={{ flex: "0 0 auto" }} />{ref}</a>)}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </>
  );
}
