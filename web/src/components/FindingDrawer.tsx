import { useEffect, useState, type CSSProperties } from "react";
import { Link } from "react-router-dom";
import { ExternalLink, FileCode2, ShieldCheck, X } from "lucide-react";
import { api } from "../api";
import type { Finding } from "../types";
import { CopyButton, SEV_COLOR, SeverityChip, Skeleton } from "./ui";

export function FindingDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const [finding, setFinding] = useState<Finding | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api.get<Finding>(`/findings/${id}`).then(setFinding).catch((err) => setError(err.message));
  }, [id]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const rail = finding ? ({ "--rail": SEV_COLOR[finding.severity] } as CSSProperties) : undefined;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" style={rail} role="dialog" aria-modal="true" aria-label={finding?.title || "Finding"}>
        <div className="drawer-head">
          <div style={{ minWidth: 0, flex: 1 }}>
            {finding ? <SeverityChip severity={finding.severity} /> : <Skeleton height={20} width="80px" />}
            {finding ? <h2>{finding.title}</h2> : <div style={{ margin: "12px 0 8px" }}><Skeleton height={20} width="70%" /></div>}
            {finding && <div className="small dim mono">{finding.ruleId} · {finding.engine}</div>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        <div className="drawer-body">
          {error && <div className="callout danger">{error}</div>}
          {!finding && !error && (
            <div className="grid" style={{ gap: 10 }} aria-busy="true">
              <Skeleton height={12} /><Skeleton height={12} width="85%" /><Skeleton height={12} width="60%" /><Skeleton height={120} />
            </div>
          )}
          {finding && (
            <>
              <div className="flex flex-wrap small" style={{ marginBottom: 14 }}>
                {finding.verified ? <span className="badge sev-low"><ShieldCheck size={11} /> verified</span> : <span className="badge sev-info">unverified</span>}
                <span className="tag">CVSS {finding.cvss}</span>
                {finding.cwe && <span className="tag">{finding.cwe}</span>}
                <span className="tag">{finding.confidence} confidence</span>
                <span className="tag">{finding.status.replace(/_/g, " ")}</span>
              </div>
              <p className="prose">{finding.description}</p>
              {finding.file && <div className="flex mono small dim mt-16"><FileCode2 size={12} />{finding.file}{finding.line ? `:${finding.line}` : ""}</div>}
              {finding.snippet && <pre className="code mt-8">{finding.snippet}</pre>}
              {finding.remediation && <><div className="section-title">Remediation</div><p className="prose">{finding.remediation}</p></>}
            </>
          )}
        </div>
        {finding && (
          <div className="drawer-foot">
            <CopyButton value={finding.id} label="Copy ID" />
            <Link to={`/findings/${finding.id}`} className="btn btn-sm btn-primary">Open full detail <ExternalLink size={12} /></Link>
          </div>
        )}
      </aside>
    </>
  );
}
