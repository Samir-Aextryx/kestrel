import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Download, ExternalLink, FlaskConical, X } from "lucide-react";
import { api } from "../api";
import type { PocBundle } from "../types";
import { CopyButton, Skeleton } from "./ui";

export function downloadText(name: string, content: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Reads GET /api/findings/:id/poc and shows the reproducible bundle plus its source. */
export function PocView({ findingId }: { findingId: string }) {
  const [poc, setPoc] = useState<PocBundle | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    setPoc(null);
    setError("");
    api.get<PocBundle>(`/findings/${findingId}/poc`)
      .then((data) => alive && setPoc(data))
      .catch((err) => alive && setError(err instanceof Error ? err.message : "PoC unavailable"));
    return () => { alive = false; };
  }, [findingId]);

  if (error) return <div className="callout small">{error === "no PoC bundle" ? "No PoC bundle for this finding." : error}</div>;
  if (!poc) return <div className="grid" style={{ gap: 8 }} aria-busy="true"><Skeleton height={12} /><Skeleton height={120} /></div>;

  const { code, sha256, ...bundle } = poc;
  const json = JSON.stringify(bundle, null, 2);
  const ext = poc.runtime === "python" ? "py" : "mjs";
  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="flex flex-wrap small">
        <span className="tag">{poc.family}</span>
        <span className="tag">{poc.runtime}</span>
        <span className="tag">exploitability {poc.exploitability}/10</span>
        <span className="tag">zero-day {poc.zeroDayScore}/100</span>
        {poc.deterministic && <span className="badge sev-low">deterministic</span>}
      </div>
      {sha256 && <div className="mono small dim truncate" title={sha256}>sha256 {sha256}</div>}
      <div>
        <div className="flex">
          <b className="small">Bundle</b>
          <span className="ml-auto flex">
            <CopyButton value={json} />
            <button className="btn btn-sm btn-ghost" onClick={() => downloadText(`poc-${findingId}.json`, json)}><Download size={13} /> Download</button>
          </span>
        </div>
        <pre className="code mt-8 poc-code">{json}</pre>
      </div>
      {code && (
        <div>
          <div className="flex">
            <b className="small">Reproducer · .{ext}</b>
            <span className="ml-auto flex">
              <CopyButton value={code} />
              <button className="btn btn-sm btn-ghost" onClick={() => downloadText(`poc-${findingId}.${ext}`, code, "text/plain")}><Download size={13} /> Download</button>
            </span>
          </div>
          <pre className="code mt-8 poc-code">{code}</pre>
        </div>
      )}
      <div className="small dim">Run only against the authorized project copy or lab.</div>
    </div>
  );
}

export function PocDrawer({ findingId, title, onClose }: { findingId: string; title?: string; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Proof of concept">
        <div className="drawer-head">
          <div style={{ minWidth: 0, flex: 1 }}>
            <span className="badge sev-low"><FlaskConical size={11} /> PoC</span>
            <h2>{title || "Proof of concept"}</h2>
            <div className="small dim mono">{findingId}</div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        <div className="drawer-body"><PocView findingId={findingId} /></div>
        <div className="drawer-foot">
          <Link to={`/findings/${findingId}`} className="btn btn-sm btn-primary">Open finding <ExternalLink size={12} /></Link>
        </div>
      </aside>
    </>
  );
}
