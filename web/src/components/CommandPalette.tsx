import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, Bug, FolderGit2, Search } from "lucide-react";
import { api } from "../api";

type Results = {
  scans: { id: string; name: string; target: string }[];
  findings: { id: string; title: string; severity: string }[];
  projects: { id: string; name: string }[];
};

const PAGES = [
  ["Command Center", "/"],
  ["Scans", "/scans"],
  ["Operations", "/operations"],
  ["Findings", "/findings"],
  ["Attack Graph", "/graph"],
  ["Fuzzing Lab", "/fuzzing"],
  ["Benchmark", "/benchmark"],
  ["Settings", "/settings"],
  ["Method", "/docs"],
];

export function CommandPalette({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Results>({ scans: [], findings: [], projects: [] });
  const [index, setIndex] = useState(0);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    if (query.length < 2) {
      setResults({ scans: [], findings: [], projects: [] });
      return;
    }
    const timer = setTimeout(() => {
      api.get<Results>(`/search?q=${encodeURIComponent(query)}`).then(setResults).catch(() => {});
    }, 180);
    return () => clearTimeout(timer);
  }, [query]);

  const items = useMemo<{ kind: string; label: string; sub?: string; to: string }[]>(() => {
    const pages = PAGES.filter(([label]) => label.toLowerCase().includes(query.toLowerCase())).map(([label, to]) => ({
      kind: "page", label, to,
    }));
    return [
      ...results.scans.map((s) => ({ kind: "scan", label: s.name, sub: s.target, to: `/scans/${s.id}` })),
      ...results.findings.map((f) => ({ kind: "finding", label: f.title, sub: f.severity, to: `/findings/${f.id}` })),
      ...results.projects.map((p) => ({ kind: "project", label: p.name, sub: "project", to: `/scans/new?project=${p.id}` })),
      ...pages,
    ];
  }, [results, query]);

  function go(to: string) {
    navigate(to);
    onClose();
  }

  return (
    <div className="cmd-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="cmd">
        <input
          ref={inputRef}
          value={query}
          placeholder="Jump to a scan, finding, project or page…"
          onChange={(e) => { setQuery(e.target.value); setIndex(0); }}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose();
            if (e.key === "ArrowDown") { e.preventDefault(); setIndex((i) => Math.min(items.length - 1, i + 1)); }
            if (e.key === "ArrowUp") { e.preventDefault(); setIndex((i) => Math.max(0, i - 1)); }
            if (e.key === "Enter" && items[index]) go(items[index].to);
          }}
        />
        <div className="cmd-list">
          {items.map((item, i) => (
            <div key={`${item.kind}-${item.to}-${i}`} className={`cmd-item ${i === index ? "on" : ""}`} onMouseEnter={() => setIndex(i)} onClick={() => go(item.to)}>
              {item.kind === "scan" ? <Activity size={14} /> : item.kind === "finding" ? <Bug size={14} /> : item.kind === "project" ? <FolderGit2 size={14} /> : <Search size={14} />}
              <span>{item.label}</span>
              {item.sub && <span className="dim small truncate">{item.sub}</span>}
              <span className="kind">{item.kind}</span>
            </div>
          ))}
          {!items.length && <div className="empty"><b>No matches</b><p>Try a target, CVE, rule or page name.</p></div>}
        </div>
      </div>
    </div>
  );
}
