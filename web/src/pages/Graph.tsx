import { useEffect, useMemo, useRef, useState } from "react";
import { GitBranch, Pause, Play, RotateCcw, Search, X, ExternalLink, AlertCircle } from "lucide-react";
import { api } from "../api";
import { FindingDrawer } from "../components/FindingDrawer";
import { EmptyState, Skeleton, useTitle } from "../components/ui";
import type { Scan } from "../types";

type Node = { id: string; label: string; kind: "asset" | "finding"; severity?: string; assetKind?: string; x: number; y: number; vx: number; vy: number };
type Edge = { from: string; to: string };

const COLORS: Record<string, string> = {
  critical: "#c62828", high: "#c45a00", medium: "#9a6a00", low: "#0f766e", info: "#647067", asset: "#3b6ea8",
};
const LEGEND = ["asset", "critical", "high", "medium", "low", "info"] as const;

const colorOf = (n: Node) => (n.kind === "asset" ? COLORS.asset : COLORS[n.severity || "info"] || COLORS.info);
const groupOf = (n: Node) => (n.kind === "asset" ? "asset" : n.severity || "info");
const LANE_ORDER: string[] = [...LEGEND];

// Lane centres (0..1) for the groups that actually exist, in legend order.
function laneMap(nodes: Node[]) {
  const present = LANE_ORDER.filter((g) => nodes.some((n) => groupOf(n) === g));
  return new Map(present.map((g, i) => [g, (i + 0.5) / present.length] as const));
}
const clip = (t: string, n: number) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);

export default function Graph() {
  useTitle("Attack Graph");
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const miniRef = useRef<HTMLCanvasElement>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [scansLoaded, setScansLoaded] = useState(false);
  const [scanId, setScanId] = useState("");
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [hover, setHover] = useState<Node | null>(null);
  const [selected, setSelected] = useState<Node | null>(null);
  const [query, setQuery] = useState("");
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [paused, setPaused] = useState(false);
  const drag = useRef<{ node: Node; dx: number; dy: number } | null>(null);
  const pausedRef = useRef(false);
  pausedRef.current = paused;

  useEffect(() => {
    api.get<Scan[]>("/scans?limit=100").then((list) => {
      const done = list.filter((s) => s.status === "done");
      setScans(done);
      if (done[0]) setScanId(done[0].id);
    }).catch(() => setError(true)).finally(() => setScansLoaded(true));
  }, []);

  useEffect(() => {
    if (!scanId) return;
    let live = true;
    setLoading(true);
    setError(false);
    setSelected(null);
    setHover(null);
    api.get<{ assets: { id: string; kind: string; value: string }[]; findings: { id: string; title: string; severity: string; asset_id?: string }[]; edges: Edge[] }>(`/scans/${scanId}/graph`).then((data) => {
      if (!live) return;
      const width = canvasRef.current?.clientWidth || 900;
      const height = canvasRef.current?.clientHeight || 560;
      const all: Node[] = [
        ...data.assets.map((a, i) => ({ id: a.id, label: a.value, kind: "asset" as const, assetKind: a.kind, x: width / 2 + Math.cos(i) * 180, y: height / 2 + Math.sin(i) * 180, vx: 0, vy: 0 })),
        ...data.findings.map((f, i) => ({ id: f.id, label: f.title, kind: "finding" as const, severity: f.severity, x: width / 2 + Math.cos(i * 2) * 260, y: height / 2 + Math.sin(i * 2) * 260, vx: 0, vy: 0 })),
      ];
      const lanes = laneMap(all);
      all.forEach((n, i) => {
        n.x = (lanes.get(groupOf(n)) || 0.5) * width + Math.cos(i * 1.7) * 30;
        n.y = height * (0.15 + 0.7 * ((i * 0.618) % 1));
      });
      setNodes(all);
      setEdges(data.edges);
    }).catch(() => { if (live) { setNodes([]); setEdges([]); setError(true); } }).finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [scanId]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of nodes) c[groupOf(n)] = (c[groupOf(n)] || 0) + 1;
    return c;
  }, [nodes]);

  const neighbors = useMemo(() => {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const map = new Map<string, Node[]>();
    for (const e of edges) {
      const a = byId.get(e.from);
      const b = byId.get(e.to);
      if (!a || !b) continue;
      map.set(a.id, [...(map.get(a.id) || []), b]);
      map.set(b.id, [...(map.get(b.id) || []), a]);
    }
    return map;
  }, [nodes, edges]);

  const q = query.trim().toLowerCase();
  const visible = (n: Node) => !hidden.has(groupOf(n));
  const matches = (n: Node) => !q || n.label.toLowerCase().includes(q);
  const matchCount = q ? nodes.filter((n) => visible(n) && matches(n)).length : 0;

  // Latest filter state for the render loop without restarting the simulation.
  const view = useRef({ hidden, q, selected, hover, related: new Set<string>() });
  view.current = {
    hidden, q, selected, hover,
    related: new Set(selected ? [selected.id, ...(neighbors.get(selected.id) || []).map((n) => n.id)] : []),
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const lanes = laneMap(nodes);
    const links = edges.map((e) => [byId.get(e.from), byId.get(e.to)] as const).filter((l): l is readonly [Node, Node] => !!l[0] && !!l[1]);

    const tick = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const v = view.current;
      const show = (n: Node) => !v.hidden.has(groupOf(n));
      const hit = (n: Node) => !v.q || n.label.toLowerCase().includes(v.q);
      const dimmed = (n: Node) => (v.q && !hit(n)) || (v.selected && !v.related.has(n.id));

      if (!pausedRef.current) {
        for (let i = 0; i < nodes.length; i += 1) {
          const a = nodes[i];
          for (let j = i + 1; j < nodes.length; j += 1) {
            const b = nodes[j];
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const dist = Math.max(20, Math.hypot(dx, dy));
            const force = 1400 / (dist * dist);
            a.vx -= (dx / dist) * force;
            a.vy -= (dy / dist) * force;
            b.vx += (dx / dist) * force;
            b.vy += (dy / dist) * force;
          }
          a.vx += ((lanes.get(groupOf(a)) || 0.5) * width - a.x) * 0.006;
          a.vy += (height / 2 - a.y) * 0.0005;
        }
        for (const [a, b] of links) {
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const dist = Math.max(1, Math.hypot(dx, dy));
          const force = (dist - 120) * 0.0008;
          a.vx += (dx / dist) * force;
          a.vy += (dy / dist) * force;
          b.vx -= (dx / dist) * force;
          b.vy -= (dy / dist) * force;
        }
        for (const node of nodes) {
          if (drag.current?.node === node) continue;
          node.x += node.vx;
          node.y += node.vy;
          node.vx *= 0.86;
          node.vy *= 0.86;
          node.x = Math.max(24, Math.min(width - 24, node.x));
          node.y = Math.max(52, Math.min(height - 24, node.y));
        }
      }

      ctx.clearRect(0, 0, width, height);
      // Grouped lanes: soft alternating bands with a quiet header each.
      const laneList = [...lanes.entries()];
      const laneW = width / Math.max(1, laneList.length);
      laneList.forEach(([g, c], idx) => {
        const x0 = c * width - laneW / 2;
        const off = v.hidden.has(g);
        if (idx % 2 === 0) { ctx.fillStyle = "rgba(47,111,62,0.035)"; ctx.fillRect(x0, 0, laneW, height); }
        if (idx > 0) { ctx.strokeStyle = "rgba(17,23,19,0.06)"; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(x0, 14); ctx.lineTo(x0, height - 14); ctx.stroke(); }
        ctx.globalAlpha = off ? 0.4 : 1;
        ctx.fillStyle = COLORS[g];
        ctx.beginPath();
        ctx.arc(x0 + 18, 24, 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.font = "600 10.5px Inter, 'Segoe UI', sans-serif";
        ctx.fillStyle = "#56615a";
        ctx.fillText(g.toUpperCase(), x0 + 28, 28);
        ctx.globalAlpha = 1;
      });

      for (const [a, b] of links) {
        if (!show(a) || !show(b)) continue;
        const active = v.selected && (a === v.selected || b === v.selected);
        const faint = dimmed(a) || dimmed(b);
        ctx.strokeStyle = active ? "rgba(47,111,62,0.75)" : faint ? "rgba(17,23,19,0.05)" : "rgba(60,90,70,0.22)";
        ctx.lineWidth = active ? 1.8 : 1.1;
        const mx = (a.x + b.x) / 2;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.bezierCurveTo(mx, a.y, mx, b.y, b.x, b.y);
        ctx.stroke();
      }

      for (const node of nodes) {
        if (!show(node)) continue;
        const color = colorOf(node);
        const faded = dimmed(node);
        const isSel = node === v.selected;
        const isHover = node === v.hover;
        ctx.globalAlpha = faded ? 0.22 : 1;
        if (node.kind === "asset") {
          const r = isHover || isSel ? 9 : 8;
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
          ctx.fillStyle = `${color}1f`;
          ctx.fill();
          ctx.beginPath();
          ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
          ctx.fillStyle = "#ffffff";
          ctx.fill();
          ctx.strokeStyle = color;
          ctx.lineWidth = 2.5;
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(node.x, node.y, 2.6, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();
        } else {
          const r = isHover || isSel ? 8 : 6.5;
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
          ctx.fillStyle = `${color}${isSel ? "40" : "26"}`;
          ctx.fill();
          ctx.beginPath();
          ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();
          ctx.strokeStyle = "#ffffff";
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }
        if (isSel) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, (node.kind === "asset" ? 8 : 6.5) + 9, 0, Math.PI * 2);
          ctx.strokeStyle = color;
          ctx.lineWidth = 1.5;
          ctx.setLineDash([3, 3]);
          ctx.stroke();
          ctx.setLineDash([]);
        }
        // Labels: assets always, findings when the map is sparse, or on search hit / selection.
        const showLabel = !faded && !isHover && (node.kind === "asset" || nodes.length <= 40 || isSel || (v.q && hit(node)));
        if (showLabel) {
          ctx.font = node.kind === "asset" ? "600 11px Inter, 'Segoe UI', sans-serif" : "500 10.5px Inter, 'Segoe UI', sans-serif";
          ctx.fillStyle = node.kind === "asset" ? "#33403a" : "#56615a";
          ctx.textAlign = "center";
          ctx.fillText(clip(node.label, node.kind === "asset" ? 26 : 22), node.x, node.y + (node.kind === "asset" ? 27 : 24));
          ctx.textAlign = "start";
        }
        ctx.globalAlpha = 1;
      }

      const h = v.hover;
      if (h && show(h)) {
        ctx.font = "500 11.5px Inter, 'Segoe UI', sans-serif";
        const text = h.label.length > 60 ? `${h.label.slice(0, 59)}…` : h.label;
        const w = ctx.measureText(text).width;
        const tx = Math.max(8, Math.min(h.x + 14, width - w - 26));
        const ty = Math.max(26, h.y);
        ctx.fillStyle = "#ffffff";
        ctx.strokeStyle = "#d9ddd4";
        ctx.lineWidth = 1;
        ctx.shadowColor = "rgba(17,23,19,0.12)";
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.roundRect(tx, ty - 19, w + 20, 26, 7);
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.stroke();
        ctx.fillStyle = colorOf(h);
        ctx.beginPath();
        ctx.arc(tx + 10, ty - 6, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "#111713";
        ctx.fillText(text, tx + 18, ty - 2);
      }
      const mini = miniRef.current;
      const mctx = mini?.getContext("2d");
      if (mini && mctx) {
        const mw = mini.width;
        const mh = mini.height;
        mctx.clearRect(0, 0, mw, mh);
        const sx = mw / Math.max(1, width);
        const sy = mh / Math.max(1, height);
        mctx.strokeStyle = "rgba(17,23,19,0.07)";
        for (const [a, b] of links) {
          if (!show(a) || !show(b)) continue;
          mctx.beginPath();
          mctx.moveTo(a.x * sx, a.y * sy);
          mctx.lineTo(b.x * sx, b.y * sy);
          mctx.stroke();
        }
        for (const n of nodes) {
          if (!show(n)) continue;
          mctx.globalAlpha = dimmed(n) ? 0.2 : 0.9;
          mctx.fillStyle = colorOf(n);
          mctx.beginPath();
          mctx.arc(n.x * sx, n.y * sy, n === v.selected ? 3.4 : n.kind === "asset" ? 2.4 : 1.8, 0, Math.PI * 2);
          mctx.fill();
        }
        mctx.globalAlpha = 1;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [nodes, edges]);

  function pick(event: React.MouseEvent<HTMLCanvasElement>) {
    const rect = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    return nodes.find((n) => visible(n) && Math.hypot(n.x - x, n.y - y) < 14) || null;
  }

  function toggle(group: string) {
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(group)) next.delete(group); else next.add(group);
      return next;
    });
  }

  function reset() {
    setQuery("");
    setHidden(new Set());
    setSelected(null);
    const canvas = canvasRef.current;
    const w = canvas?.clientWidth || 900;
    const h = canvas?.clientHeight || 560;
    const lanes = laneMap(nodes);
    nodes.forEach((n, i) => {
      n.x = (lanes.get(groupOf(n)) || 0.5) * w + Math.cos(i * 1.7) * 30;
      n.y = h * (0.15 + 0.7 * ((i * 0.618) % 1));
      n.vx = 0;
      n.vy = 0;
    });
  }

  const selNeighbors = selected ? neighbors.get(selected.id) || [] : [];
  const hasGraph = nodes.length > 0;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Correlation</div>
          <h1>Attack Graph</h1>
          <p>Assets and findings, grouped into lanes. Select a node to inspect it and its connections.</p>
        </div>
        <div className="actions">
          <select className="select" aria-label="Scan" value={scanId} onChange={(e) => setScanId(e.target.value)}>
            {scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.name}</option>)}
          </select>
        </div>
      </div>

      {!scansLoaded ? (
        <div className="graph-shell"><div className="graph-wrap graph-state"><Skeleton height={14} width="180px" /><Skeleton height={10} width="120px" /></div></div>
      ) : scans.length ? (
        <div className="graph-shell">
          <div className="graph-toolbar">
            <label className="graph-search">
              <Search size={14} aria-hidden="true" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search nodes…" aria-label="Search nodes" />
              {query && <button type="button" className="graph-x" onClick={() => setQuery("")} aria-label="Clear search"><X size={13} /></button>}
            </label>
            {q && <span className="graph-meta">{matchCount} match{matchCount === 1 ? "" : "es"}</span>}
            <div className="graph-spacer" />
            <span className="graph-meta">{counts.asset || 0} assets · {nodes.length - (counts.asset || 0)} findings · {edges.length} links</span>
            <button type="button" className="graph-btn" onClick={() => setPaused((p) => !p)} aria-pressed={paused} title={paused ? "Resume layout" : "Pause layout"}>
              {paused ? <Play size={13} /> : <Pause size={13} />}{paused ? "Resume" : "Pause"}
            </button>
            <button type="button" className="graph-btn" onClick={reset} title="Reset layout and filters"><RotateCcw size={13} />Reset</button>
          </div>

          <div className="graph-body">
            <div className="graph-wrap">
              <canvas
                ref={canvasRef}
                style={{ cursor: hover ? (drag.current ? "grabbing" : "pointer") : "default" }}
                onMouseMove={(e) => {
                  const node = pick(e);
                  setHover(node);
                  if (drag.current) {
                    const rect = e.currentTarget.getBoundingClientRect();
                    drag.current.node.x = e.clientX - rect.left - drag.current.dx;
                    drag.current.node.y = e.clientY - rect.top - drag.current.dy;
                  }
                }}
                onMouseDown={(e) => {
                  const node = pick(e);
                  if (node) {
                    const rect = e.currentTarget.getBoundingClientRect();
                    drag.current = { node, dx: e.clientX - rect.left - node.x, dy: e.clientY - rect.top - node.y };
                  }
                }}
                onMouseUp={() => { drag.current = null; }}
                onMouseLeave={() => { drag.current = null; setHover(null); }}
                onClick={(e) => setSelected(pick(e))}
              />
              {loading && (
                <div className="graph-overlay" role="status" aria-live="polite">
                  <span className="graph-spinner" aria-hidden="true" />
                  <b>Building graph…</b>
                  <span>Correlating assets and findings</span>
                </div>
              )}
              {!loading && error && (
                <div className="graph-overlay">
                  <AlertCircle size={24} aria-hidden="true" />
                  <b>Couldn't load this graph</b>
                  <span>Check your connection or pick another scan.</span>
                  <button type="button" className="graph-btn" onClick={() => { const id = scanId; setScanId(""); setTimeout(() => setScanId(id), 0); }}>Try again</button>
                </div>
              )}
              {!loading && !error && !hasGraph && (
                <div className="graph-overlay">
                  <GitBranch size={26} aria-hidden="true" />
                  <b>Nothing to graph yet</b>
                  <span>This scan produced no assets or findings.</span>
                </div>
              )}
              {hasGraph && <canvas ref={miniRef} className="graph-minimap" width={168} height={104} aria-hidden="true" />}
              <div className="graph-legend" role="group" aria-label="Filter by type">
                {LEGEND.map((key) => (
                  <button type="button" key={key} className={hidden.has(key) ? "off" : ""} onClick={() => toggle(key)} aria-pressed={!hidden.has(key)}>
                    <i style={{ background: COLORS[key] }} />{key}<em>{counts[key] || 0}</em>
                  </button>
                ))}
              </div>
            </div>

            <aside className="graph-panel" aria-label="Node details">
              {selected ? (
                <>
                  <div className="graph-panel-head">
                    <span className="graph-pill" style={{ color: colorOf(selected), background: `${colorOf(selected)}14`, borderColor: `${colorOf(selected)}40` }}>
                      <i style={{ background: colorOf(selected) }} />{selected.kind === "asset" ? selected.assetKind || "asset" : selected.severity || "info"}
                    </span>
                    <button type="button" className="graph-x" onClick={() => setSelected(null)} aria-label="Close details"><X size={14} /></button>
                  </div>
                  <h3 className="graph-panel-title">{selected.label}</h3>
                  <dl className="graph-facts">
                    <div><dt>Lane</dt><dd>{groupOf(selected)}</dd></div>
                    <div><dt>Type</dt><dd>{selected.kind}</dd></div>
                    <div><dt>Connections</dt><dd>{selNeighbors.length}</dd></div>
                  </dl>
                  {selected.kind === "finding" && (
                    <button type="button" className="graph-btn primary" onClick={() => setDrawer(selected.id)}><ExternalLink size={13} />Open evidence</button>
                  )}
                  {selNeighbors.length > 0 && (
                    <>
                      <div className="graph-panel-sub">Connected {selNeighbors.length === 1 ? "node" : "nodes"}</div>
                      <ul className="graph-links">
                        {selNeighbors.map((n) => (
                          <li key={n.id}>
                            <button type="button" onClick={() => setSelected(n)}>
                              <i style={{ background: colorOf(n) }} /><span>{n.label}</span>
                            </button>
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                </>
              ) : (
                <div className="graph-panel-empty">
                  <GitBranch size={22} aria-hidden="true" />
                  <b>Select a node</b>
                  <span>Click an asset or finding to see its details and what it connects to. Drag nodes to rearrange.</span>
                </div>
              )}
            </aside>
          </div>
        </div>
      ) : <EmptyState icon={<GitBranch size={28} />} title="No completed scans" text="Finish a scan to build its graph." />}
      {drawer && <FindingDrawer id={drawer} onClose={() => setDrawer(null)} />}
    </>
  );
}
