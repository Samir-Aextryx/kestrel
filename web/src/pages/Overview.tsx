import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Activity, ArrowUpRight, Bot, Bug, Cpu, FlaskConical, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "../api";
import {
  EmptyState, Orb, RiskRing, SEV_COLOR, SEV_ORDER, SeverityChip, SeverityMeter, Skeleton, SkeletonRows,
  Sparkline, StatusBadge, TimeAgo, riskColor, useTitle,
} from "../components/ui";
import type { Severity } from "../types";

type Dashboard = {
  empty?: boolean;
  totals: { scans: number; running: number };
  severity: Record<Severity, number>;
  recent: { id: string; name: string; target: string; target_type: string; status: string; risk_score: number; created_at: string; findings: number }[];
  trend: { day: string; findings: number; severe: number }[];
  topRules: { rule_id: string; engine: string; n: number }[];
  recentFindings: { id: string; title: string; severity: Severity; scan_id: string; engine: string; created_at: string }[];
  agents: { agent: string; status: string; n: number }[];
  queue: { running: number; queued: number };
  llm: { calls: number; cost: number; tokens: number };
  agentLabels: Record<string, string>;
  autonomy?: { goals: number; running: number; awaiting: number; decisions: number };
};

export default function Overview() {
  useTitle("Command Center");
  const [data, setData] = useState<Dashboard | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let alive = true;
    const load = () => api.get<Dashboard>("/dashboard").then((d) => alive && setData(d)).catch(() => {});
    load();
    const timer = setInterval(load, 5000);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  const total = useMemo(() => data ? Object.values(data.severity).reduce((a, b) => a + b, 0) : 0, [data]);
  const risk = useMemo(() => {
    if (!data) return 0;
    const weighted = data.severity.critical * 10 + data.severity.high * 6 + data.severity.medium * 3 + data.severity.low;
    return Math.min(100, Math.round(100 * (1 - Math.exp(-weighted / 55))));
  }, [data]);
  const severeTrend = data?.trend.map((t) => t.severe) || [];
  const findingTrend = data?.trend.map((t) => t.findings) || [];
  const runningAgents = data?.agents.filter((a) => a.status === "running") || [];
  const severe = (data?.severity.critical ?? 0) + (data?.severity.high ?? 0);
  const awaiting = data?.autonomy?.awaiting ?? 0;
  const posture = risk >= 75 ? "Critical exposure" : risk >= 45 ? "Elevated exposure" : risk >= 20 ? "Moderate exposure" : "Controlled exposure";
  const postureTone = risk >= 75 ? "red" : risk >= 45 ? "orange" : risk >= 20 ? "yellow" : "lime";
  const maxRule = Math.max(1, ...(data?.topRules.map((r) => r.n) || [1]));

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Operational picture</div>
          <h1>Command Center</h1>
          <p>Live risk, coverage and agent activity across every authorized workspace.</p>
        </div>
        <div className="actions">
          <Link to="/benchmark" className="btn"><FlaskConical size={14} /> Benchmark</Link>
          <Link to="/scans/new" className="btn btn-primary"><Radar size={14} /> Start research</Link>
        </div>
      </div>

      {!data ? (
        <div className="panel" style={{ padding: 28 }} aria-busy="true">
          <div className="flex" style={{ gap: 28 }}>
            <Skeleton height={112} width="112px" />
            <div className="grid" style={{ flex: 1, gap: 12 }}>
              <Skeleton height={12} width="22%" />
              <Skeleton height={26} width="46%" />
              <Skeleton height={12} width="72%" />
              <Skeleton height={6} width="72%" />
            </div>
          </div>
        </div>
      ) : (
        <section className="panel hero" aria-label="Exposure summary">
          <div className="hero-main">
            <RiskRing score={risk} size={124} label="exposure" />
            <div className="hero-narrative">
              <div className="hero-state"><Orb tone={postureTone} pulse={risk >= 45} /> Aggregate exposure</div>
              <h2>{posture}</h2>
              <p>
                {total === 0 && data.totals.scans === 0 ? (
                  <>No research has run yet. Scope a scan or run the benchmark lab to establish a baseline.</>
                ) : (
                  <>
                    <b>{total}</b> open findings across <b>{data.totals.scans}</b> scans.{" "}
                    {severe > 0 ? <><b style={{ color: "#b42318" }}>{data.severity.critical} critical</b> and <b style={{ color: "#a64b00" }}>{data.severity.high} high</b> issues need a decision.</> : <>Nothing critical or high is open.</>}
                    {awaiting > 0 && <> <b style={{ color: "#845b00" }}>{awaiting}</b> autonomous {awaiting === 1 ? "goal is" : "goals are"} waiting for approval.</>}
                  </>
                )}
              </p>
              <div className="hero-meter">
                <SeverityMeter counts={data.severity} height={6} />
                <div className="hero-meter-legend">
                  {SEV_ORDER.map((s) => <span key={s}><i style={{ background: SEV_COLOR[s] }} />{s} <b>{data.severity[s] || 0}</b></span>)}
                </div>
              </div>
              <div className="actions">
                <Link to="/findings?severity=critical,high" className="btn btn-danger"><ShieldAlert size={14} /> Triage critical</Link>
                <Link to="/graph" className="btn"><ArrowUpRight size={14} /> Attack graph</Link>
              </div>
            </div>
          </div>
          <div className="hero-scope" aria-label="Pipeline status">
            <div className="hero-scope-cap"><span>Pipeline</span><span>now</span></div>
            <dl className="hero-facts">
              <div><dt><Orb tone={data.totals.running ? "lime" : "dim"} pulse={!!data.totals.running} size={6} /> Running</dt><dd>{data.totals.running}</dd></div>
              <div><dt>Queued</dt><dd>{data.queue.queued}</dd></div>
              <div><dt>Recent findings</dt><dd>{data.recentFindings.length}</dd></div>
              <div><dt>Awaiting approval</dt><dd className={awaiting ? "warn" : ""}>{awaiting}</dd></div>
            </dl>
          </div>
        </section>
      )}

      <div className="grid grid-4 mt-16">
        <div className="panel kpi red">
          <div className="label">Critical + high</div>
          <div className="value">{severe}</div>
          <div className="delta">{severe ? "Awaiting triage decision" : "No severe exposure open"}</div>
          {severeTrend.length > 1 && <Sparkline data={severeTrend} color="#c62828" />}
        </div>
        <div className="panel kpi cyan">
          <div className="label">Findings</div>
          <div className="value">{total}</div>
          <div className="delta">Across all severities</div>
          {findingTrend.length > 1 && <Sparkline data={findingTrend} color="#0f766e" />}
        </div>
        <div className="panel kpi lime">
          <div className="label">Scans</div>
          <div className="value">{data?.totals.scans ?? 0}</div>
          <div className="delta"><Orb tone={data?.totals.running ? "lime" : "dim"} pulse={!!data?.totals.running} size={6} /> {data?.totals.running ?? 0} running · {data?.queue.queued ?? 0} queued</div>
          <div className="kpi-bar"><span style={{ width: `${data?.totals.scans ? Math.min(100, ((data.totals.running + data.queue.queued) / data.totals.scans) * 100) : 0}%` }} /></div>
        </div>
        <div className="panel kpi">
          <div className="label">Model calls</div>
          <div className="value">{data?.llm.calls ?? 0}</div>
          <div className="delta mono">{(data?.llm.tokens ?? 0).toLocaleString()} tok · ${(data?.llm.cost ?? 0).toFixed(3)}</div>
        </div>
      </div>

      <div className="grid grid-3 mt-16">
        <div className="panel span-2">
          <div className="panel-head">
            <Activity size={15} color="#0f766e" />
            <h2>Live signal</h2>
            <span className="sub">findings / day · 14d</span>
            <div className="right chart-legend">
              <span><i style={{ background: "#0f766e" }} />all</span>
              <span><i style={{ background: "#c62828" }} />severe</span>
            </div>
          </div>
          <div className="panel-body">
            {data ? <TrendChart data={data.trend} /> : <Skeleton height={190} />}
          </div>
        </div>
        <div className="panel">
          <div className="panel-head">
            <Bot size={15} color="#2f6f3e" />
            <h2>Autonomy</h2>
            <div className="right"><Link to="/autonomy" className="btn btn-sm btn-ghost">Open console <ArrowUpRight size={12} /></Link></div>
          </div>
          <div className="autonomy-dial">
            <Orb tone={awaiting ? "yellow" : data?.autonomy?.running ? "lime" : "dim"} pulse={!!(awaiting || data?.autonomy?.running)} size={10} />
            <div>
              <h3>{awaiting ? "Waiting on you" : data?.autonomy?.running ? "Agents operating" : data?.autonomy?.goals ? "Idle within policy" : "No goals yet"}</h3>
              <p>{awaiting ? `${awaiting} goal${awaiting === 1 ? "" : "s"} paused at the approval gate.` : data?.autonomy?.goals ? "Planner, policy and verifier are standing by." : "Create a goal and let the planner build the scope."}</p>
            </div>
          </div>
          <div className="stat-row">
            <div className="stat-cell"><div className="k">Goals</div><div className="v">{data?.autonomy?.goals ?? 0}</div></div>
            <div className="stat-cell"><div className="k">Running</div><div className={`v ${data?.autonomy?.running ? "ok" : ""}`}>{data?.autonomy?.running ?? 0}</div></div>
            <div className="stat-cell"><div className="k">Approval</div><div className={`v ${awaiting ? "warn" : ""}`}>{awaiting}</div></div>
            <div className="stat-cell"><div className="k">Receipts</div><div className="v">{data?.autonomy?.decisions ?? 0}</div></div>
          </div>
        </div>
      </div>

      <div className="grid grid-3 mt-16">
        <div className="panel span-2">
          <div className="panel-head">
            <Radar size={15} color="#2f6f3e" />
            <h2>Recent activity</h2>
            <span className="sub">scans</span>
            <div className="right"><Link to="/scans" className="btn btn-sm btn-ghost">All scans <ArrowUpRight size={12} /></Link></div>
          </div>
          <div className="panel-body tight table-wrap">
            {!data ? <SkeletonRows rows={5} cols={5} /> : data.recent.length ? (
              <table className="data">
                <thead><tr><th>Scan</th><th>Type</th><th>Status</th><th>Risk</th><th>Findings</th><th>Created</th></tr></thead>
                <tbody>
                  {data.recent.map((scan) => (
                    <tr key={scan.id} className="row-link" onClick={() => navigate(`/scans/${scan.id}`)}>
                      <td><div className="cell-title"><b>{scan.name}</b><span className="mono dim truncate" style={{ maxWidth: 320 }}>{scan.target}</span></div></td>
                      <td><span className="tag">{scan.target_type}</span></td>
                      <td><StatusBadge status={scan.status} /></td>
                      <td><RiskNum score={scan.risk_score} /></td>
                      <td className="mono">{scan.findings}</td>
                      <td className="dim nowrap"><TimeAgo value={scan.created_at} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <EmptyState icon={<Radar size={20} />} title="No scans yet" text="Start with the benchmark to see the full pipeline, or point KESTREL at a project." action={<Link to="/scans/new" className="btn btn-primary btn-sm">New scan</Link>} />}
          </div>
        </div>
        <div className="panel">
          <div className="panel-head">
            <Sparkles size={15} color="#2f6f3e" />
            <h2>Live findings</h2>
            <div className="right"><Link to="/findings" className="btn btn-sm btn-ghost">Ledger <ArrowUpRight size={12} /></Link></div>
          </div>
          <div className="feed">
            {!data ? <SkeletonRows rows={5} cols={1} /> : data.recentFindings.length ? data.recentFindings.map((f) => (
              <Link key={f.id} to={`/findings/${f.id}`} className="feed-item" style={{ boxShadow: `inset 2px 0 0 ${SEV_COLOR[f.severity]}` }}>
                <span className="time"><TimeAgo value={f.created_at} /></span>
                <span className="msg"><SeverityChip severity={f.severity} />{f.title}<div className="agent">{f.engine}</div></span>
              </Link>
            )) : <EmptyState compact icon={<Bug size={18} />} title="Quiet for now" text="Findings stream in as agents work." />}
          </div>
        </div>
      </div>

      <div className="grid grid-2 mt-16">
        <div className="panel">
          <div className="panel-head">
            <Cpu size={15} color="#0f766e" />
            <h2>Agent coverage</h2>
            <span className="sub">24h</span>
            <div className="right"><span className="tag">{runningAgents.length} active</span></div>
          </div>
          <div className="panel-body">
            {data?.agents.length ? (
              <div className="agent-grid">
                {data.agents.map((a) => (
                  <div key={`${a.agent}-${a.status}`} className={`agent ${a.status}`}>
                    <span className={`dot ${a.status}`} />
                    <span className="truncate">{data.agentLabels[a.agent] || a.agent}</span>
                    <span className="ml-auto mono">{a.n}</span>
                  </div>
                ))}
              </div>
            ) : <EmptyState compact icon={<Cpu size={18} />} title="No agent activity" text="Agent runs from the last 24 hours appear here." />}
          </div>
        </div>
        <div className="panel">
          <div className="panel-head"><Bug size={15} color="#c45a00" /><h2>Noisiest rules</h2><span className="sub">by hit count</span></div>
          <div className="panel-body">
            {data?.topRules.length ? (
              <div className="bars">
                {data.topRules.map((rule) => (
                  <div className="rule-row" key={rule.rule_id}>
                    <span className="mono truncate">{rule.rule_id}</span>
                    <span className="tag">{rule.engine}</span>
                    <b>{rule.n}</b>
                    <div className="rule-bar"><span style={{ width: `${(rule.n / maxRule) * 100}%` }} /></div>
                  </div>
                ))}
              </div>
            ) : <EmptyState compact icon={<Bug size={18} />} title="No rule statistics" text="Rule hit counts appear after the first scan." />}
          </div>
        </div>
      </div>
    </>
  );
}

function RiskNum({ score }: { score: number }) {
  const color = riskColor(score);
  return (
    <span className="risk-num" style={{ color }}>
      {score}
      <i><span style={{ width: `${Math.min(100, score)}%`, background: color }} /></i>
    </span>
  );
}

function TrendChart({ data }: { data: { day: string; findings: number; severe: number }[] }) {
  if (!data.length) return <EmptyState compact icon={<Activity size={18} />} title="No signal yet" text="The chart fills as scans complete." />;
  const width = 760;
  const height = 200;
  const padB = 22;
  const padT = 10;
  const max = Math.max(1, ...data.map((d) => d.findings));
  const x = (i: number) => (i / Math.max(1, data.length - 1)) * width;
  const y = (v: number) => height - padB - (v / max) * (height - padB - padT);
  const all = data.map((d, i) => `${x(i)},${y(d.findings)}`).join(" ");
  const severe = data.map((d, i) => `${x(i)},${y(d.severe)}`).join(" ");
  const lastIdx = data.length - 1;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="signal-chart" role="img" aria-label={`Findings per day over ${data.length} days`}>
      <defs>
        <linearGradient id="sig-all" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="#0f766e" stopOpacity="0.1" />
          <stop offset="1" stopColor="#0f766e" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="sig-sev" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="#c62828" stopOpacity="0.08" />
          <stop offset="1" stopColor="#c62828" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 0.25, 0.5, 0.75, 1].map((p) => (
        <g key={p}>
          <line x1="0" x2={width} y1={padT + (height - padB - padT) * p} y2={padT + (height - padB - padT) * p} stroke={p === 1 ? "#d9ddd4" : "#eceee8"} vectorEffect="non-scaling-stroke" />
        </g>
      ))}
      <polygon points={`0,${height - padB} ${all} ${width},${height - padB}`} fill="url(#sig-all)" />
      <polygon points={`0,${height - padB} ${severe} ${width},${height - padB}`} fill="url(#sig-sev)" />
      <polyline points={all} fill="none" stroke="#0f766e" strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
      <polyline points={severe} fill="none" stroke="#c62828" strokeWidth="1.6" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
      <circle cx={x(lastIdx)} cy={y(data[lastIdx].findings)} r="3.5" fill="#ffffff" stroke="#0f766e" strokeWidth="1.75" />
      {data.map((d, i) => (
        i % Math.ceil(data.length / 7) === 0 || i === lastIdx ? (
          <text key={d.day} x={Math.min(width - 16, Math.max(16, x(i)))} y={height - 6} fill="#647067" fontSize="9.5" fontFamily="var(--mono)" textAnchor="middle">{d.day.slice(5)}</text>
        ) : null
      ))}
      <text x="4" y={padT + 10} fill="#647067" fontSize="9.5" fontFamily="var(--mono)">{max}</text>
    </svg>
  );
}
