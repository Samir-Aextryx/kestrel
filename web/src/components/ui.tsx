import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Check, Copy, X } from "lucide-react";
import type { Severity } from "../types";

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#c62828", high: "#c45a00", medium: "#9a6a00", low: "#0f766e", info: "#647067",
};
/** Darker text-safe variants of each severity for use on white/tinted surfaces (WCAG AA). */
export const SEV_INK: Record<Severity, string> = {
  critical: "#b42318", high: "#a64b00", medium: "#845b00", low: "#0f766e", info: "#56615a",
};
export const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Geometric kestrel mark: a stooping falcon seen from above, swept faceted wings. */
export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 4.5l2.6 7.2 11.4-2.4-8.6 7.6-2.9 10.6L16 23.2l-2.5 4.3-2.9-10.6L2 9.3l11.4 2.4L16 4.5z" fill="currentColor" />
      <path d="M16 11.2l1.3 4.6L16 19.6l-1.3-3.8L16 11.2z" fill="#ffffff" opacity="0.5" />
    </svg>
  );
}

/** Large faceted kestrel used on the sign-in surface: flat tonal facets with hairline edges. */
export function KestrelWings({ className = "" }: { className?: string }) {
  return (
    <svg className={`kestrel-wings ${className}`} viewBox="0 0 800 420" fill="none" aria-hidden="true">
      <g fill="currentColor">
        <path d="M400 70L452 190 348 190Z" opacity="0.9" />
        <path d="M452 190L780 130 640 168Z" opacity="0.28" />
        <path d="M348 190L20 130 160 168Z" opacity="0.28" />
        <path d="M452 190L640 168 520 262Z" opacity="0.5" />
        <path d="M348 190L160 168 280 262Z" opacity="0.5" />
        <path d="M640 168L780 130 520 262Z" opacity="0.16" />
        <path d="M160 168L20 130 280 262Z" opacity="0.16" />
        <path d="M452 190L520 262 400 262Z" opacity="0.7" />
        <path d="M348 190L280 262 400 262Z" opacity="0.62" />
        <path d="M400 262L520 262 446 400 400 330Z" opacity="0.38" />
        <path d="M400 262L280 262 354 400 400 330Z" opacity="0.3" />
        <path d="M348 190L452 190 400 262Z" opacity="0.8" />
      </g>
      <g stroke="#ffffff" strokeWidth="1.2" strokeLinejoin="round" opacity="0.85">
        <path d="M400 70L452 190 780 130 520 262 446 400 400 330 354 400 280 262 20 130 348 190Z" />
        <path d="M452 190L520 262M348 190L280 262M400 70L400 330M348 190H452M280 262H520" />
        <path d="M452 190L640 168 520 262M348 190L160 168 280 262M640 168L780 130M160 168L20 130" />
      </g>
    </svg>
  );
}

export function SeverityChip({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}><i className="sev-pip" />{severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`status status-${status}`}>
      <span className={`dot ${status}`} />
      {status}
    </span>
  );
}

/** Status orb: a glowing indicator with an optional pulse ring. */
export function Orb({ tone = "lime", pulse = false, size = 8 }: { tone?: "lime" | "cyan" | "red" | "orange" | "yellow" | "dim"; pulse?: boolean; size?: number }) {
  return <span className={`orb orb-${tone} ${pulse ? "pulse" : ""}`} style={{ width: size, height: size }} aria-hidden="true" />;
}

export function TimeAgo({ value }: { value: string }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);
  const diff = Math.max(0, now - new Date(value).getTime());
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return <span title={value}>just now</span>;
  if (mins < 60) return <span title={value}>{mins}m ago</span>;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return <span title={value}>{hours}h ago</span>;
  const days = Math.floor(hours / 24);
  if (days < 30) return <span title={value}>{days}d ago</span>;
  return <span title={value}>{new Date(value).toLocaleDateString()}</span>;
}

export function Sparkline({ data, color = "#2f6f3e", width = 92, height = 28 }: { data: number[]; color?: string; width?: number; height?: number }) {
  const gid = useId().replace(/:/g, "");
  const max = Math.max(1, ...data);
  const pts = data.map((v, i) => [(i / Math.max(1, data.length - 1)) * width, height - (v / max) * (height - 4) - 2] as const);
  const line = pts.map(([x, y]) => `${x},${y}`).join(" ");
  const area = `0,${height} ${line} ${width},${height}`;
  const last = pts[pts.length - 1];
  return (
    <svg width={width} height={height} className="spark" aria-hidden="true">
      <defs>
        <linearGradient id={`sp${gid}`} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.14" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#sp${gid})`} />
      <polyline points={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      {last && <circle cx={last[0]} cy={last[1]} r="2.2" fill={color} />}
    </svg>
  );
}

export function riskColor(score: number) {
  return score >= 75 ? "#b42318" : score >= 45 ? "#a64b00" : score >= 20 ? "#845b00" : "#2f6f3e";
}

/** Quiet gauge: hairline track + progress arc + numeric readout. */
export function RiskRing({ score, size = 96, label = "risk" }: { score: number; size?: number; label?: string }) {
  const c = size / 2;
  const r = (size - 10) / 2;
  const circumference = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score)) / 100;
  const color = riskColor(score);
  return (
    <svg width={size} height={size} className="risk-ring" viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Risk ${Math.round(score)} of 100`}>
      <circle cx={c} cy={c} r={r} fill="none" stroke="#e8ebe4" strokeWidth="5" />
      <circle
        cx={c} cy={c} r={r} fill="none" stroke={color} strokeWidth="5" strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={circumference * (1 - pct)}
        transform={`rotate(-90 ${c} ${c})`}
        style={{ transition: "stroke-dashoffset 0.8s cubic-bezier(.2,.7,.2,1)" }}
        opacity={pct === 0 ? 0 : 1}
      />
      <text x="50%" y={size >= 80 ? c - size * 0.05 : c} textAnchor="middle" dominantBaseline="central" fill="#111713" fontSize={size * 0.28} fontWeight="600" fontFamily="var(--display)" letterSpacing="-0.03em">
        {Math.round(score)}
      </text>
      {size >= 80 && (
        <text x="50%" y={c + size * 0.19} textAnchor="middle" fill="#56615a" fontSize={Math.max(8, size * 0.075)} fontWeight="600" fontFamily="var(--font)" letterSpacing="0.06em">
          {label.toUpperCase()}
        </text>
      )}
    </svg>
  );
}

/** Stacked severity meter with a hairline gap between segments. */
export function SeverityMeter({ counts, height = 6 }: { counts: Partial<Record<Severity, number>>; height?: number }) {
  const total = SEV_ORDER.reduce((a, s) => a + (counts[s] || 0), 0);
  return (
    <div className="sev-meter" style={{ height }} role="img" aria-label={SEV_ORDER.map((s) => `${counts[s] || 0} ${s}`).join(", ")}>
      {total === 0 ? <span className="sev-meter-empty" /> : SEV_ORDER.map((s) => (counts[s] ? <span key={s} style={{ flexGrow: counts[s], background: SEV_COLOR[s] }} title={`${counts[s]} ${s}`} /> : null))}
    </div>
  );
}

function hash(str: string) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) h = Math.imul(h ^ str.charCodeAt(i), 16777619);
  return (h >>> 0) / 4294967295;
}

/**
 * Radar scope. Each blip is a real item: bearing is derived from its id,
 * range from severity (critical sits closest to the center).
 */
export function RadarScope({ blips, size = 240, onSelect }: { blips: { id: string; severity: Severity; label: string }[]; size?: number; onSelect?: (id: string) => void }) {
  const c = size / 2;
  const R = c - 8;
  const RANGE: Record<Severity, number> = { critical: 0.28, high: 0.46, medium: 0.64, low: 0.8, info: 0.92 };
  return (
    <div className="radar-scope" style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} aria-hidden="true">
        <defs>
          <radialGradient id="rs-bg">
            <stop offset="0" stopColor="#2f6f3e" stopOpacity="0.05" />
            <stop offset="1" stopColor="#2f6f3e" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle cx={c} cy={c} r={R} fill="url(#rs-bg)" stroke="#d9ddd4" />
        {[0.25, 0.5, 0.75].map((p) => <circle key={p} cx={c} cy={c} r={R * p} fill="none" stroke="#e4e7e0" strokeDasharray="2 4" />)}
        <path d={`M${c} ${c - R}V${c + R}M${c - R} ${c}H${c + R}`} stroke="#e4e7e0" />
        {Array.from({ length: 72 }, (_, i) => {
          const a = (i / 72) * Math.PI * 2;
          const len = i % 6 === 0 ? 7 : 3;
          return <line key={i} x1={c + Math.cos(a) * R} y1={c + Math.sin(a) * R} x2={c + Math.cos(a) * (R - len)} y2={c + Math.sin(a) * (R - len)} stroke="#c5cbc2" />;
        })}
      </svg>
      <div className="radar-scope-sweep" />
      {blips.map((b) => {
        const a = hash(b.id) * Math.PI * 2;
        const r = R * (RANGE[b.severity] + (hash(b.id + "r") - 0.5) * 0.1);
        return (
          <button
            key={b.id}
            type="button"
            className={`blip blip-${b.severity}`}
            style={{ left: c + Math.cos(a) * r, top: c + Math.sin(a) * r, animationDelay: `${(a / (Math.PI * 2)) * 4}s` }}
            title={`${b.severity} · ${b.label}`}
            aria-label={`${b.severity}: ${b.label}`}
            onClick={() => onSelect?.(b.id)}
          />
        );
      })}
      <span className="radar-scope-core" />
    </div>
  );
}

/** Empty states: a soft tinted disc holding the icon, a title and one line of guidance. */
export function EmptyState({ icon, title, text, action, compact = false }: { icon?: ReactNode; title: string; text?: string; action?: ReactNode; compact?: boolean }) {
  return (
    <div className={`empty ${compact ? "compact" : ""}`}>
      {icon && <div className="empty-glyph" aria-hidden="true"><span className="empty-icon">{icon}</span></div>}
      <b>{title}</b>
      {text && <p>{text}</p>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

export function Modal({ title, children, onClose, footer, wide = false }: { title: string; children: ReactNode; onClose: () => void; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <span className="modal-mark"><Logo size={14} /></span>
          <h3>{title}</h3>
          <button className="icon-btn ml-auto" onClick={onClose} aria-label="Close"><X size={15} /></button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="btn btn-sm btn-ghost"
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? <Check size={13} /> : <Copy size={13} />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function BackButton() {
  const navigate = useNavigate();
  return (
    <button className="btn btn-ghost btn-sm back-btn" onClick={() => navigate(-1)}>
      <ArrowLeft size={13} /> Back
    </button>
  );
}

export function useTitle(title: string) {
  useEffect(() => {
    document.title = `${title} · KESTREL`;
  }, [title]);
}

export function Skeleton({ height = 16, width = "100%" }: { height?: number; width?: string }) {
  return <div className="skeleton" style={{ height, width }} />;
}

/** Table-shaped loading state: mirrors the real layout so content doesn't jump. */
export function SkeletonRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="skeleton-table" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="skeleton-row" style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
          {Array.from({ length: cols }, (_, c) => <div key={c} className="skeleton" style={{ height: 10, width: c === 0 ? "70%" : `${40 + ((r * 7 + c * 13) % 45)}%` }} />)}
        </div>
      ))}
    </div>
  );
}

export function useClickOutside<T extends HTMLElement>(onOutside: () => void) {
  const ref = useRef<T>(null);
  useEffect(() => {
    const handler = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) onOutside();
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [onOutside]);
  return ref;
}
