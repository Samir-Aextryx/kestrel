import { useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity, Boxes, Bug, ChartNoAxesCombined, FileText, FlaskConical, GitBranch,
  LayoutDashboard, Plug, Search, Settings, LogOut, BookOpen, ChevronRight,
  Bot, Menu, Radar, X, Microscope, KeyRound, Crosshair,
} from "lucide-react";
import { Logo } from "./ui";
import { CommandPalette } from "./CommandPalette";
import { useAuth } from "../AuthContext";
import { logout } from "../api";

const GROUPS = [
  {
    label: "Operate",
    items: [
      { to: "/", label: "Command Center", icon: LayoutDashboard, end: true },
      { to: "/autonomy", label: "Autonomy", icon: Bot },
      { to: "/agent", label: "Agent", icon: KeyRound },
      { to: "/scans", label: "Scans", icon: Activity },
      { to: "/operations", label: "Operations", icon: Crosshair },
    ],
  },
  {
    label: "Research",
    items: [
      { to: "/research", label: "Research", icon: Microscope },
      { to: "/findings", label: "Findings", icon: Bug },
      { to: "/graph", label: "Attack Graph", icon: GitBranch },
      { to: "/assets", label: "Assets", icon: Boxes },
      { to: "/fuzzing", label: "Fuzzing Lab", icon: FlaskConical },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/benchmark", label: "Benchmark", icon: ChartNoAxesCombined },
      { to: "/plugins", label: "Plugins", icon: Plug },
      { to: "/settings", label: "Settings", icon: Settings },
      { to: "/docs", label: "Method", icon: BookOpen },
    ],
  },
];

const TITLES: Record<string, string[]> = {
  "/": ["Command Center"],
  "/autonomy": ["Autonomy"],
  "/agent": ["Agent"],
  "/research": ["Research"],
  "/scans": ["Scans"],
  "/operations": ["Operations"],
  "/scans/new": ["Scans", "New scan"],
  "/findings": ["Findings"],
  "/graph": ["Attack Graph"],
  "/assets": ["Assets"],
  "/fuzzing": ["Fuzzing Lab"],
  "/reports": ["Reports"],
  "/benchmark": ["Benchmark"],
  "/plugins": ["Plugins"],
  "/settings": ["Settings"],
  "/docs": ["Method"],
};

export default function Layout() {
  const { user, setUser } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [palette, setPalette] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPalette(true);
      }
      if (event.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => setNavOpen(false), [location.pathname]);

  const crumbs = useMemo(() => {
    if (location.pathname.startsWith("/scans/") && location.pathname !== "/scans/new") return ["Scans", "Live run"];
    if (location.pathname.startsWith("/findings/")) return ["Findings", "Detail"];
    return TITLES[location.pathname] || ["KESTREL"];
  }, [location.pathname]);

  async function signOut() {
    await logout();
    setUser(null);
    navigate("/login");
  }

  return (
    <div className={`app ${navOpen ? "nav-open" : ""}`}>
      <a href="#main" className="skip-link">Skip to content</a>
      <aside className="sidebar" aria-label="Primary">
        <div className="sidebar-brand">
          <NavLink to="/" className="brand-mark" aria-label="KESTREL home">
            <Logo size={20} />
          </NavLink>
          <div className="brand-text">
            <b>KESTREL</b>
            <span>Research console</span>
          </div>
          <button className="icon-btn sidebar-close" onClick={() => setNavOpen(false)} aria-label="Close navigation"><X size={16} /></button>
        </div>
        <nav className="sidebar-nav">
          {GROUPS.map((group) => (
            <div key={group.label} className="nav-group">
              <div className="nav-label">{group.label}</div>
              {group.items.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`} aria-label={item.label}>
                  <item.icon size={17} strokeWidth={1.7} />
                  <span className="tip">{item.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-spacer" />
        <div className="sidebar-foot">
          <button className="nav-item" onClick={() => setPalette(true)} aria-label="Search">
            <Search size={17} strokeWidth={1.7} />
            <span className="tip">Search</span>
            <span className="kbd nav-kbd">Ctrl K</span>
          </button>
          <div className="user-card">
            <div className="avatar" title={user?.email}>{user?.name?.slice(0, 2).toUpperCase()}</div>
            <div className="user-meta">
              <b className="truncate">{user?.name}</b>
              <span className="truncate">{user?.role} · {user?.email}</span>
            </div>
            <button className="icon-btn user-out" onClick={signOut} aria-label="Sign out" title="Sign out">
              <LogOut size={15} strokeWidth={1.8} />
            </button>
          </div>
          <div className="system-foot"><span className="orb orb-lime" /> KSTL 1.0 · local</div>
        </div>
      </aside>
      <div className="nav-scrim" onClick={() => setNavOpen(false)} aria-hidden="true" />
      <div className="main">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setNavOpen(true)} aria-label="Open navigation"><Menu size={18} /></button>
          <nav className="crumbs" aria-label="Breadcrumb">
            <span className="crumb-root">KSTL</span>
            {crumbs.map((crumb, idx) => (
              <span key={crumb} className="flex">
                <span className="sep"><ChevronRight size={12} /></span>
                {idx === crumbs.length - 1 ? <b>{crumb}</b> : <span>{crumb}</span>}
              </span>
            ))}
          </nav>
          <div className="topbar-spacer" />
          <span className="live-pill" title="Console is receiving live updates">
            <svg width="26" height="10" viewBox="0 0 26 10" aria-hidden="true"><polyline className="live-trace" points="0,5 5,5 7,1 10,9 13,3 15,5 26,5" fill="none" stroke="currentColor" strokeWidth="1.2" /></svg>
            LIVE
          </span>
          <button className="search-trigger" onClick={() => setPalette(true)} aria-label="Search">
            <Search size={14} />
            <span>Search targets, findings…</span>
            <span className="kbd">Ctrl K</span>
          </button>
          <NavLink to="/scans/new" className="btn btn-primary btn-sm topbar-cta">
            <Radar size={14} /> <span>New scan</span>
          </NavLink>
        </header>
        <main className="content" id="main">
          <Outlet />
        </main>
      </div>
      {palette && <CommandPalette onClose={() => setPalette(false)} />}
    </div>
  );
}
