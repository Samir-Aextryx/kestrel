import { useEffect, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ArrowRight, LockKeyhole, ShieldCheck } from "lucide-react";
import { login } from "../api";
import { useAuth } from "../AuthContext";
import { KestrelWings, Logo, Orb, useTitle } from "../components/ui";

export default function Login() {
  useTitle("Sign in");
  const { user, setUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (user) navigate("/", { replace: true });
  }, [user, navigate]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await login(email, password);
      setUser(result.user);
      navigate((location.state as { from?: string })?.from || "/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <section className="login-art">
        <div className="login-brand">
          <span className="brand-mark"><Logo size={20} /></span>
          <b>KESTREL</b>
          <span>Research console</span>
        </div>
        <KestrelWings />
        <div className="login-copy">
          <div className="eyebrow">Autonomous security research</div>
          <h1>Find what<br /><span>scanners miss.</span></h1>
          <p>
            Evidence-first analysis across source, cloud, containers, APIs and live surfaces.
            Deterministic engines, a differential zero-day lab and a verifier that refuses to guess.
          </p>
        </div>
        <div className="foot">
          <div className="login-stat"><b>Scope</b><span>Gated by design</span></div>
          <div className="login-stat"><b>Evidence</b><span>Hashed and signed</span></div>
          <div className="login-stat"><b>Runtime</b><span>Local-first</span></div>
        </div>
      </section>
      <section className="login-form">
        <div className="login-card">
          <div className="login-auth">
            <ShieldCheck size={13} color="#2f6f3e" />
            Authorized research only
          </div>
          <h2>Sign in to the console</h2>
          <p>Use the administrator credentials printed on first boot.</p>
          <form onSubmit={submit}>
            <div className="field">
              <label htmlFor="email">Email</label>
              <input id="email" className="input" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input id="password" className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </div>
            {error && <div className="callout danger" role="alert">{error}</div>}
            <button className="btn btn-primary" type="submit" disabled={busy}>
              {busy ? <span className="spinner" /> : <LockKeyhole size={15} />}
              {busy ? "Signing in…" : "Sign in"}
              {!busy && <ArrowRight size={15} />}
            </button>
          </form>
          <div className="login-fine">
            <span><Orb tone="lime" size={6} /> Sessions expire after 12 hours.</span>
            <span><Orb tone="cyan" size={6} /> Mutations require a per-session CSRF token.</span>
          </div>
        </div>
      </section>
    </div>
  );
}
