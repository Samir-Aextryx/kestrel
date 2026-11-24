import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Cpu, FolderGit2, KeyRound, Plus, Save, ScrollText, Settings2, ShieldCheck, Trash2, Users, Zap } from "lucide-react";
import { api } from "../api";
import { useAuth } from "../AuthContext";
import { useToast } from "../components/Toast";
import { CopyButton, EmptyState, Modal, Orb, Skeleton, SkeletonRows, TimeAgo, useTitle } from "../components/ui";
import type { Project } from "../types";

const TABS = [
  ["general", "General", Settings2, "Scan defaults and dependency license policy."],
  ["llm", "Cloud AI", Cpu, "Model providers, routing strategy and per-scan budgets."],
  ["projects", "Projects", FolderGit2, "Source trees available to code, IaC and binary scans."],
  ["users", "Users", Users, "Who can sign in and what they can change."],
  ["tokens", "API tokens", KeyRound, "Bearer tokens for CI and automation. They bypass CSRF."],
  ["audit", "Audit log", ScrollText, "Every mutation, with actor and source address."],
] as const;

type TabId = (typeof TABS)[number][0];
type Profile = { id: string; name: string; provider: string; baseUrl: string; model: string; apiKey?: string; hasKey?: boolean; roles: string[]; priority: number; costIn: number; costOut: number; enabled: boolean };
type User = { id: string; email: string; name: string; role: string; created_at: string; last_login?: string };
type Token = { id: string; name: string; scopes: string[]; last_used?: string; created_at: string };
type Audit = { id: number; email?: string; action: string; object_type?: string; object_id?: string; ip?: string; created_at: string };

function SectionHead({ id, action }: { id: TabId; action?: ReactNode }) {
  const [, label, Icon, desc] = TABS.find((t) => t[0] === id)!;
  return (
    <div className="settings-section-head">
      <Icon size={16} color="#2f6f3e" style={{ alignSelf: "center" }} />
      <div style={{ minWidth: 0 }}>
        <h2>{label}</h2>
        <p>{desc}</p>
      </div>
      {action && <div className="ml-auto" style={{ alignSelf: "center" }}>{action}</div>}
    </div>
  );
}

export default function Settings() {
  useTitle("Settings");
  const { user } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState<TabId>("general");
  const [general, setGeneral] = useState<{ licensePolicy: { deny: string[]; allow: string[] }; defaults: { fuzzIterations: number; requireApproval: boolean }; version: string } | null>(null);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [strategy, setStrategy] = useState("priority");
  const [maxCalls, setMaxCalls] = useState(60);
  const [maxCost, setMaxCost] = useState(1.5);
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [tokens, setTokens] = useState<Token[] | null>(null);
  const [audit, setAudit] = useState<Audit[] | null>(null);
  const [newToken, setNewToken] = useState("");
  const [modal, setModal] = useState<"user" | "token" | "project" | null>(null);
  const [form, setForm] = useState<Record<string, string>>({});
  const [testing, setTesting] = useState<string | null>(null);

  useEffect(() => {
    api.get<{ llm: { enabled: boolean; strategy: string; maxCallsPerScan: number; maxCostPerScan: number; profiles: Profile[] }; general: typeof general }>("/settings").then((data) => {
      setGeneral(data.general);
      setProfiles(data.llm.profiles);
      setLlmEnabled(data.llm.enabled);
      setStrategy(data.llm.strategy);
      setMaxCalls(data.llm.maxCallsPerScan);
      setMaxCost(data.llm.maxCostPerScan);
    }).catch(() => {}).finally(() => setSettingsLoaded(true));
    api.get<Project[]>("/projects").then(setProjects).catch(() => setProjects([]));
    api.get<User[]>("/users").then(setUsers).catch(() => setUsers([]));
    api.get<Token[]>("/auth/tokens").then(setTokens).catch(() => setTokens([]));
  }, []);

  useEffect(() => {
    if (tab === "audit") api.get<Audit[]>("/audit").then(setAudit).catch(() => setAudit([]));
  }, [tab]);

  function updateProfile(index: number, patch: Partial<Profile>) {
    setProfiles((list) => list.map((p, i) => i === index ? { ...p, ...patch } : p));
  }

  async function saveLLM() {
    try {
      await api.put("/settings/llm", { enabled: llmEnabled, strategy, maxCallsPerScan: maxCalls, maxCostPerScan: maxCost, profiles });
      toast.push("success", "AI settings saved");
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Save failed");
    }
  }

  async function testProfile(profile: Profile) {
    setTesting(profile.id);
    try {
      const result = await api.post<{ latencyMs: number }>("/settings/llm/test", profile);
      toast.push("success", `Connection OK · ${result.latencyMs}ms`);
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Connection failed");
    } finally {
      setTesting(null);
    }
  }

  async function saveGeneral() {
    if (!general) return;
    try {
      await api.put("/settings/general", { licensePolicy: general.licensePolicy, defaults: general.defaults });
      toast.push("success", "General settings saved");
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Save failed");
    }
  }

  async function importPath() {
    try {
      await api.post("/projects/path", { path: form.path, name: form.name });
      toast.push("success", "Project imported");
      setModal(null);
      setProjects(await api.get<Project[]>("/projects"));
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Import failed");
    }
  }

  async function createUser() {
    try {
      await api.post("/users", form);
      toast.push("success", "User created");
      setModal(null);
      setUsers(await api.get<User[]>("/users"));
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Create failed");
    }
  }

  async function createToken() {
    try {
      const result = await api.post<{ token: string }>("/auth/tokens", { name: form.name, scopes: ["read", "write"] });
      setNewToken(result.token);
      setTokens(await api.get<Token[]>("/auth/tokens"));
    } catch (err) {
      toast.push("error", err instanceof Error ? err.message : "Create failed");
    }
  }

  const keyed = profiles.filter((p) => p.hasKey || p.apiKey || p.provider === "ollama").length;

  return (
    <>
      <div className="page-head">
        <div><div className="eyebrow">Control plane</div><h1>Settings</h1><p>Model routing, policy, access and audit. Secrets are encrypted with AES-256-GCM at rest.</p></div>
      </div>
      <div className="settings-grid">
        <nav className="settings-nav" aria-label="Settings sections">
          {TABS.map(([id, label, Icon]) => (
            <button key={id} className={tab === id ? "on" : ""} onClick={() => setTab(id)} aria-current={tab === id ? "page" : undefined}><Icon size={14} />{label}</button>
          ))}
        </nav>
        <div style={{ minWidth: 0 }}>
          {tab === "general" && (
            <>
              <SectionHead id="general" />
              {!settingsLoaded ? (
                <div className="panel panel-body grid" style={{ gap: 12 }}><Skeleton height={12} width="30%" /><Skeleton height={36} /><Skeleton height={96} /></div>
              ) : !general ? (
                <div className="panel"><EmptyState icon={<Settings2 size={20} />} title="Settings unavailable" text="Only administrators can read general settings." /></div>
              ) : (
                <div className="grid" style={{ gap: 14 }}>
                  <div className="panel">
                    <div className="panel-head"><h3>Scan defaults</h3><span className="sub">applied to new scans</span></div>
                    <div className="panel-body grid grid-2">
                      <div className="field"><label htmlFor="def-fuzz">Fuzz iterations per function</label><input id="def-fuzz" className="input mono" type="number" min={20} max={3000} value={general.defaults.fuzzIterations} onChange={(e) => setGeneral({ ...general, defaults: { ...general.defaults, fuzzIterations: Number(e.target.value) } })} /></div>
                      <label className="check" style={{ alignSelf: "end" }}><input type="checkbox" checked={general.defaults.requireApproval} onChange={(e) => setGeneral({ ...general, defaults: { ...general.defaults, requireApproval: e.target.checked } })} /><span><span className="t">Require approval by default</span><span className="d">For active engines.</span></span></label>
                    </div>
                  </div>
                  <div className="panel">
                    <div className="panel-head"><h3>License policy</h3><span className="sub">one SPDX id per line</span></div>
                    <div className="panel-body grid grid-2">
                      <div className="field"><label htmlFor="lic-deny">Denied licenses</label><textarea id="lic-deny" className="textarea" value={general.licensePolicy.deny.join("\n")} onChange={(e) => setGeneral({ ...general, licensePolicy: { ...general.licensePolicy, deny: e.target.value.split("\n").filter(Boolean) } })} /></div>
                      <div className="field"><label htmlFor="lic-allow">Explicit allow overrides</label><textarea id="lic-allow" className="textarea" value={general.licensePolicy.allow.join("\n")} onChange={(e) => setGeneral({ ...general, licensePolicy: { ...general.licensePolicy, allow: e.target.value.split("\n").filter(Boolean) } })} /></div>
                    </div>
                  </div>
                  <div className="save-bar">
                    <span className="small">Changes apply to scans created after saving.</span>
                    <button className="btn btn-primary ml-auto" onClick={saveGeneral}><Save size={14} /> Save general settings</button>
                  </div>
                </div>
              )}
            </>
          )}

          {tab === "llm" && (
            <>
              <SectionHead id="llm" />
              <div className="grid" style={{ gap: 14 }}>
                <div className="panel">
                  <div className="panel-head">
                    <Cpu size={14} color="#2f6f3e" /><h3>Routing</h3>
                    <span className="sub flex" style={{ gap: 6 }}><Orb tone={llmEnabled && keyed ? "lime" : "dim"} size={6} />{llmEnabled ? `${keyed}/${profiles.length} providers ready` : "deterministic only"}</span>
                    <div className="right"><label className="check" style={{ padding: "4px 10px" }}><input type="checkbox" checked={llmEnabled} onChange={(e) => setLlmEnabled(e.target.checked)} /><span className="t">Enabled</span></label></div>
                  </div>
                  <div className="panel-body grid grid-3">
                    <div className="field"><label htmlFor="llm-strategy">Strategy</label><select id="llm-strategy" className="select" value={strategy} onChange={(e) => setStrategy(e.target.value)}><option value="priority">Priority</option><option value="round_robin">Round robin</option><option value="cheapest">Cheapest</option></select></div>
                    <div className="field"><label htmlFor="llm-calls">Max calls / scan</label><input id="llm-calls" className="input mono" type="number" value={maxCalls} onChange={(e) => setMaxCalls(Number(e.target.value))} /></div>
                    <div className="field"><label htmlFor="llm-cost">Max cost / scan (USD)</label><input id="llm-cost" className="input mono" type="number" step="0.1" value={maxCost} onChange={(e) => setMaxCost(Number(e.target.value))} /></div>
                  </div>
                </div>
                {profiles.map((profile, index) => (
                  <div key={profile.id || index} className="panel">
                    <div className="panel-head">
                      <span className="mono dim small">#{index + 1}</span>
                      <h3 className="truncate">{profile.name || "New provider"}</h3>
                      {profile.hasKey && <span className="tag"><KeyRound size={10} /> key stored</span>}
                      <div className="right">
                        <button className="btn btn-sm" onClick={() => testProfile(profile)} disabled={testing === profile.id}>{testing === profile.id ? <span className="spinner" /> : <Zap size={12} />} Test</button>
                        <button className="icon-btn" onClick={() => setProfiles((list) => list.filter((_, i) => i !== index))} aria-label={`Remove ${profile.name || "provider"}`} title="Remove provider"><Trash2 size={13} /></button>
                      </div>
                    </div>
                    <div className="panel-body grid grid-3">
                      <div className="field"><label>Name</label><input className="input" value={profile.name} onChange={(e) => updateProfile(index, { name: e.target.value })} /></div>
                      <div className="field"><label>Provider</label><select className="select" value={profile.provider} onChange={(e) => updateProfile(index, { provider: e.target.value })}><option value="openai">OpenAI-compatible</option><option value="anthropic">Anthropic</option><option value="ollama">Ollama</option></select></div>
                      <div className="field"><label>Model</label><input className="input mono" value={profile.model} onChange={(e) => updateProfile(index, { model: e.target.value })} placeholder="model-id" /></div>
                      <div className="field"><label>Base URL</label><input className="input mono" value={profile.baseUrl} onChange={(e) => updateProfile(index, { baseUrl: e.target.value })} placeholder="https://api.openai.com" /></div>
                      <div className="field"><label>API key</label><input className="input mono" type="password" value={profile.apiKey || ""} onChange={(e) => updateProfile(index, { apiKey: e.target.value })} placeholder={profile.hasKey ? "••••••••  (unchanged)" : "sk-…"} autoComplete="off" /></div>
                      <div className="field"><label>Roles</label><input className="input mono" value={profile.roles.join(",")} onChange={(e) => updateProfile(index, { roles: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} placeholder="critic,reporter" /></div>
                    </div>
                  </div>
                ))}
                {settingsLoaded && !profiles.length && (
                  <div className="panel"><EmptyState compact icon={<Cpu size={18} />} title="No providers configured" text="Every agent uses deterministic fallbacks until a provider is added." /></div>
                )}
                <div className="save-bar">
                  <button className="btn" onClick={() => setProfiles((list) => [...list, { id: crypto.randomUUID(), name: "New provider", provider: "openai", baseUrl: "", model: "", roles: [], priority: list.length + 1, costIn: 0, costOut: 0, enabled: true }])}><Plus size={13} /> Add provider</button>
                  <button className="btn btn-primary ml-auto" onClick={saveLLM}><Save size={14} /> Save AI settings</button>
                </div>
                <div className="callout flex" style={{ alignItems: "flex-start" }}><ShieldCheck size={14} style={{ flex: "0 0 auto", marginTop: 2 }} /><span>Without a provider, every agent uses deterministic fallbacks. Tool output is wrapped with nonce delimiters before it reaches a model.</span></div>
              </div>
            </>
          )}

          {tab === "projects" && (
            <>
              <SectionHead id="projects" action={<button className="btn btn-sm btn-primary" onClick={() => { setForm({}); setModal("project"); }}><Plus size={12} /> Import path</button>} />
              <div className="panel">
                {!projects ? <SkeletonRows rows={4} cols={4} /> : projects.length ? <div className="table-wrap"><table className="data"><thead><tr><th>Name</th><th>Files</th><th>Scans</th><th>Created</th><th></th></tr></thead><tbody>
                  {projects.map((p) => (
                    <tr key={p.id}>
                      <td><div className="cell-title"><b>{p.name}</b><span className="mono dim small">{p.kind}</span></div></td>
                      <td className="mono">{p.files}</td>
                      <td className="mono">{p.scans}</td>
                      <td className="dim nowrap"><TimeAgo value={p.created_at} /></td>
                      <td style={{ textAlign: "right" }}>
                        <Link to={`/scans/new?project=${p.id}`} className="btn btn-sm btn-ghost">Scan</Link>
                        <button className="icon-btn" aria-label={`Delete ${p.name}`} title="Delete project" onClick={async () => { await api.del(`/projects/${p.id}`); setProjects(await api.get<Project[]>("/projects")); }}><Trash2 size={13} /></button>
                      </td>
                    </tr>
                  ))}
                </tbody></table></div> : <EmptyState icon={<FolderGit2 size={20} />} title="No projects" text="Upload a ZIP from the scan wizard or import a local path." action={<button className="btn btn-primary btn-sm" onClick={() => { setForm({}); setModal("project"); }}><Plus size={12} /> Import path</button>} />}
              </div>
            </>
          )}

          {tab === "users" && (
            <>
              <SectionHead id="users" action={<button className="btn btn-sm btn-primary" onClick={() => { setForm({ role: "viewer" }); setModal("user"); }}><Plus size={12} /> Add user</button>} />
              <div className="panel">
                {!users ? <SkeletonRows rows={3} cols={4} /> : users.length ? <div className="table-wrap"><table className="data"><thead><tr><th>User</th><th>Role</th><th>Last login</th><th></th></tr></thead><tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <div className="flex" style={{ gap: 10 }}>
                          <span className="avatar">{u.name.slice(0, 2).toUpperCase()}</span>
                          <div className="cell-title"><b>{u.name}{u.id === user?.id && <span className="dim small"> · you</span>}</b><span className="mono dim small truncate">{u.email}</span></div>
                        </div>
                      </td>
                      <td style={{ width: 150 }}><select className="select" aria-label={`Role for ${u.name}`} value={u.role} disabled={u.id === user?.id} onChange={async (e) => { await api.patch(`/users/${u.id}`, { role: e.target.value }); setUsers(await api.get<User[]>("/users")); }}>{["admin", "analyst", "viewer"].map((r) => <option key={r}>{r}</option>)}</select></td>
                      <td className="dim nowrap">{u.last_login ? <TimeAgo value={u.last_login} /> : "never"}</td>
                      <td style={{ textAlign: "right" }}>{u.id !== user?.id && <button className="icon-btn" aria-label={`Delete ${u.name}`} title="Delete user" onClick={async () => { await api.del(`/users/${u.id}`); setUsers(await api.get<User[]>("/users")); }}><Trash2 size={13} /></button>}</td>
                    </tr>
                  ))}
                </tbody></table></div> : <EmptyState icon={<Users size={20} />} title="No users visible" text="Only administrators can list users." />}
              </div>
            </>
          )}

          {tab === "tokens" && (
            <>
              <SectionHead id="tokens" action={<button className="btn btn-sm btn-primary" onClick={() => { setForm({}); setNewToken(""); setModal("token"); }}><Plus size={12} /> New token</button>} />
              <div className="grid" style={{ gap: 8 }}>
                {!tokens ? <div className="panel"><SkeletonRows rows={2} cols={3} /></div> : tokens.length ? tokens.map((t) => (
                  <div key={t.id} className="list-row">
                    <KeyRound size={14} color="#2f6f3e" />
                    <b className="truncate">{t.name}</b>
                    <span className="tag">{t.scopes.join(", ")}</span>
                    <span className="ml-auto dim small nowrap">{t.last_used ? <>used <TimeAgo value={t.last_used} /></> : "never used"}</span>
                    <button className="icon-btn" aria-label={`Revoke ${t.name}`} title="Revoke token" onClick={async () => { await api.del(`/auth/tokens/${t.id}`); setTokens(await api.get<Token[]>("/auth/tokens")); }}><Trash2 size={13} /></button>
                  </div>
                )) : <div className="panel"><EmptyState icon={<KeyRound size={20} />} title="No API tokens" text="Tokens authenticate the API with a Bearer header and bypass CSRF." /></div>}
              </div>
            </>
          )}

          {tab === "audit" && (
            <>
              <SectionHead id="audit" />
              <div className="panel">
                {!audit ? <SkeletonRows rows={8} cols={5} /> : audit.length ? <div className="table-wrap"><table className="data"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>IP</th></tr></thead><tbody>
                  {audit.map((a) => <tr key={a.id}><td className="dim nowrap"><TimeAgo value={a.created_at} /></td><td>{a.email || <span className="dim">system</span>}</td><td><span className="tag">{a.action}</span></td><td className="mono small">{a.object_type ? `${a.object_type}:${a.object_id?.slice(0, 8) ?? ""}` : "—"}</td><td className="mono small dim">{a.ip || "—"}</td></tr>)}
                </tbody></table></div> : <EmptyState icon={<ScrollText size={20} />} title="Audit log is empty" text="Sign-ins, scans and setting changes are recorded here." />}
              </div>
            </>
          )}
        </div>
      </div>

      {modal === "project" && (
        <Modal title="Import project path" onClose={() => setModal(null)} footer={<><button className="btn" onClick={() => setModal(null)}>Cancel</button><button className="btn btn-primary" onClick={importPath}>Import</button></>}>
          <div className="grid" style={{ gap: 12 }}>
            <div className="field"><label htmlFor="imp-path">Absolute path</label><input id="imp-path" className="input mono" value={form.path || ""} onChange={(e) => setForm({ ...form, path: e.target.value })} placeholder="C:\src\my-service" autoFocus /><span className="hint">A directory on the server host. It is copied into KESTREL's project store.</span></div>
            <div className="field"><label htmlFor="imp-name">Name</label><input id="imp-name" className="input" value={form.name || ""} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
          </div>
        </Modal>
      )}
      {modal === "user" && (
        <Modal title="Add user" onClose={() => setModal(null)} footer={<><button className="btn" onClick={() => setModal(null)}>Cancel</button><button className="btn btn-primary" onClick={createUser}>Create</button></>}>
          <div className="grid" style={{ gap: 12 }}>
            <div className="field"><label htmlFor="u-name">Name</label><input id="u-name" className="input" value={form.name || ""} onChange={(e) => setForm({ ...form, name: e.target.value })} autoFocus /></div>
            <div className="field"><label htmlFor="u-email">Email</label><input id="u-email" className="input" type="email" value={form.email || ""} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
            <div className="field"><label htmlFor="u-pass">Password</label><input id="u-pass" className="input" type="password" value={form.password || ""} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="new-password" /><span className="hint">At least 12 characters.</span></div>
            <div className="field"><label htmlFor="u-role">Role</label><select id="u-role" className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{["viewer", "analyst", "admin"].map((r) => <option key={r}>{r}</option>)}</select></div>
          </div>
        </Modal>
      )}
      {modal === "token" && (
        <Modal title="New API token" onClose={() => setModal(null)} footer={newToken ? <button className="btn btn-primary" onClick={() => setModal(null)}>Done</button> : <><button className="btn" onClick={() => setModal(null)}>Cancel</button><button className="btn btn-primary" onClick={createToken}>Create token</button></>}>
          {newToken ? (
            <>
              <div className="callout warn">Copy this token now. It is shown once and stored only as a hash.</div>
              <div className="secret-box"><code className="code">{newToken}</code><CopyButton value={newToken} /></div>
            </>
          ) : (
            <div className="field"><label htmlFor="t-name">Token name</label><input id="t-name" className="input" value={form.name || ""} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="ci-pipeline" autoFocus /><span className="hint">Scopes: read, write.</span></div>
          )}
        </Modal>
      )}
      <p className="small dim mt-16 mono">KESTREL {general?.version ?? ""} · <Link to="/docs">method & threat model</Link></p>
    </>
  );
}
