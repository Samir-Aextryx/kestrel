import { useEffect, useState } from "react";
import { Plug, ShieldCheck } from "lucide-react";
import { api } from "../api";
import { useToast } from "../components/Toast";
import { EmptyState, Skeleton, useTitle } from "../components/ui";

type Plugin = { id: string; name: string; version: string; description: string; enabled: number; permissions: string[]; targetTypes: string[] };

export default function Plugins() {
  useTitle("Plugins");
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [loading, setLoading] = useState(true);
  const toast = useToast();
  const load = () => api.get<Plugin[]>("/plugins").then(setPlugins).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  async function toggle(plugin: Plugin) {
    await api.patch(`/plugins/${plugin.id}`, { enabled: !plugin.enabled });
    toast.push("success", `${plugin.name} ${plugin.enabled ? "disabled" : "enabled"}`);
    load();
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Extension surface</div>
          <h1>Plugins</h1>
          <p>Manifest-scoped plugins run in a worker with explicit filesystem or network permissions and a hard timeout.</p>
        </div>
      </div>
      <div className="grid grid-2">
        {loading ? [0, 1].map((i) => <div key={i} className="panel panel-body grid" style={{ gap: 10 }}><Skeleton height={14} width="40%" /><Skeleton height={12} /><Skeleton height={12} width="70%" /></div>) : plugins.length ? plugins.map((plugin) => (
          <div key={plugin.id} className="panel">
            <div className="panel-head"><Plug size={15} color="#2f6f3e" /><h2 className="truncate">{plugin.name}</h2><span className="tag">v{plugin.version}</span><div className="right"><button className={`btn btn-sm ${plugin.enabled ? "btn-danger" : "btn-primary"}`} onClick={() => toggle(plugin)}>{plugin.enabled ? "Disable" : "Enable"}</button></div></div>
            <div className="panel-body">
              <p className="small muted" style={{ marginTop: 0 }}>{plugin.description}</p>
              <div className="flex flex-wrap small mt-8">{plugin.permissions.map((p) => <span key={p} className="tag"><ShieldCheck size={10} /> {p}</span>)}{plugin.targetTypes.map((t) => <span key={t} className="tag">{t}</span>)}</div>
            </div>
          </div>
        )) : <div className="panel span-2"><EmptyState icon={<Plug size={20} />} title="No plugins installed" text="Drop a plugin folder into /plugins with a plugin.json manifest." /></div>}
      </div>
    </>
  );
}
