import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Boxes } from "lucide-react";
import { api } from "../api";
import { EmptyState, SkeletonRows, TimeAgo, useTitle } from "../components/ui";

type Asset = { id: string; kind: string; value: string; first_seen: string; scan_id: string; scan_name: string };

export default function Assets() {
  useTitle("Assets");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [kind, setKind] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.get<Asset[]>("/assets").then(setAssets).catch(() => {}).finally(() => setLoading(false));
  }, []);
  const kinds = [...new Set(assets.map((a) => a.kind))];
  const filtered = kind ? assets.filter((a) => a.kind === kind) : assets;
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Inventory</div>
          <h1>Assets</h1>
          <p>Discovered domains, URLs, endpoints, images and artifacts, linked to their scan.</p>
        </div>
        <div className="actions">
          <select className="select" aria-label="Asset kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">All kinds</option>
            {kinds.map((k) => <option key={k}>{k}</option>)}
          </select>
        </div>
      </div>
      <div className="panel">
        {loading ? <SkeletonRows rows={6} cols={4} /> : filtered.length ? (
          <div className="table-wrap"><table className="data">
            <thead><tr><th>Kind</th><th>Value</th><th>Scan</th><th>First seen</th></tr></thead>
            <tbody>{filtered.map((asset) => (
              <tr key={asset.id}><td><span className="tag">{asset.kind}</span></td><td className="mono" style={{ wordBreak: "break-all" }}>{asset.value}</td><td><Link to={`/scans/${asset.scan_id}`}>{asset.scan_name}</Link></td><td className="dim nowrap"><TimeAgo value={asset.first_seen} /></td></tr>
            ))}</tbody>
          </table></div>
        ) : <EmptyState icon={<Boxes size={28} />} title="No assets" text="Recon and engines add assets during a scan." action={<Link to="/scans/new" className="btn btn-primary btn-sm">New scan</Link>} />}
      </div>
    </>
  );
}
