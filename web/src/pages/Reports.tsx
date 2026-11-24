import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Download, FileText } from "lucide-react";
import { api } from "../api";
import { EmptyState, SkeletonRows, TimeAgo, useTitle } from "../components/ui";

type Report = { id: string; scan_id: string; scan_name: string; format: string; sha256: string; hmac: string; created_at: string };

export default function Reports() {
  useTitle("Reports");
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.get<Report[]>("/reports").then(setReports).catch(() => {}).finally(() => setLoading(false));
  }, []);
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Deliverables</div>
          <h1>Reports</h1>
          <p>Every export is SHA-256 hashed and HMAC-signed. SARIF feeds CI; HTML is stakeholder-ready.</p>
        </div>
      </div>
      <div className="panel">
        {loading ? <SkeletonRows rows={5} cols={4} /> : reports.length ? (
          <div className="table-wrap"><table className="data">
            <thead><tr><th>Format</th><th>Scan</th><th>SHA-256</th><th>Created</th><th></th></tr></thead>
            <tbody>{reports.map((report) => (
              <tr key={report.id}>
                <td><span className="tag">{report.format}</span></td>
                <td><Link to={`/scans/${report.scan_id}`}>{report.scan_name}</Link></td>
                <td className="mono small dim">{report.sha256.slice(0, 24)}…</td>
                <td className="dim nowrap"><TimeAgo value={report.created_at} /></td>
                <td><a className="btn btn-sm" href={`/api/reports/${report.id}/download`}><Download size={12} /> Download</a></td>
              </tr>
            ))}</tbody>
          </table></div>
        ) : <EmptyState icon={<FileText size={28} />} title="No reports" text="The reporter agent writes one at the end of every scan. You can also export from a scan page." />}
      </div>
    </>
  );
}
