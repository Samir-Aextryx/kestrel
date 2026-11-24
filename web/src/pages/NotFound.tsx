import { Link } from "react-router-dom";
import { Compass } from "lucide-react";
import { EmptyState, useTitle } from "../components/ui";

export default function NotFound() {
  useTitle("Not found");
  return <div className="panel"><EmptyState icon={<Compass size={30} />} title="Route not found" text="The page may have moved or the scan was deleted." action={<Link to="/" className="btn btn-primary btn-sm">Command Center</Link>} /></div>;
}
