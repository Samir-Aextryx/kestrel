import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./AuthContext";
import Layout from "./components/Layout";
import { Logo } from "./components/ui";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Scans from "./pages/Scans";
import ScanNew from "./pages/ScanNew";
import ScanDetail from "./pages/ScanDetail";
import Findings from "./pages/Findings";
import FindingDetail from "./pages/FindingDetail";
import Graph from "./pages/Graph";
import Assets from "./pages/Assets";
import Fuzzing from "./pages/Fuzzing";
import Reports from "./pages/Reports";
import Benchmark from "./pages/Benchmark";
import Plugins from "./pages/Plugins";
import Settings from "./pages/Settings";
import Docs from "./pages/Docs";
import NotFound from "./pages/NotFound";
import Autonomy from "./pages/Autonomy";
import Research from "./pages/Research";
import Agent from "./pages/Agent";
import Operations from "./pages/Operations";

function Protected() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="boot" role="status" aria-label="Loading console">
        <div className="boot-mark">
          <span className="brand-mark"><Logo size={24} /></span>
          ESTABLISHING SESSION
        </div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  return <Layout />;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<Protected />}>
          <Route index element={<Overview />} />
          <Route path="autonomy" element={<Autonomy />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/new" element={<ScanNew />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/:id" element={<FindingDetail />} />
          <Route path="research" element={<Research />} />
          <Route path="operations" element={<Operations />} />
          <Route path="agent"element={<Agent />} />
          <Route path="graph" element={<Graph />} />
          <Route path="assets" element={<Assets />} />
          <Route path="fuzzing" element={<Fuzzing />} />
          <Route path="reports" element={<Reports />} />
          <Route path="benchmark" element={<Benchmark />} />
          <Route path="plugins" element={<Plugins />} />
          <Route path="settings" element={<Settings />} />
          <Route path="docs" element={<Docs />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
