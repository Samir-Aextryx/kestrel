export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Scan = {
  id: string;
  name: string;
  target: string;
  target_type: string;
  status: string;
  progress: number;
  phase: string;
  risk_score: number;
  findings: number;
  project_name?: string;
  created_at: string;
  stats?: Stats;
};

export type Stats = {
  findings: number;
  verified: number;
  assets: number;
  fuzzExecs: number;
  coverage: number;
  crashes: number;
  severity: Record<Severity, number>;
};

export type Finding = {
  id: string;
  scanId: string;
  scanName?: string;
  title: string;
  description: string;
  severity: Severity;
  cvss: number;
  cvssVector?: string;
  cwe?: string;
  owasp?: string;
  confidence: string;
  status: string;
  engine: string;
  ruleId: string;
  file?: string;
  line?: number;
  snippet?: string;
  taint?: { source?: { line: number; code: string }; sink?: { line: number; code: string }; steps?: unknown[] };
  evidence?: Record<string, unknown>;
  remediation?: string;
  references?: string[];
  verified: boolean;
  verification?: Record<string, unknown>;
  tags: string[];
  hash: string;
  createdAt: string;
  assetValue?: string;
};

export type Event = {
  id: number;
  type: string;
  agent?: string;
  level: string;
  message: string;
  data: Record<string, unknown>;
  at: string;
};

export type ScanDetail = Scan & {
  scope: Record<string, unknown>;
  config: Record<string, unknown>;
  project?: { id: string; name: string };
  agents: { id: string; agent: string; status: string; summary?: string; started_at: string; finished_at?: string }[];
  approvals: { id: string; action: string; status: string; payload_json: string; requested_at: string }[];
  fuzz: { id: string; target: string; status: string; iterations: number; execs: number; coverage: number; crashes: number }[];
  reports: { id: string; format: string; sha256: string; created_at: string }[];
  llm: { calls: number; cost: number; tokens: number };
  paths: AttackPath[];
};

export type AttackPath = {
  id: string;
  name: string;
  score: number;
  steps: { id: string; title: string; severity: Severity; asset?: string }[];
};

export type Engine = {
  id: string;
  name: string;
  description: string;
  category: string;
  targetTypes: string[];
  dynamic: boolean;
  cost: string;
};

export type Project = { id: string; name: string; kind: string; scans: number; files: number; created_at: string };

export type Hypothesis = {
  id: string;
  scan_id: string;
  finding_id?: string | null;
  file: string;
  function: string;
  param?: string | null;
  family: string;
  oracle: string;
  status: string;
  confidence: string;
  exploitability: number;
  evidence: Record<string, unknown> & { zeroDayScore?: number; poc?: string };
  created_at: string;
  finding_title?: string | null;
  finding_severity?: Severity | null;
};

export type ScanResearch = {
  scanId: string;
  confirmed: number;
  rejected: number;
  errors: number;
  hypotheses: Hypothesis[];
  byFamily: { family: string; status: string; n: number }[];
  corpus: { entries: number; hits: number };
};

export type ConfirmedHypothesis = {
  id: string;
  family: string;
  function: string;
  file: string;
  exploitability: number;
  confidence: string;
  finding_id?: string | null;
  title?: string | null;
  severity?: Severity | null;
  cvss?: number | null;
  scan_id: string;
  scan_name: string;
};

export type ResearchOverview = {
  confirmed: ConfirmedHypothesis[];
  families: { family: string; n: number }[];
  corpus: { entries: number };
};

export type PocBundle = {
  findingId: string;
  family: string;
  title: string;
  file: string;
  function: string;
  runtime: string;
  oracle: string;
  deterministic: boolean;
  exploitability: number;
  zeroDayScore: number;
  createdAt: string;
  code: string | null;
  sha256?: string;
  [key: string]: unknown;
};
