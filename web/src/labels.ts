export const AGENT_LABELS: Record<string, string> = {
  orchestrator: "Orchestrator",
  recon: "Recon",
  code: "Code Analyst",
  secrets: "Secret Hunter",
  supply: "Supply Chain",
  iac: "Cloud & IaC",
  api: "API Analyst",
  fuzz: "Fuzz Strategist",
  zeroday: "Zero-Day Lab",
  plugins: "Plugin Runtime",
  verifier: "Verifier",
  critic: "Critic",
  correlator: "Correlator",
  reporter: "Reporter",
  optimizer: "Optimizer",
};

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
