import orchestrator from "./orchestrator.js";
import recon from "./recon.js";
import code from "./code.js";
import secrets from "./secrets.js";
import supply from "./supply.js";
import iac from "./iac.js";
import api from "./api.js";
import fuzz from "./fuzz.js";
import zeroday from "./zeroday.js";
import plugins from "./plugins.js";
import exploit from "./exploit.js";
import foothold from "./foothold.js";
import credentials from "./credentials.js";
import verifier from "./verifier.js";
import critic from "./critic.js";
import correlator from "./correlator.js";
import reporter from "./reporter.js";
import optimizer from "./optimizer.js";

const AGENTS = {
  orchestrator,
  recon,
  code,
  secrets,
  supply,
  iac,
  api,
  fuzz,
  zeroday,
  plugins,
  exploit,
  foothold,
  credentials,
  verifier,
  critic,
  correlator,
  reporter,
  optimizer,
};

export async function runAgent(name, ctx, plan) {
  const agent = AGENTS[name];
  if (!agent) throw new Error(`unknown agent ${name}`);
  ctx.agent = name;
  return agent.run(ctx, plan);
}
