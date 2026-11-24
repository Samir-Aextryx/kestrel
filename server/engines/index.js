import secrets from "./secrets.js";
import sastJs from "./sast-js.js";
import sastPython from "./sast-python.js";
import sastGo from "./sast-go.js";
import iac from "./iac.js";
import dependencies from "./dependencies.js";
import api from "./api.js";
import web from "./web.js";
import tls from "./tls.js";
import container from "./container.js";
import binary from "./binary.js";
import sbom from "./sbom.js";
import licenses from "./licenses.js";
import graphql from "./graphql.js";
import zeroday from "./zeroday.js";
import fuzzJs from "./fuzz-js.js";
import fuzzPython from "./fuzz-python.js";
import patchDiff from "./patch-diff.js";
import interproc from "./interproc.js";
import invariant from "./invariant.js";
import network from "./network.js";
import auth from "./auth.js";
import exploit from "./exploit.js";
import foothold from "./foothold.js";
import credentials from "./credentials.js";

export const ENGINES = [
  secrets,
  sastJs,
  sastPython,
  sastGo,
  iac,
  dependencies,
  api,
  web,
  tls,
  container,
  binary,
  sbom,
  licenses,
  graphql,
  zeroday,
  fuzzJs,
  fuzzPython,
  patchDiff,
  interproc,
  invariant,
  network,
  auth,
  exploit,
  foothold,
  credentials,
];

export const ENGINE_MAP = new Map(ENGINES.map((e) => [e.id, e]));

export function enginesFor(targetType, config = {}) {
  const enabled = new Set(config.engines || []);
  return ENGINES.filter((engine) => {
    if (enabled.size && !enabled.has(engine.id)) return false;
    return engine.targetTypes.includes(targetType) || engine.targetTypes.includes("*");
  });
}

export function publicEngines() {
  return ENGINES.map((e) => ({
    id: e.id,
    name: e.name,
    description: e.description,
    category: e.category,
    targetTypes: e.targetTypes,
    dynamic: Boolean(e.dynamic),
    cost: e.cost || "low",
  }));
}
