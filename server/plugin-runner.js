import { parentPort, workerData } from "node:worker_threads";

const pending = new Map();
let seq = 0;

function rpc(method, args) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    parentPort.postMessage({ type: "rpc", id, method, args });
  });
}

parentPort.on("message", (msg) => {
  if (msg.type !== "rpc-result") return;
  const entry = pending.get(msg.id);
  if (!entry) return;
  pending.delete(msg.id);
  if (msg.error) entry.reject(new Error(msg.error));
  else entry.resolve(msg.result);
});

const mod = await import(workerData.entry);
const plugin = mod.default || mod;
const ctx = {
  config: workerData.config,
  files: workerData.files,
  targetType: workerData.targetType,
  target: workerData.target,
  permissions: workerData.permissions,
  readFile: (rel) => rpc("readFile", { rel }),
  http: (url, options) => rpc("http", { url, options }),
  addAsset: (kind, value, meta) => rpc("addAsset", { kind, value, meta }),
  emit: (level, message) => parentPort.postMessage({ type: "emit", level, message }),
  add: (finding) => parentPort.postMessage({ type: "finding", finding }),
};

try {
  await plugin.run(ctx);
  parentPort.postMessage({ type: "done" });
} catch (err) {
  parentPort.postMessage({ type: "emit", level: "error", message: err.message });
  process.exitCode = 1;
}
