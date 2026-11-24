import fs from "node:fs";
import { execSync } from "node:child_process";

export function readUserFile(name) {
  return fs.readFileSync(name, "utf8");
}

export function runCommand(cmd) {
  return execSync(cmd).toString();
}

export async function fetchUrl(url) {
  const res = await fetch(url);
  return res.text();
}

export function mergeConfig(base, patch) {
  for (const key of Object.keys(patch)) {
    if (patch[key] && typeof patch[key] === "object" && !Array.isArray(patch[key])) {
      base[key] = mergeConfig(base[key] || {}, patch[key]);
    } else {
      base[key] = patch[key];
    }
  }
  return base;
}

export function renderGreeting(name) {
  return `<h1>Hello ${name}</h1>`;
}

export function parseQuery(sql) {
  return sql.trim().toLowerCase();
}
