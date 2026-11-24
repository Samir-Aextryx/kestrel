import express from "express";
import multer from "multer";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { db, now, audit } from "../db.js";
import { PROJECTS_DIR, MAX_UPLOAD_BYTES } from "../config.js";
import { extractZip, flattenProjectRoot, walkFiles, safeJoin } from "../lib/util.js";
import { requireRole } from "../auth.js";

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD_BYTES } });

router.get("/workspaces", (req, res) => {
  const rows = db
    .prepare(
      `SELECT w.*, (SELECT COUNT(*) FROM projects p WHERE p.workspace_id = w.id) AS projects
       FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id
       WHERE m.user_id = ? ORDER BY w.created_at`,
    )
    .all(req.user.id);
  res.json(rows);
});

router.post("/workspaces", requireRole("admin"), (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 120);
  if (!name) return res.status(400).json({ error: "name required" });
  const id = crypto.randomUUID();
  db.prepare("INSERT INTO workspaces(id, name, created_at) VALUES(?, ?, ?)").run(id, name, now());
  db.prepare("INSERT INTO workspace_members(workspace_id, user_id, role) VALUES(?, ?, 'admin')").run(id, req.user.id);
  res.status(201).json({ id, name });
});

router.get("/projects", (req, res) => {
  const rows = db
    .prepare(
      `SELECT p.*, (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) AS scans,
       (SELECT COUNT(*) FROM project_files f WHERE f.project_id = p.id) AS files
       FROM projects p JOIN workspace_members m ON m.workspace_id = p.workspace_id
       WHERE m.user_id = ? ORDER BY p.created_at DESC`,
    )
    .all(req.user.id);
  res.json(rows);
});

router.get("/projects/:id", (req, res) => {
  const project = db
    .prepare(
      `SELECT p.* FROM projects p JOIN workspace_members m ON m.workspace_id = p.workspace_id
       WHERE p.id = ? AND m.user_id = ?`,
    )
    .get(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: "project not found" });
  const files = db.prepare("SELECT path, size, language FROM project_files WHERE project_id = ? ORDER BY path").all(project.id);
  res.json({ ...project, files });
});

async function registerProject(req, res, { name, kind, rootPath, repoUrl = null, meta = {} }) {
  const id = crypto.randomUUID();
  const workspaceId = req.body?.workspaceId || db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1").get(req.user.id)?.workspace_id;
  if (!workspaceId) return res.status(400).json({ error: "no workspace" });
  const files = await walkFiles(rootPath);
  if (!files.length) return res.status(400).json({ error: "no readable files found" });
  db.prepare(
    "INSERT INTO projects(id, workspace_id, name, kind, path, repo_url, meta_json, created_by, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(id, workspaceId, name, kind, rootPath, repoUrl, JSON.stringify(meta), req.user.id, now());
  const insert = db.prepare("INSERT OR IGNORE INTO project_files(project_id, path, size, sha256, language) VALUES(?, ?, ?, ?, ?)");
  for (const file of files.slice(0, 8000)) {
    insert.run(id, file.rel, file.size, crypto.createHash("sha256").update(`${file.rel}:${file.size}`).digest("hex"), file.lang);
  }
  audit(req.user.id, "project.create", "project", id, req.ip, { name, files: files.length });
  res.status(201).json({ id, name, files: files.length });
}

router.post("/projects/upload", requireRole("admin", "analyst"), upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "zip file required" });
  const name = String(req.body?.name || req.file.originalname.replace(/\.zip$/i, "")).slice(0, 120);
  const id = crypto.randomUUID();
  const dir = path.join(PROJECTS_DIR, id);
  fs.mkdirSync(dir, { recursive: true });
  try {
    extractZip(req.file.buffer, dir);
    const root = flattenProjectRoot(dir);
    await registerProject(req, res, { name, kind: "code", rootPath: root, meta: { original: req.file.originalname } });
  } catch (err) {
    await fsp.rm(dir, { recursive: true, force: true });
    res.status(400).json({ error: `upload failed: ${err.message}` });
  }
});

router.post("/projects/path", requireRole("admin", "analyst"), async (req, res) => {
  const source = String(req.body?.path || "").trim();
  if (!source) return res.status(400).json({ error: "path required" });
  const resolved = path.resolve(source);
  let stat;
  try {
    stat = await fsp.stat(resolved);
  } catch {
    return res.status(400).json({ error: "path does not exist" });
  }
  if (!stat.isDirectory()) return res.status(400).json({ error: "path is not a directory" });
  const id = crypto.randomUUID();
  const dir = path.join(PROJECTS_DIR, id);
  await fsp.mkdir(dir, { recursive: true });
  try {
    await fsp.cp(resolved, dir, {
      recursive: true,
      filter: (src) => !/node_modules|\.git\/objects|[\\/](?:dist|build|\.next|target|vendor)[\\/]/.test(src),
    });
    const root = flattenProjectRoot(dir);
    await registerProject(req, res, {
      name: String(req.body?.name || path.basename(resolved)).slice(0, 120),
      kind: "code",
      rootPath: root,
      meta: { source: resolved },
    });
  } catch (err) {
    await fsp.rm(dir, { recursive: true, force: true });
    res.status(400).json({ error: `import failed: ${err.message}` });
  }
});

router.get("/projects/:id/tree", (req, res) => {
  const project = db
    .prepare(
      `SELECT p.* FROM projects p JOIN workspace_members m ON m.workspace_id = p.workspace_id
       WHERE p.id = ? AND m.user_id = ?`,
    )
    .get(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: "project not found" });
  const files = db.prepare("SELECT path, size, language FROM project_files WHERE project_id = ? ORDER BY path").all(project.id);
  res.json({ root: project.name, files });
});

router.get("/projects/:id/file", (req, res) => {
  const project = db
    .prepare(
      `SELECT p.* FROM projects p JOIN workspace_members m ON m.workspace_id = p.workspace_id
       WHERE p.id = ? AND m.user_id = ?`,
    )
    .get(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: "project not found" });
  const rel = String(req.query.path || "");
  let full;
  try {
    full = safeJoin(project.path, rel);
  } catch {
    return res.status(400).json({ error: "invalid path" });
  }
  if (!fs.existsSync(full)) return res.status(404).json({ error: "file not found" });
  const stat = fs.statSync(full);
  if (stat.size > 2 * 1024 * 1024) return res.status(413).json({ error: "file too large" });
  res.json({ path: rel, content: fs.readFileSync(full, "utf8"), size: stat.size });
});

router.delete("/projects/:id", requireRole("admin", "analyst"), async (req, res) => {
  const project = db.prepare("SELECT * FROM projects WHERE id = ?").get(req.params.id);
  if (!project) return res.status(404).json({ error: "project not found" });
  db.prepare("DELETE FROM projects WHERE id = ?").run(project.id);
  if (project.path && project.path.startsWith(PROJECTS_DIR)) {
    await fsp.rm(project.path, { recursive: true, force: true });
  }
  audit(req.user.id, "project.delete", "project", project.id, req.ip);
  res.json({ ok: true });
});

export default router;
