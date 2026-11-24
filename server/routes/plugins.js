import express from "express";
import { db } from "../db.js";
import { listPlugins } from "../plugins.js";
import { requireRole } from "../auth.js";

const router = express.Router();

router.get("/plugins", (req, res) => {
  res.json(listPlugins());
});

router.patch("/plugins/:id", requireRole("admin"), (req, res) => {
  const plugin = db.prepare("SELECT * FROM plugins WHERE id = ?").get(req.params.id);
  if (!plugin) return res.status(404).json({ error: "plugin not found" });
  db.prepare("UPDATE plugins SET enabled = ? WHERE id = ?").run(req.body?.enabled ? 1 : 0, plugin.id);
  res.json({ ok: true });
});

export default router;
