import express from "express";
import helmet from "helmet";
import crypto from "node:crypto";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "100kb" }));

const users = new Map([["1", { id: "1", name: "Ada" }]]);

app.get("/users/:id", (req, res) => {
  const user = users.get(req.params.id);
  if (!user) return res.status(404).json({ error: "not found" });
  res.json(user);
});

app.post("/users", (req, res) => {
  const id = crypto.randomUUID();
  users.set(id, { id, name: String(req.body.name || "").slice(0, 80) });
  res.status(201).json({ id });
});

app.listen(3000);
