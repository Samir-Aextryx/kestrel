import express from "express";
import fs from "node:fs";
import { exec } from "node:child_process";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import axios from "axios";
import _ from "lodash";

const app = express();
app.use(express.json());

const db = {
  query(sql, cb) {
    cb(null, [{ id: 1, sql }]);
  },
};

app.get("/users", (req, res) => {
  const name = req.query.name;
  db.query(`SELECT * FROM users WHERE name = '${name}'`, (err, rows) => {
    res.json(rows);
  });
});

app.get("/file", (req, res) => {
  const file = req.query.path;
  const content = fs.readFileSync(file, "utf8");
  res.send(content);
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const response = await axios.get(target);
  res.json(response.data);
});

app.get("/redirect", (req, res) => {
  res.redirect(req.query.next);
});

app.get("/greet", (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

app.post("/merge", (req, res) => {
  const config = _.merge({}, req.body);
  res.json(config);
});

app.post("/token", (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.cookie("session", token, { httpOnly: false });
  res.json({ token });
});

app.get("/verify", (req, res) => {
  const payload = jwt.verify(req.query.token, "secret");
  res.json(payload);
});

app.get("/digest", (req, res) => {
  const hash = crypto.createHash("md5").update(req.query.value).digest("hex");
  res.send(hash);
});

app.get("/inner", (req, res) => {
  res.send(`<div id="out"></div><script>document.getElementById("out").innerHTML = "${req.query.html}"</script>`);
});

app.listen(3000);
