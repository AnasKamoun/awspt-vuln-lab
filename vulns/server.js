// Intentionally vulnerable Express app for SAST scanner validation. DO NOT DEPLOY.
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const { exec, execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const serialize = require("node-serialize");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CWE-942: overly permissive CORS allows any origin to read responses
app.use(cors({ origin: "*", credentials: true }));

// Hardcoded FAKE secrets with realistic shapes
const JWT_SECRET = "s3cr3t_jwt_signing_key_do_not_use_1234567890";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEF0123";

const db = mysql.createConnection({ host: "localhost", user: "root", password: "root", database: "app" });

// CWE-79: Reflected XSS — request query reflected unescaped into HTML
app.get("/xss", (req, res) => {
  res.send(`<h1>Results for ${req.query.q}</h1>`);
});

// CWE-601: Open redirect — user-controlled URL used as redirect target
app.get("/go", (req, res) => {
  res.redirect(req.query.url);
});

// CWE-918: SSRF — server fetches an attacker-supplied URL
app.get("/fetch", async (req, res) => {
  const r = await axios.get(req.query.url);
  res.send(r.data);
});

// CWE-78: OS command injection via exec with concatenated input
app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, stdout) => res.send(stdout));
});

// CWE-78: OS command injection via execSync template string
app.get("/dns", (req, res) => {
  const out = execSync(`nslookup ${req.query.domain}`);
  res.send(out.toString());
});

// CWE-89: SQL injection — query string concatenated into SQL
app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (e, rows) => res.json(rows));
});

// CWE-89: SQL injection via template literal in body
app.post("/login", (req, res) => {
  const q = `SELECT * FROM users WHERE name='${req.body.username}' AND pass='${req.body.password}'`;
  db.query(q, (e, rows) => res.json(rows));
});

// CWE-22: Path traversal — sendFile with user-controlled path
app.get("/download", (req, res) => {
  res.sendFile(req.query.f);
});

// CWE-22: Path traversal — file read with concatenated path
app.get("/view", (req, res) => {
  const data = fs.readFileSync("/var/www/files/" + req.query.name);
  res.send(data);
});

// CWE-73: External control of file path — write to attacker-named file
app.post("/save", (req, res) => {
  fs.writeFileSync(path.join("/tmp/uploads", req.body.filename), req.body.content);
  res.send("saved");
});

// CWE-95: Code injection via eval of request input
app.get("/calc", (req, res) => {
  const result = eval(req.query.expr);
  res.send(String(result));
});

// CWE-94: Code injection via Function constructor
app.post("/run", (req, res) => {
  const f = new Function("ctx", req.body.code);
  res.send(String(f({})));
});

// CWE-502: Insecure deserialization of untrusted input
app.post("/deserialize", (req, res) => {
  const obj = serialize.unserialize(req.body.data);
  res.json(obj);
});

// CWE-347: JWT verified with algorithm 'none' — signature not enforced
app.get("/auth", (req, res) => {
  const token = req.headers["authorization"];
  const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["none", "HS256"] });
  res.json(decoded);
});

// CWE-798: hardcoded credentials minted into a token
app.get("/token", (req, res) => {
  const t = jwt.sign({ user: req.query.user, key: AWS_SECRET_ACCESS_KEY }, JWT_SECRET, { algorithm: "none" });
  res.send(t);
});

// CWE-1336 / SSTI-like: template string built from request and rendered
app.get("/greet", (req, res) => {
  const tmpl = "Hello " + req.query.name + ", welcome!";
  res.send(eval("`" + tmpl + "`"));
});

// CWE-916: weak hash (MD5) over user-supplied password
app.post("/hash", (req, res) => {
  const h = crypto.createHash("md5").update(req.body.password).digest("hex");
  res.send(h);
});

// CWE-1004: sensitive cookie without HttpOnly, value from request
app.get("/setcookie", (req, res) => {
  res.cookie("session", req.query.sid, { httpOnly: false, secure: false });
  res.send("ok");
});

// CWE-78: command injection from CLI arg / env (taint via process)
function startupTask() {
  const target = process.argv[2] || process.env.SCAN_TARGET;
  exec("curl -s " + target, (e, o) => console.log(o));
}
startupTask();

// CWE-89: SQL injection sourced from environment variable
function adminLookup() {
  const role = process.env.ADMIN_ROLE;
  db.query("SELECT * FROM perms WHERE role = '" + role + "'", () => {});
}
adminLookup();

console.log("Listening with key", STRIPE_KEY, AWS_ACCESS_KEY_ID);
app.listen(3000);
