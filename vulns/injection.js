// Intentionally vulnerable Express lab for SAST validation. DO NOT DEPLOY.
const express = require('express');
const child_process = require('child_process');
const vm = require('vm');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Hardcoded fake secrets with realistic shapes
// CWE-798: Use of Hard-coded Credentials
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const STRIPE_API_KEY = 'sk_live_51Hq8zKJ9aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ';

let db; // SQL-like connection stub
const mongo = { db: null };

// CWE-95: Eval Injection — query param flows directly into eval()
app.get('/eval', (req, res) => {
  const x = req.query.x;
  const result = eval(x);
  res.send(String(result));
});

// CWE-78: OS Command Injection — query param into shell command
app.get('/ping', (req, res) => {
  const cmd = req.query.cmd;
  child_process.exec(`ping ${cmd}`, (err, stdout) => {
    res.send(stdout || String(err));
  });
});

// CWE-78: OS Command Injection — execSync variant from request body
app.post('/run', (req, res) => {
  const target = req.body.target;
  const out = child_process.execSync('nslookup ' + target);
  res.send(out.toString());
});

// CWE-94: Code Injection via vm.runInThisContext
app.post('/vm', (req, res) => {
  const code = req.body.code;
  const out = vm.runInThisContext(code);
  res.send(String(out));
});

// CWE-94: Code Injection via vm.runInNewContext
app.get('/sandbox', (req, res) => {
  const expr = req.query.expr;
  const out = vm.runInNewContext(expr, {});
  res.send(String(out));
});

// CWE-89: SQL Injection — string concatenation of request body
app.post('/user', (req, res) => {
  const id = req.body.id;
  db.query("SELECT * FROM users WHERE id = " + id, (err, rows) => {
    res.json(rows);
  });
});

// CWE-89: SQL Injection — template literal with query param
app.get('/search', (req, res) => {
  const name = req.query.name;
  db.query(`SELECT * FROM products WHERE name = '${name}'`, (err, rows) => {
    res.json(rows);
  });
});

// CWE-22: Path Traversal — unsanitized path read from request
app.get('/file', (req, res) => {
  const p = req.query.path;
  fs.readFile(p, 'utf8', (err, data) => {
    res.send(data || String(err));
  });
});

// CWE-22: Path Traversal — join with user-controlled filename
app.get('/download', (req, res) => {
  const name = req.query.name;
  const full = path.join('/var/data/', name);
  res.send(fs.readFileSync(full));
});

// CWE-98: Unsafe require() of user-controlled module name
app.get('/load', (req, res) => {
  const mod = req.query.module;
  const loaded = require(mod);
  res.send(Object.keys(loaded));
});

// CWE-943: NoSQL Injection — $where operator from request body
app.post('/find', async (req, res) => {
  const q = req.body.q;
  const docs = await mongo.db.collection('accounts').find({ $where: q }).toArray();
  res.json(docs);
});

// CWE-943: NoSQL Injection — raw object from query into filter
app.get('/lookup', async (req, res) => {
  const user = req.query.user;
  const docs = await mongo.db.collection('users').find({ username: user }).toArray();
  res.json(docs);
});

// CWE-1321: Prototype Pollution via recursive merge of request body
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
app.post('/config', (req, res) => {
  const settings = {};
  merge(settings, req.body);
  res.json(settings);
});

// CWE-918: SSRF — fetch a URL supplied by the user
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  require('http').get(url, (r) => {
    let body = '';
    r.on('data', (c) => (body += c));
    r.on('end', () => res.send(body));
  });
});

// CWE-79: Reflected XSS — request input written into HTML response
app.get('/hello', (req, res) => {
  const name = req.query.name;
  res.send(`<html><body><h1>Hello ${name}</h1></body></html>`);
});

// CWE-601: Open Redirect — redirect to user-controlled location
app.get('/go', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});

// CWE-330: Weak token derived from predictable, attacker-influenced seed
app.get('/token', (req, res) => {
  const seed = req.query.seed;
  const token = crypto.createHash('md5').update(seed).digest('hex');
  res.send(token);
});

app.listen(3000, () => console.log('vuln lab on 3000'));

module.exports = { app, merge };
