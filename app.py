"""
awspt-lab — Intentionally vulnerable web app for validating awspt modules.

DO NOT DEPLOY THIS APP. It is designed to be exploited.

Each endpoint contains one (or more) well-defined vulnerability that maps
to a specific awspt module. The expected_findings.yaml file in the parent
directory documents the mapping.

All endpoints accept simple GET/POST so the awspt scanner can discover
them without complex auth. A handful of endpoints simulate auth via a
fake static cookie.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from fastapi import (Cookie, FastAPI, Form, Header, HTTPException, Query,
                     Request, Response, UploadFile, WebSocket,
                     WebSocketDisconnect)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse


app = FastAPI(title="awspt-lab", description="Vulnerable target for awspt validation")


# Persist the lab DB and uploads in a writable temp dir on both Docker (/tmp)
# and bare Windows hosts. Path is cached for the lifetime of the process.
LAB_TMP = Path(os.environ.get("AWSPT_LAB_TMP") or tempfile.gettempdir()) / "awspt-lab"
LAB_TMP.mkdir(parents=True, exist_ok=True)
DB_PATH = str(LAB_TMP / "awspt-lab.db")

# When AWSPT_LAB_CLEAN=1 the same codebase exposes a NON-vulnerable variant.
# Used by the validator as the target for false-positive guards — modules that
# probe `s.target` directly (cors, open_redirect, host_header, cookies…) need
# a "clean" target to be testable for FP behaviour.
CLEAN_MODE = os.environ.get("AWSPT_LAB_CLEAN", "0") == "1"


def _init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        );
        INSERT INTO users (id, username, password, email, role) VALUES
            (1, 'admin',   'admin123',  'admin@lab.local',  'admin'),
            (2, 'alice',   'alice2024', 'alice@lab.local',  'user'),
            (3, 'bob',     'hunter2',   'bob@lab.local',    'user');

        DROP TABLE IF EXISTS comments;
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT, body TEXT
        );
        """
    )
    con.commit()
    con.close()


_init_db()


# ---------------------------------------------------------------------------
# Landing & robots / sitemap — give the crawler enough endpoints to discover.
# ---------------------------------------------------------------------------

LANDING_HTML = """
<!doctype html>
<html><head><title>awspt-lab</title></head><body>
<h1>awspt-lab — vulnerable target</h1>
<!-- TODO: remove API key before release: AKIAIOSFODNN7EXAMPLE -->
<!-- DB_PASSWORD=lab-pw-2024 STRIPE_SECRET=sk_test_4eC39HqLyjWDarjtT1zdp7dc -->
<a href="https://evil.example.com" target="_blank">External link without rel</a>

<h2>Forms (for crawler to discover)</h2>
<form method="GET" action="/sqli">
  <input name="id" value="1">
  <button type="submit">SQLi GET</button>
</form>
<form method="POST" action="/csrf-action">
  <input name="action" value="delete-account">
  <button type="submit">CSRF POST</button>
</form>
<form method="POST" action="/login">
  <input name="username" value="admin">
  <input name="password" value="admin">
  <button>Login</button>
</form>
<form method="POST" action="/api/users">
  <input name="username" value="x">
  <input name="role" value="admin">
  <button>Create user</button>
</form>
<form method="POST" enctype="multipart/form-data" action="/upload">
  <input type="file" name="f">
  <button>Upload</button>
</form>

<h2>Endpoints (for crawler to walk)</h2>
<ul>
  <li><a href="/sqli?id=1">/sqli</a> — error SQLi</li>
  <li><a href="/sqli_blind?id=1">/sqli_blind</a> — blind/time SQLi</li>
  <li><a href="/xss?q=hello">/xss</a> — reflected XSS</li>
  <li><a href="/xss_dom">/xss_dom</a> — DOM XSS</li>
  <li><a href="/search?q=test">/search</a> — HTML injection</li>
  <li><a href="/redirect?next=/home">/redirect</a> — open redirect</li>
  <li><a href="/ssrf?url=http://example.com">/ssrf</a> — SSRF</li>
  <li><a href="/lfi?file=hello.txt">/lfi</a> — LFI</li>
  <li><a href="/rfi?url=http://example.com">/rfi</a> — RFI</li>
  <li><a href="/ssti?name=world">/ssti</a> — SSTI (Jinja-like)</li>
  <li><a href="/crlf?next=/home">/crlf</a> — CRLF</li>
  <li><a href="/cmd?host=127.0.0.1">/cmd</a> — Command injection</li>
  <li><a href="/jwt">/jwt</a> — JWT alg=none</li>
  <li><a href="/api/users/2">/api/users/{id}</a> — IDOR</li>
  <li><a href="/api/graphql">/api/graphql</a> — GraphQL introspection</li>
  <li><a href="/admin">/admin</a> — host-header dependent</li>
  <li><a href="/admin/login">/admin/login</a> — admin login (default creds)</li>
  <li><a href="https://analytics.example.com/track?api_key=awspt-lab-secret-key-1234567890abcdef">analytics</a> — token-in-URL Referer leak (R17)</li>
  <li><a href="/upload">/upload</a> — unrestricted upload</li>
  <li><a href="/.env">/.env</a> — exposed secrets</li>
  <li><a href="/backup.zip">/backup.zip</a> — backup file</li>
  <li><a href="/backup.bak">/backup.bak</a> — backup file (.bak)</li>
  <li><a href="/.git/config">/.git/config</a> — VCS leak</li>
  <li><a href="/.git/HEAD">/.git/HEAD</a> — VCS ref (source_disclosure)</li>
  <li><a href="/source.php">/source.php</a> — raw source served as text (source_disclosure)</li>
  <li><a href="/info">/info</a> — info disclosure</li>
  <li><a href="/csrf-action">/csrf-action</a> — CSRF</li>
  <li><a href="/cors-api">/cors-api</a> — CORS misconfig</li>
  <li><a href="/login">/login</a> — login (default creds + account enum)</li>
  <li><a href="/password-reset?token=token-1">/password-reset</a> — weak token</li>
  <li><a href="/headers">/headers</a> — missing security headers</li>
  <li><a href="/files/">/files/</a> — directory listing</li>
  <li><a href="/extlink?url=https://evil.example.com">/extlink</a> — tabnabbing</li>
  <li><a href="/xxe">/xxe</a> — XXE (POST)</li>
  <li><a href="/profile?name=Guest">/profile</a> — Client-side template injection (AngularJS)</li>
  <li><a href="/cache-page">/cache-page</a> — cache poisoning via unkeyed headers</li>
  <li><a href="/widget.js">/widget.js</a> — postMessage listener without origin check</li>
  <li><code>ws://lab/ws</code> — WebSocket with no Origin check (use websocket_csrf)</li>
  <li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a> — JWKS (jwt_chain target)</li>
</ul>
<script>
  // Hint for the websocket_csrf crawler: explicit `new WebSocket(...)`.
  const lab_ws = new WebSocket('ws://' + location.host + '/ws');
</script>
</body></html>
"""


# Cookies set without Secure / HttpOnly / SameSite — so /cookies module picks
# up the bad attrs whether it probes root or /login.
_INSECURE_COOKIES = {"sessionid": "lab-session-abc123", "tracking": "yes"}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, response: Response,
                next: str | None = Query(default=None),
                url: str | None = Query(default=None),
                redirect: str | None = Query(default=None),
                origin: str | None = Header(default=None),
                host: str | None = Header(default=None)):
    """The lab root is *deliberately* vulnerable in default mode so modules
    that only probe `s.target` (cors, host_header, cookies, open_redirect…)
    can fire. When `AWSPT_LAB_CLEAN=1`, the same handler returns a hardened
    response with security headers, sanitised redirects and no Origin
    reflection — used as the false-positive-guard target by the validator."""

    if CLEAN_MODE:
        # Hardened response: no reflection, no redirect, security headers,
        # no cookies, no Host reflection. Modules probing `s.target` should
        # find nothing here.
        body = "<html><body><h1>awspt-lab (clean mode)</h1>" \
               "<p>This instance is hardened for FP-guard testing.</p>" \
               "</body></html>"
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        return HTMLResponse(body, headers=headers)

    # Open redirect via `?next=`, `?url=` or `?redirect=` — covers REDIRECT_PARAMS.
    redir_to = next or url or redirect
    if redir_to:
        resp = Response(status_code=302)
        resp.headers["Location"] = redir_to  # unsanitised
        return resp

    # Reflect Origin (with credentials) — CORS misconfig.
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"

    # Insecure cookies on every response from /.
    for k, v in _INSECURE_COOKIES.items():
        response.set_cookie(k, v)

    # Drop any security headers FastAPI may add by default. The compound
    # Server banner exposes BOTH PHP/7.4.3 (for PHP-CGI 4577 lab) AND
    # nginx/1.25.3 (vulnerable to CVE-2024-27316 CONTINUATION flood).
    response.headers["Server"] = "awspt-lab/0.1 nginx/1.25.3 (PHP/7.4.3)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    # Trusted-Types 'none' = neutralised TT enforcement (CVE-class).
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; require-trusted-types-for 'script'; "
        "trusted-types 'none'"
    )

    # Reflect Host header — host header injection probe surface.
    host_value = host or "lab"
    body = LANDING_HTML.replace(
        "<h1>awspt-lab — vulnerable target</h1>",
        f"<h1>awspt-lab — vulnerable target</h1>"
        f"<p>Welcome from host <code>{host_value}</code></p>"
        f"<a href='http://{host_value}/admin'>admin panel</a>"
    )
    return HTMLResponse(body, headers=dict(response.headers))


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /api/\nDisallow: /.git/\nDisallow: /backup.zip\n"


@app.get("/sitemap.xml")
async def sitemap():
    urls = [
        "/", "/sqli", "/xss", "/login", "/admin", "/upload",
        "/api/users/1", "/api/graphql", "/redirect", "/ssrf", "/lfi",
    ]
    body = "<?xml version='1.0'?><urlset>"
    for u in urls:
        body += f"<url><loc>http://lab{u}</loc></url>"
    body += "</urlset>"
    return Response(content=body, media_type="application/xml")


# ---------------------------------------------------------------------------
# SQL Injection — error-based + boolean/time blind.   Module: sqli, sqli_blind
# ---------------------------------------------------------------------------

@app.get("/sqli")
async def sqli(id: str = Query(default="1")):
    """Error-based SQLi target. Echoes a MySQL-flavoured error message so the
    sqli module's signature regex can latch onto something realistic. The
    underlying DB is SQLite, but real-world apps frequently echo the
    upstream driver's error string when they sanitise badly — that's what
    we emulate here."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute(f"SELECT id, username, email FROM users WHERE id = {id}")
        row = cur.fetchone()
        return {"row": row}
    except sqlite3.Error as e:
        # Canonical MySQL error string — matches `you have an error in your
        # sql syntax` in backend/data/payloads.py::SQLI_ERRORS.
        msg = (
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax "
            f"to use near '{id}' at line 1"
        )
        return PlainTextResponse(
            f"<html><body><h1>Database error</h1><pre>{msg}\n"
            f"Warning: mysql_fetch_array() expects parameter 1 to be resource, "
            f"boolean given in /var/www/app.php on line 42\n"
            f"(underlying: {e})</pre></body></html>",
            status_code=500,
            media_type="text/html",
        )
    finally:
        con.close()


@app.get("/sqli_blind")
async def sqli_blind(id: str = Query(default="1")):
    """Boolean-blind SQLi: page differs based on injection, no error leak."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute(f"SELECT username FROM users WHERE id = {id} LIMIT 1")
        row = cur.fetchone()
        # Time-blind simulation: if payload contains sleep/benchmark, delay.
        low = id.lower()
        if "sleep" in low or "benchmark" in low or "pg_sleep" in low or "waitfor" in low:
            time.sleep(5)
        if row:
            return HTMLResponse(f"<p>User exists: {row[0]}</p>")
        return HTMLResponse("<p>No such user.</p>")
    except sqlite3.Error:
        return HTMLResponse("<p>No such user.</p>")
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Reflected / DOM / Stored XSS.   Module: xss, dom_xss, html_injection
# ---------------------------------------------------------------------------

@app.get("/xss", response_class=HTMLResponse)
async def xss(q: str = Query(default="hello")):
    # No escaping — reflected XSS.
    return HTMLResponse(f"<html><body><h1>Hello {q}</h1></body></html>")


@app.get("/xss_dom", response_class=HTMLResponse)
async def xss_dom():
    # DOM XSS via hash/fragment + document.write.
    return HTMLResponse(
        "<html><body><h1>DOM XSS Lab</h1><script>"
        "document.write('Welcome ' + decodeURIComponent(location.hash.slice(1)));"
        "</script></body></html>"
    )


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = Query(default="")):
    # Reflected HTML injection (no JS) — module: html_injection.
    return HTMLResponse(f"<html><body><div>Results for: {q}</div></body></html>")


# ---------------------------------------------------------------------------
# Open redirect + tabnabbing + CRLF.   Module: open_redirect, tabnabbing, crlf
# ---------------------------------------------------------------------------

@app.get("/redirect")
async def open_redirect(next: str = Query(default="/")):
    return RedirectResponse(url=next, status_code=302)


@app.get("/extlink", response_class=HTMLResponse)
async def tabnabbing(url: str = Query(default="https://example.com")):
    # target=_blank without rel=noopener — tabnabbing.
    return HTMLResponse(f"<a href='{url}' target='_blank'>Click</a>")


@app.get("/crlf")
async def crlf(next: str = Query(default="/")):
    """Header-injection lab. Reflects the `next` parameter into the Location
    header AND, if the payload contains CRLF (raw or %0d%0a / Unicode look-
    alikes), parses out injected `Header: value` lines and emits them as
    response headers."""
    decoded = (next
               .replace("%0d%0a", "\r\n")
               .replace("%0D%0A", "\r\n")
               .replace("嘊嘍", "\r\n"))  # CJK CRLF look-alikes
    parts = decoded.split("\r\n")
    loc = parts[0]
    resp = Response(status_code=302)
    resp.headers["Location"] = loc
    for line in parts[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if k and v:
                # h11 rejects raw CRLF inside header values, so we emit them
                # cleanly — the awspt module just checks for header presence.
                resp.headers[k] = v
    return resp


# ---------------------------------------------------------------------------
# SSRF / RFI / LFI / path traversal.   Modules: ssrf, rfi, lfi, path_traversal
# ---------------------------------------------------------------------------

@app.get("/ssrf")
async def ssrf(url: str = Query(default="http://example.com")):
    try:
        with urllib.request.urlopen(url, timeout=4) as f:
            return Response(content=f.read(1024), media_type="text/plain")
    except Exception as e:
        return PlainTextResponse(f"fetch failed: {e}", status_code=500)


@app.get("/rfi", response_class=HTMLResponse)
async def rfi(url: str = Query(default="")):
    if not url:
        return HTMLResponse("<p>provide ?url=</p>")
    try:
        with urllib.request.urlopen(url, timeout=4) as f:
            body = f.read(2048).decode("utf-8", errors="replace")
        # Include remote content verbatim — classic RFI behavior.
        return HTMLResponse(f"<html><body>{body}</body></html>")
    except Exception as e:
        return HTMLResponse(f"<p>include failed: {e}</p>")


_LAB_FILES = {
    "hello.txt": "Hello from awspt-lab\n",
    "readme.md": "# README\nNothing sensitive here.\n",
}


@app.get("/lfi", response_class=PlainTextResponse)
async def lfi(file: str = Query(default="hello.txt")):
    # Vulnerable file read — accepts ../ traversal.
    target = LAB_TMP / file
    try:
        return target.read_text()
    except (FileNotFoundError, OSError, NotADirectoryError):
        if file in _LAB_FILES:
            return _LAB_FILES[file]
        # Try common LFI targets so the scanner sees real content.
        if "passwd" in file or "/etc/" in file:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
        if "win.ini" in file.lower() or "windows" in file.lower():
            return "[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\n"
        raise HTTPException(404, "file not found")
    except Exception as e:
        raise HTTPException(500, f"read error: {e}")


# ---------------------------------------------------------------------------
# SSTI — minimal Jinja-style expression evaluator (UNSAFE).   Module: ssti
# ---------------------------------------------------------------------------

@app.get("/ssti", response_class=HTMLResponse)
async def ssti(name: str = Query(default="world")):
    """SSTI lab — evaluates `{{ expr }}`, `${expr}`, `<%= expr %>` and `#set(...)`
    blocks present in the user-supplied name and renders ONLY the evaluated
    output. The literal payload is NOT echoed, so the awspt probe's
    "payload not in r.text" assertion holds."""

    def _eval_py(expr: str) -> str:
        try:
            return str(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307
        except Exception:
            return ""

    rendered = name

    # Jinja / Twig / Tornado / Pebble / Handlebars-style {{ ... }}
    rendered = re.sub(r"\{\{\s*(.+?)\s*\}\}",
                      lambda m: _eval_py(m.group(1)), rendered)
    # Mako / Freemarker / Razor-style ${ ... }
    rendered = re.sub(r"\$\{\s*(.+?)\s*\}",
                      lambda m: _eval_py(m.group(1)), rendered)
    # ERB / EJS-style <%= ... %>
    rendered = re.sub(r"<%=\s*(.+?)\s*%>",
                      lambda m: _eval_py(m.group(1)), rendered)
    # Velocity-style #set($x=...) → returns the value
    rendered = re.sub(r"#set\(\$\w+=([^)]+)\)\s*\$\w+",
                      lambda m: _eval_py(m.group(1)), rendered)
    # Razor @( ... )
    rendered = re.sub(r"@\(\s*([^)]+)\s*\)",
                      lambda m: _eval_py(m.group(1)), rendered)
    # Smarty {math equation='...'}
    rendered = re.sub(r"\{math\s+equation\s*=\s*['\"]([^'\"]+)['\"]\s*\}",
                      lambda m: _eval_py(m.group(1)), rendered)

    return HTMLResponse(f"<html><body><h1>Hello</h1><p>{rendered}</p></body></html>")


# ---------------------------------------------------------------------------
# XXE.   Module: xxe
# ---------------------------------------------------------------------------

@app.post("/xxe")
async def xxe(request: Request):
    body = await request.body()
    try:
        # Use ElementTree with explicit DTD loading enabled is hard in stdlib;
        # we manually parse entities to simulate XXE for the lab.
        text = body.decode("utf-8", errors="replace")
        # Match <!ENTITY foo SYSTEM "...">  &foo;
        entities = dict(re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"', text))
        result = re.sub(r"&(\w+);", lambda m: _resolve_entity(entities.get(m.group(1), "")), text)
        return PlainTextResponse(result)
    except Exception as e:
        return PlainTextResponse(f"xml error: {e}", status_code=400)


def _resolve_entity(uri: str) -> str:
    if uri.startswith("file://"):
        path = uri[7:]
        try:
            return Path(path).read_text(errors="replace")[:2048]
        except Exception:
            # Provide canned content so the lab works on any host.
            if "passwd" in path:
                return "root:x:0:0:root:/root:/bin/bash"
            if "win.ini" in path.lower():
                return "[fonts]\n[extensions]\n"
            return ""
    if uri.startswith("http://") or uri.startswith("https://"):
        try:
            with urllib.request.urlopen(uri, timeout=3) as f:
                return f.read(1024).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


# ---------------------------------------------------------------------------
# Command injection.   Module: cmdi, cmdi_blind
# ---------------------------------------------------------------------------

@app.get("/cmd")
async def cmd(host: str = Query(default="127.0.0.1")):
    # Vulnerable: shell=True with user input concatenated.
    try:
        out = subprocess.check_output(f"echo pinging {host}", shell=True, timeout=8)
        return PlainTextResponse(out.decode())
    except subprocess.CalledProcessError as e:
        return PlainTextResponse(str(e), status_code=500)


# ---------------------------------------------------------------------------
# JWT alg=none.   Module: jwt_attacks
# ---------------------------------------------------------------------------

JWT_SECRET = "lab-secret"


def _jwt_encode(payload: dict, alg: str = "HS256") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    if alg == "none":
        return f"{header}.{body}."
    sig = hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def _b64decode(s: str) -> bytes:
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def _jwt_decode_unsafe(token: str) -> dict | None:
    """Vulnerable: trusts alg field, accepts alg=none."""
    try:
        header_b64, body_b64, sig_b64 = token.split(".")
        header = json.loads(_b64decode(header_b64))
        body = json.loads(_b64decode(body_b64))
        if header.get("alg") == "none":
            return body  # VULN: trust unsigned token
        if header.get("alg") == "HS256":
            expected = hmac.new(JWT_SECRET.encode(),
                                f"{header_b64}.{body_b64}".encode(),
                                hashlib.sha256).digest()
            if hmac.compare_digest(_b64decode(sig_b64), expected):
                return body
        return None
    except Exception:
        return None


@app.get("/jwt")
async def jwt_issue():
    token = _jwt_encode({"sub": "alice", "role": "user", "iat": int(time.time())})
    return {"token": token, "decode_at": "/jwt/whoami"}


@app.get("/jwt/whoami")
async def jwt_whoami(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        return {"role": "anonymous"}
    token = authorization.split(" ", 1)[1]
    claims = _jwt_decode_unsafe(token)
    if not claims:
        return JSONResponse({"role": "invalid"}, status_code=401)
    return claims


# ---------------------------------------------------------------------------
# Headers / cookies / security misconfiguration.   Modules: headers, cookies
# ---------------------------------------------------------------------------

@app.get("/headers", response_class=PlainTextResponse)
async def headers_demo(response: Response):
    # Deliberately omit Strict-Transport-Security, X-Content-Type-Options,
    # X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy.
    response.headers["Server"] = "awspt-lab/0.1 (Python)"
    response.headers["X-Powered-By"] = "FastAPI"
    return "no security headers here"


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(
        """<form method='POST' action='/login'>
        <input name='username'><input name='password' type='password'>
        <button>login</button></form>"""
    )


@app.post("/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, role FROM users WHERE username=? AND password=?", (username, password))
    row = cur.fetchone()
    con.close()
    if not row:
        # Account enumeration: distinct messages for missing user vs wrong pw.
        if not _user_exists(username):
            return JSONResponse({"error": "no such user"}, status_code=401)
        return JSONResponse({"error": "wrong password"}, status_code=401)
    # Insecure cookies: no Secure, no HttpOnly, no SameSite.
    response.set_cookie("session", f"id-{row[0]}-role-{row[1]}")
    return {"ok": True, "role": row[1]}


def _user_exists(username: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
    found = cur.fetchone() is not None
    con.close()
    return found


# ---------------------------------------------------------------------------
# CORS misconfig.   Module: cors, cors_advanced
# ---------------------------------------------------------------------------

@app.get("/cors-api")
async def cors_api(origin: str | None = Header(default=None)):
    resp = JSONResponse({"data": "sensitive-info"})
    # Reflect any origin AND allow credentials — classic misconfig.
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


# ---------------------------------------------------------------------------
# IDOR + mass assignment.   Modules: idor, mass_assignment
# ---------------------------------------------------------------------------

@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, username, email, role FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "not found")
    return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}


@app.post("/api/users")
async def create_user(request: Request):
    payload = await request.json()
    # Mass assignment: accepts role= from user input.
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)",
        (payload.get("username", "x"), payload.get("password", "x"),
         payload.get("email", "x@x"), payload.get("role", "user")),
    )
    uid = cur.lastrowid
    con.commit()
    con.close()
    return {"id": uid, **payload}


# ---------------------------------------------------------------------------
# CSRF — state-changing action with no token.   Module: csrf
# ---------------------------------------------------------------------------

@app.get("/csrf-action", response_class=HTMLResponse)
async def csrf_page():
    return HTMLResponse(
        """<form method='POST' action='/csrf-action'>
        <input name='action' value='delete-account'>
        <button>do it</button></form>"""
    )


@app.post("/csrf-action")
async def csrf_action(action: str = Form(...)):
    # No CSRF token verified.
    return {"performed": action}


# ---------------------------------------------------------------------------
# File upload — no extension/type check.   Module: file_upload
# ---------------------------------------------------------------------------

@app.get("/upload", response_class=HTMLResponse)
async def upload_page():
    return HTMLResponse(
        """<form method='POST' enctype='multipart/form-data' action='/upload'>
        <input type='file' name='f'><button>upload</button></form>"""
    )


@app.post("/upload")
async def upload_file(f: UploadFile):
    data = await f.read()
    safe_name = Path(f.filename or "anon").name
    dest_dir = LAB_TMP / "uploads"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_name
    dest.write_bytes(data[:1_000_000])
    # Vulnerable: store any extension, return the URL.
    return {"saved": str(dest), "url": f"/uploads/{safe_name}"}


# ---------------------------------------------------------------------------
# Host header injection.   Module: host_header
# ---------------------------------------------------------------------------

@app.get("/admin")
async def admin_panel(host: str | None = Header(default=None)):
    # Sensitive page that trusts Host header to build links.
    return HTMLResponse(
        f"<h1>Admin Panel</h1><a href='http://{host or 'localhost'}/admin/reset'>reset</a>"
    )


# ---------------------------------------------------------------------------
# Exposed secrets / backup files / VCS / info disclosure.
#   Modules: exposed_secrets, backup_files, well_known
# ---------------------------------------------------------------------------

@app.get("/.env", response_class=PlainTextResponse)
async def env_file():
    return (
        "DB_PASSWORD=lab-pw-2024\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "STRIPE_SECRET=sk_test_4eC39HqLyjWDarjtT1zdp7dc\n"
    )


@app.get("/backup.zip")
async def backup_zip():
    # Pretend backup archive: serves zip-magic header so MIME sniff matches.
    return Response(content=b"PK\x03\x04lab-backup-fake-content", media_type="application/zip")


@app.get("/.git/config", response_class=PlainTextResponse)
async def git_config():
    return (
        "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
        "\turl = git@github.com:lab/secret.git\n"
    )


@app.get("/.git/HEAD", response_class=PlainTextResponse)
async def git_head():
    # Exposed VCS ref — module: source_disclosure (CWE-527).
    return "ref: refs/heads/main\n"


@app.get("/source.php", response_class=PlainTextResponse)
async def source_php_raw():
    # Raw PHP source served as text/plain instead of executed — module:
    # source_disclosure (CWE-540) + mini-SAST (hard-coded AWS key, eval-on-input,
    # SQL string concatenation).
    return Response(
        content=(
            b"<?php\n"
            b"$AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\n"
            b"$id = $_GET['id'];\n"
            b"$q = \"SELECT * FROM users WHERE id=\" . $_GET['id'];\n"
            b"eval($_GET['code']);\n"
            b"?>\n"
        ),
        media_type="text/plain",
    )


@app.get("/info", response_class=HTMLResponse)
async def info():
    # Mimic phpinfo / dev-stacktrace style leakage.
    return HTMLResponse(
        "<h1>phpinfo()-style page</h1>"
        "<p>PHP Version 7.4.3</p><p>Server API: cgi-fcgi</p>"
        "<p>Loaded modules: mysqli, pdo_mysql</p>"
        "<pre>Stack trace:\n  File \"/var/www/app.py\", line 42, in handler\n    raise ValueError('boom')</pre>"
    )


# ---------------------------------------------------------------------------
# GraphQL with introspection enabled.   Module: api_graphql
# ---------------------------------------------------------------------------

GRAPHQL_SCHEMA = {
    "data": {
        "__schema": {
            "types": [
                {"name": "User", "fields": [
                    {"name": "id", "type": {"name": "ID"}},
                    {"name": "email", "type": {"name": "String"}},
                    {"name": "role", "type": {"name": "String"}},
                ]},
                {"name": "Query", "fields": [
                    {"name": "user", "type": {"name": "User"}},
                    {"name": "users", "type": {"name": "User"}},
                    {"name": "adminToken", "type": {"name": "String"}},
                ]},
            ],
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
        }
    }
}


@app.post("/api/graphql")
async def graphql(request: Request):
    body = await request.json()
    query = body.get("query", "")
    if "__schema" in query or "__type" in query:
        return JSONResponse(GRAPHQL_SCHEMA)
    if "adminToken" in query:
        return JSONResponse({"data": {"adminToken": "admin-secret-token-leak"}})
    return JSONResponse({"data": {}})


@app.get("/api/graphql")
async def graphql_get():
    return JSONResponse({"hint": "POST a JSON {query: ...}"})


# ---------------------------------------------------------------------------
# Default creds endpoint hint + rate-limit absence.   Modules: default_creds,
#   rate_limit, account_enum
# ---------------------------------------------------------------------------

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page():
    return HTMLResponse("<form method='POST' action='/admin/login'>"
                        "<input name='u'><input name='p'><button>go</button></form>")


@app.post("/admin/login")
async def admin_login(u: str = Form(...), p: str = Form(...)):
    # accepts admin/admin
    if u == "admin" and p == "admin":
        return {"ok": True, "role": "admin"}
    return JSONResponse({"ok": False}, status_code=401)


# ---------------------------------------------------------------------------
# Weak password reset token.   Module: session_management / business_logic
# ---------------------------------------------------------------------------

_RESET_TOKENS = {f"token-{i}": f"user-{i}" for i in range(1, 100)}


@app.get("/password-reset")
async def password_reset(token: str = Query(default="")):
    # Predictable tokens like token-1, token-2 …
    if token in _RESET_TOKENS:
        return {"ok": True, "user": _RESET_TOKENS[token]}
    return JSONResponse({"ok": False}, status_code=403)


# ---------------------------------------------------------------------------
# Misconfig: directory listing / verbose error.   Module: misconfig
# ---------------------------------------------------------------------------

@app.get("/files/", response_class=HTMLResponse)
async def file_listing():
    # Auto-directory-listing look.
    return HTMLResponse(
        "<title>Index of /files/</title><h1>Index of /files/</h1>"
        "<ul><li><a href='secret.txt'>secret.txt</a></li>"
        "<li><a href='backup.tar.gz'>backup.tar.gz</a></li></ul>"
    )


# ---------------------------------------------------------------------------
# Path-segment traversal — covers /static/.., /assets/.., /files/..;/..
# Module: path_traversal
# ---------------------------------------------------------------------------

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


@app.get("/static/{path:path}", response_class=PlainTextResponse)
async def static_traversal(path: str):
    """Naive static handler that traverses on `..` — leaks /etc/passwd."""
    if "passwd" in path or "etc/" in path or "..%2f" in path.lower():
        return _PASSWD
    if "win.ini" in path.lower():
        return "[fonts]\n[extensions]\n[mci extensions]\n"
    raise HTTPException(404, "not found")


@app.get("/assets/{path:path}", response_class=PlainTextResponse)
async def assets_traversal(path: str):
    if "passwd" in path or "etc/" in path:
        return _PASSWD
    raise HTTPException(404)


@app.get("/files/{path:path}", response_class=PlainTextResponse)
async def files_traversal(path: str):
    if "passwd" in path or "etc/" in path:
        return _PASSWD
    raise HTTPException(404)


# ---------------------------------------------------------------------------
# More backup / archive artifacts — module: backup_files
# These return non-HTML content so the heuristic upgrades to "firm".
# ---------------------------------------------------------------------------

@app.get("/index.php.bak", response_class=PlainTextResponse)
async def php_bak():
    return Response(
        content=b"<?php\n$DB_PASSWORD='lab-pw';\necho 'backup';\n?>\n",
        media_type="application/x-php",
    )


@app.get("/web.config.bak", response_class=PlainTextResponse)
async def webconfig_bak():
    return Response(
        content=b"<configuration><appSettings><add key='db' value='secret'/></appSettings></configuration>",
        media_type="application/xml",
    )


@app.get("/database.sql", response_class=PlainTextResponse)
async def database_sql():
    return Response(
        content=(
            b"CREATE TABLE users (id INT, email TEXT, password TEXT);\n"
            b"INSERT INTO users VALUES (1,'admin@lab.local','admin123');\n"
            b"INSERT INTO users VALUES (2,'alice@lab.local','alice2024');\n"
        ),
        media_type="application/sql",
    )


@app.get("/backup.bak")
async def backup_bak():
    return Response(content=b"PK\x03\x04lab-secret-data\x00\x00",
                    media_type="application/octet-stream")


@app.get("/app.tar.gz")
async def app_tar_gz():
    return Response(content=b"\x1f\x8b\x08\x00lab-archive",
                    media_type="application/gzip")


# ---------------------------------------------------------------------------
# Forgot-password page — fuels account_enum heuristic.
# Module: account_enum
# ---------------------------------------------------------------------------

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_get():
    return HTMLResponse(
        "<form method='POST' action='/forgot-password'>"
        "<input name='email' placeholder='email'>"
        "<button>Send reset link</button></form>"
    )


@app.post("/forgot-password")
async def forgot_password_post(email: str = Form(...)):
    # Reveal whether email exists — classic enumeration.
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM users WHERE email=?", (email,))
    exists = cur.fetchone() is not None
    con.close()
    if exists:
        return HTMLResponse(
            "<p>Reset link sent. Check your inbox at " + html.escape(email) + ".</p>"
        )
    return HTMLResponse(
        "<p>User not found for email " + html.escape(email) + ".</p>",
        status_code=404,
    )


# ---------------------------------------------------------------------------
# JWT token visible in the landing flow — fuels jwt_attacks discovery.
# ---------------------------------------------------------------------------

@app.get("/account", response_class=HTMLResponse)
async def account_page():
    token = _jwt_encode({"sub": "alice", "role": "user"})
    return HTMLResponse(
        f"<h1>Account</h1>"
        f"<script>const session={{token:'{token}'}};</script>"
        f"<p>API token: <code>{token}</code></p>"
        f"<a href='/jwt/whoami'>whoami</a>"
    )


# ---------------------------------------------------------------------------
# Default-credentials panels — module: default_creds
# Tomcat/Jenkins/Grafana fingerprints that accept admin/admin.
# ---------------------------------------------------------------------------

@app.get("/manager/html")
async def tomcat_manager(authorization: str | None = Header(default=None)):
    if not authorization:
        resp = JSONResponse({"error": "auth required"}, status_code=401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="Tomcat Manager Application"'
        return resp
    try:
        creds = base64.b64decode(authorization.split(" ", 1)[1]).decode()
    except Exception:
        raise HTTPException(401)
    if creds in ("tomcat:tomcat", "admin:admin"):
        return HTMLResponse(
            "<title>Tomcat Manager</title><h1>Apache Tomcat/9.0.36</h1>"
            "<p>OK - Logged in as admin</p>"
        )
    raise HTTPException(403)


@app.get("/jenkins/login", response_class=HTMLResponse)
async def jenkins_login_page():
    return HTMLResponse(
        "<title>Jenkins</title><h1>Jenkins 2.346.1</h1>"
        "<form method='POST' action='/jenkins/j_security_check'>"
        "<input name='j_username'><input name='j_password' type='password'>"
        "<button>log in</button></form>"
    )


@app.post("/jenkins/j_security_check")
async def jenkins_login(j_username: str = Form(...), j_password: str = Form(...)):
    if j_username == "admin" and j_password == "admin":
        return JSONResponse({"ok": True})
    return JSONResponse({"ok": False}, status_code=401)


# ---------------------------------------------------------------------------
# XXE convenience — accepts GET so api_xml-style probes hit too.
# Module: xxe
# ---------------------------------------------------------------------------

@app.api_route("/api/xml", methods=["GET", "POST"])
async def api_xml(request: Request):
    body = await request.body()
    if not body:
        # Echo a hint so the module knows XML is consumed here.
        return Response(
            "<?xml version='1.0'?><response>send POST with XML body</response>",
            media_type="application/xml",
        )
    return await xxe(request)


# ---------------------------------------------------------------------------
# Round 7 lab endpoints — exercise the new detection modules
# ---------------------------------------------------------------------------

# postmessage_xss: JS that registers a listener WITHOUT origin check + sink
@app.get("/widget.js", response_class=PlainTextResponse)
async def widget_js():
    return Response(
        content=(
            "// awspt-lab postmessage XSS demo\n"
            "window.addEventListener('message', function(event) {\n"
            "  // BUG: no event.origin check\n"
            "  document.getElementById('output').innerHTML = event.data.html;\n"
            "  if (event.data.code) eval(event.data.code);\n"
            "});\n"
        ),
        media_type="application/javascript",
    )


# csti: serve a page that proudly advertises AngularJS and reflects ?name=
@app.get("/profile", response_class=HTMLResponse)
async def csti_profile(name: str = Query(default="Guest")):
    # Pretend to be an AngularJS app: tech-detect will catch the literal.
    return HTMLResponse(
        f"<!doctype html><html ng-app><head>"
        f"<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.5.0/angular.min.js'></script>"
        f"</head><body><h1>Profile: {name}</h1>"
        f"<div ng-bind='name'>{name}</div></body></html>"
    )


# cache_keyed_headers: reflect Forwarded-Host into an absolute link
@app.get("/cache-page", response_class=HTMLResponse)
async def cache_page(response: Response,
                     x_forwarded_host: str | None = Header(default=None),
                     x_original_url: str | None = Header(default=None)):
    response.headers["Cache-Control"] = "public, max-age=300"
    # No Vary header — cache-key omits the reflected header on purpose.
    host = x_forwarded_host or x_original_url or "lab"
    return HTMLResponse(
        f"<!doctype html><html><body><h1>Cacheable page</h1>"
        f"<a href='https://{host}/admin'>admin</a></body></html>"
    )


# websocket_csrf: accept any Origin (no validation)
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    # BUG: no Origin validation — anyone can connect cross-site.
    await websocket.accept()
    try:
        await websocket.send_text('{"type":"welcome","user":"alice"}')
        while True:
            data = await websocket.receive_text()
            await websocket.send_text('{"echo":' + (data or "null") + '}')
    except WebSocketDisconnect:
        return
    except Exception:
        return


# jwt_chain: keep /jwt endpoint as before; add a JWKS endpoint
@app.get("/.well-known/jwks.json")
async def jwks():
    """Expose a JWKS containing our public key — so jwt_chain can detect
    that we publish keys (algorithm-confusion attack surface)."""
    return {
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "kid": "lab-key-1",
            "use": "sig",
            "n": base64.urlsafe_b64encode(b"lab-fake-pubkey").rstrip(b"=").decode(),
            "e": "AQAB",
        }]
    }


# ===========================================================================
# Round 14 / 15 — vulnerable fixtures for modern modules
# ===========================================================================
# Each block fakes the minimum fingerprint needed for an awspt module to
# fire. They are NOT real CVE implementations — only signature surfaces.

# ─── cve_2024_late — Craft CMS fingerprint ────────────────────────────────
@app.get("/admin/login", response_class=HTMLResponse)
async def cve2024_craft_admin():
    if CLEAN_MODE:
        return HTMLResponse("<html><body>Login</body></html>")
    return HTMLResponse(
        "<html><head><title>Craft</title></head>"
        "<body><h1>Craft CMS 4.13.0</h1>"
        '<div class="cpresources" data-craft="1">'
        '<form action="/cpresources/" method="post">…</form>'
        "</div></body></html>",
    )


# ─── cve_2025_chain — Roundcube webmail fingerprint ───────────────────────
@app.get("/webmail/", response_class=HTMLResponse)
async def cve2025_roundcube():
    if CLEAN_MODE:
        return HTMLResponse("<html><body>x</body></html>")
    return HTMLResponse(
        "<html><head><title>Roundcube Webmail 1.6.5</title></head>"
        '<body><div id="loginform"><h1>Roundcube Webmail 1.6.5</h1>'
        '<form action="/?_task=login" method="post">'
        "<input name='_user'><input name='_pass'></form>"
        "</div></body></html>"
    )


# ─── service_worker_abuse — broad-scope SW with importScripts ─────────────
@app.get("/sw.js")
async def lab_sw():
    if CLEAN_MODE:
        return Response("// scope-limited\n", media_type="application/javascript")
    js = (
        "// awspt-lab service worker — intentionally wide-scope\n"
        "importScripts('https://cdn.example-evil.tld/sw-helper.js');\n"
        "self.addEventListener('fetch', e => {\n"
        "  e.respondWith(caches.open('v1').then(c =>\n"
        "    c.match(e.request).then(r => r || fetch(e.request))));\n"
        "});\n"
        "self.addEventListener('install', e => self.skipWaiting());\n"
    )
    return Response(js, media_type="application/javascript",
                    headers={"Service-Worker-Allowed": "/"})


# ─── trusted_types_bypass — permissive CSP + pass-through policy ──────────
@app.get("/tt-app", response_class=HTMLResponse)
async def lab_trusted_types():
    headers = {} if CLEAN_MODE else {
        "Content-Security-Policy":
            "default-src 'self'; require-trusted-types-for 'script'; "
            "trusted-types 'none'",
    }
    body = "<html><head><title>tt</title></head><body>" + (
        "<div id='x'></div><script>document.getElementById('x').innerHTML='hi'</script>"
        if CLEAN_MODE else
        "<script>const p=trustedTypes.createPolicy('default',{createHTML:s=>s});"
        "document.body.innerHTML='<img src=x>';</script>"
    ) + "</body></html>"
    return HTMLResponse(body, headers=headers)


# ─── trpc_discovery — public tRPC endpoint with procedure leak ────────────
@app.get("/api/trpc/_def")
async def lab_trpc_def():
    if CLEAN_MODE:
        raise HTTPException(404)
    # Include the literal "trpc" string so _is_trpc_payload() accepts.
    return {
        "trpc": "appRouter",
        "router": "appRouter",
        "procedures": ["user.list", "user.byId", "user.update", "user.delete",
                       "admin.createUser", "auth.me", "post.create"],
    }


@app.post("/api/trpc/{proc:path}")
async def lab_trpc_proc(proc: str, request: Request):
    if CLEAN_MODE:
        raise HTTPException(404)
    if "list" in proc or "byId" in proc:
        return {"result": {"data": {"json": [{"id": 1, "name": "alice"}]}}}
    raise HTTPException(
        status_code=400,
        detail={"json": {"error": {"code": -32600, "data": {
            "code": "BAD_REQUEST", "httpStatus": 400, "path": proc,
            "stack": "Zod issue at messages[0].content",
            "issues": [{"path": ["messages"], "message": "expected array"}],
        }}}},
    )


# ─── supabase_rls_check — leaked anon key + open PostgREST ────────────────
@app.get("/dashboard", response_class=HTMLResponse)
async def lab_supabase_dashboard():
    # Bundle an anon JWT in the page body (role:"anon" payload base64url)
    anon = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."  # {"alg":"HS256","typ":"JWT"}
        "eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0."   # {"role":"anon",...}
        "awsptlabsignature"
    )
    if CLEAN_MODE:
        return HTMLResponse("<html><body>no supabase</body></html>")
    return HTMLResponse(
        f"<html><body><script>"
        f"const SUPA_URL='https://awspt-fake.supabase.co';"
        f"const SUPA_KEY='{anon}';"
        f"</script></body></html>"
    )


# ─── llm_endpoint_disco — chat completions relay with prompt echo ─────────
@app.post("/api/chat")
async def lab_llm_chat(request: Request):
    if CLEAN_MODE:
        raise HTTPException(401)
    try:
        body = await request.json()
    except Exception:
        body = {}
    msgs = body.get("messages") or []
    last = (msgs[-1].get("content") if msgs else "") or ""
    sys_msg = next((m for m in msgs if m.get("role") == "system"), None)
    if sys_msg and "ROLE_CONFIRMED" in sys_msg.get("content", ""):
        return {"choices": [{"index": 0, "message": {
            "role": "assistant", "content": "ROLE_CONFIRMED"}}]}
    # Echo the marker so the module's probe is satisfied
    return {"choices": [{"index": 0, "message": {
        "role": "assistant",
        "content": f"echo: {last[:200]}"}}]}


# ─── wasm_endpoint — WASM with embedded URLs + a fake secret ──────────────
@app.get("/app.wasm")
async def lab_wasm():
    if CLEAN_MODE:
        raise HTTPException(404)
    # Minimal valid WASM: header + version, then string-table padding
    blob = b"\x00asm\x01\x00\x00\x00"  # magic + version
    # Inject candidate "endpoints" and a fake secret in plain bytes
    payload = (
        b"\x00\x00 /api/admin/users  AKIATESTLABFAKE0000 "
        b"https://internal-api.awspt-lab.local/v1/secret "
        b"Bearer awspt_token_lab_xxxxxxxxxxxxxxxx \x00"
    )
    return Response(blob + payload, media_type="application/wasm")


# ─── cve_2025_late — Langflow fingerprint + validate/code echo ────────────
@app.get("/api/v1/version")
async def lab_langflow_version():
    if CLEAN_MODE:
        return {"version": "1.4.0"}
    return {"version": "1.0.0", "main_version": "1.0.0", "package": "Langflow"}


@app.post("/api/v1/validate/code")
async def lab_langflow_validate(request: Request):
    if CLEAN_MODE:
        raise HTTPException(401)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    code = (body or {}).get("code", "")
    return {"errors": {}, "imports": {"errors": {}, "exec": f"echo: {code[:80]}"}}


# ─── wp_plugin_cves — wp-login + vulnerable LiteSpeed plugin readme ──────
@app.get("/wp-login.php", response_class=HTMLResponse)
async def lab_wp_login():
    return HTMLResponse(
        "<html><body><h1>WordPress</h1>"
        "<form id='loginform'><input name='log'><input name='pwd'></form>"
        "</body></html>"
    )


@app.get("/wp-content/plugins/litespeed-cache/readme.txt",
         response_class=PlainTextResponse)
async def lab_wp_litespeed_readme():
    if CLEAN_MODE:
        return PlainTextResponse(
            "=== LiteSpeed Cache ===\nStable tag: 7.0.0\n"
            "Contributors: litespeedtech\n"
        )
    return PlainTextResponse(
        "=== LiteSpeed Cache ===\n"
        "Contributors: litespeedtech\n"
        "Tags: cache, performance, optimization\n"
        "Tested up to: 6.6\n"
        "Stable tag: 6.3.0.1\n"      # <-- vulnerable range
        "License: GPL\n\n"
        "== Description ==\nLab fixture for CVE-2024-28000.\n"
    )


# ─── http2_continuation_flood — vulnerable nginx version banner ─────────
@app.get("/lab-h2/nginx-banner")
async def lab_h2_banner(response: Response):
    if CLEAN_MODE:
        response.headers["Server"] = "nginx/1.27.0"
        return {"ok": True}
    response.headers["Server"] = "nginx/1.25.3"   # <= 1.25.5 → CVE-2024-27316
    response.headers["Alt-Svc"] = 'h2=":443"'
    return {"ok": True, "banner": "vulnerable"}


# ─── websocket_hijack — accepts cross-origin upgrade pre-auth ────────────
@app.websocket("/ws/awspt")
async def lab_ws_hijack(websocket: WebSocket):
    # No origin check — accept everything
    await websocket.accept()
    try:
        await websocket.send_text(
            '{"type":"welcome","user":"alice","session_token":"awspt-lab-token-xx"}'
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        return
    except Exception:
        return


# ─── edge_function_audit — fake Vercel + Cloudflare Worker fingerprints ──
@app.get("/api/edge-config")
async def lab_edge_config(response: Response):
    if CLEAN_MODE:
        raise HTTPException(404)
    response.headers["x-vercel-id"] = "iad1::lab::lab-lab-lab-lab"
    response.headers["x-vercel-cache"] = "MISS"
    response.headers["x-vercel-deployment-url"] = "awspt-lab.vercel.app"
    return {"flag.beta": True, "STRIPE_KEY": "sk_test_lab", "DB": "postgres://lab"}


# Provide Vercel-style headers on root too, so the module fingerprints us
@app.middleware("http")
async def add_edge_headers(request: Request, call_next):
    response = await call_next(request)
    if not CLEAN_MODE and request.url.path == "/":
        response.headers.setdefault("x-vercel-id", "iad1::lab::vercel-marker")
        response.headers.setdefault("cf-ray", "8b00000000000000-IAD")
        response.headers.setdefault("via", "1.1 google")
    return response


# ─── cloud_ai_exposure — fake Ollama model list ─────────────────────────
@app.get("/api/tags")
async def lab_ollama_tags():
    if CLEAN_MODE:
        raise HTTPException(404)
    return {"models": [
        {"name": "llama3:8b", "size": 4900000000},
        {"name": "mistral:7b", "size": 4100000000},
    ]}


# ─── dataplatform_disco — fake Apache Superset login ─────────────────────
@app.get("/superset/login/", response_class=HTMLResponse)
async def lab_superset_login():
    if CLEAN_MODE:
        return HTMLResponse("<html><body>x</body></html>")
    return HTMLResponse(
        "<html><head><title>Apache Superset</title></head>"
        "<body><h1>Apache Superset</h1>"
        "<form id='loginbox'>Apache Superset Login</form>"
        "</body></html>"
    )


# ===========================================================================
# Round 17 — common-vulnerability fixtures
# ===========================================================================

# ─── spring_actuator — Spring Boot Actuator with leaked env ──────────────
@app.get("/actuator")
async def lab_actuator_base(response: Response):
    response.headers["Content-Type"] = "application/vnd.spring-boot.actuator.v3+json"
    return {
        "_links": {
            "self": {"href": "/actuator", "templated": False},
            "env": {"href": "/actuator/env"},
            "heapdump": {"href": "/actuator/heapdump"},
            "loggers": {"href": "/actuator/loggers"},
            "health": {"href": "/actuator/health"},
        }
    }


@app.get("/actuator/env")
async def lab_actuator_env():
    if CLEAN_MODE:
        raise HTTPException(401)
    return {
        "activeProfiles": ["production"],
        "propertySources": [
            {"name": "applicationConfig",
             "properties": {
                 "spring.datasource.url": {"value": "jdbc:mysql://db.internal:3306/app"},
                 "spring.datasource.username": {"value": "appuser"},
                 "spring.datasource.password": {"value": "Pr0d-DB-Pwd!"},
                 "jwt.secret": {"value": "awspt-lab-jwt-signing-secret-key-32B"},
                 "stripe.secret.key": {"value": "sk_live_lab_FAKE"},
             }},
        ],
    }


# ─── werkzeug_debugger — Flask Werkzeug console fingerprint ──────────────
@app.get("/console", response_class=HTMLResponse)
async def lab_werkzeug_console():
    if CLEAN_MODE:
        raise HTTPException(404)
    return HTMLResponse(
        "<!doctype html><html><head>"
        "<title>Werkzeug Debugger</title></head><body>"
        "<div class='debugger'><h1>Werkzeug Debugger</h1>"
        "<div id='console' data-debug='1'>"
        "<script>SECRET = \"awspt-lab-debug-secret\";</script>"
        "DEBUGGER PIN: 123-456-789 (override AWSPT_NO_PIN)"
        "</div></div></body></html>"
    )


# ─── django_debug — Django DEBUG=True traceback page ─────────────────────
@app.get("/awspt-deliberate-404-trigger", response_class=HTMLResponse)
async def lab_django_404(response: Response):
    if CLEAN_MODE:
        raise HTTPException(404)
    response.status_code = 404
    return HTMLResponse(
        "<!doctype html><html><head>"
        "<title>Page not found at /awspt-deliberate-404-trigger</title>"
        "</head><body>"
        "<h1>Page not found <span>(404)</span></h1>"
        "<p>You're seeing this error because you have <code>DEBUG = True</code> "
        "in your Django settings file.</p>"
        "<table><tr><th>Django Version:</th><td>5.0.6</td></tr>"
        "<tr><th>Request Method:</th><td>GET</td></tr>"
        "<tr><th>SECRET_KEY</th><td>&#39;awspt-lab-django-secret-xx&#39;</td></tr>"
        "<tr><th>DATABASES</th><td>&#39;PASSWORD&#39;: &#39;dj-lab-pwd&#39;</td></tr>"
        "</table>"
        "Traceback (most recent call last): … in awspt-lab"
        "</body></html>"
    )


# ─── xssi — JSON endpoint returning a top-level Array with auth context ─
@app.get("/api/me")
async def lab_xssi():
    if CLEAN_MODE:
        return JSONResponse({"id": 1},
            headers={"X-Content-Type-Options": "nosniff"})
    return Response(
        content='[{"id":1,"email":"alice@lab.local","token":"awspt-session-xx"},'
                '{"id":2,"email":"bob@lab.local"}]',
        media_type="application/javascript",
    )


# ─── path_confusion — ACL on /private, /private/./ bypasses ─────────────
# We use `/private` (in path_confusion's standard probe list) so the
# module auto-discovers the baseline.
@app.get("/private")
async def lab_pc_private():
    return PlainTextResponse("Unauthorized", status_code=401)


@app.get("/private/{rest:path}")
async def lab_pc_private_bypass(rest: str):
    if CLEAN_MODE:
        raise HTTPException(401)
    return {"private": True, "secret": "awspt-lab-private-flag", "rest": rest}


# ─── token_in_url — page with link carrying a token-shaped api_key ───────
@app.get("/widgets", response_class=HTMLResponse)
async def lab_token_in_url():
    if CLEAN_MODE:
        return HTMLResponse("<html><body><a href='/secure'>secure</a></body></html>")
    return HTMLResponse(
        "<html><body>"
        "<a href='https://analytics.example.com/track?api_key=awspt-lab-secret-key-1234567890abcdef'>track</a> "
        "<a href='/dashboard?session=eyJsYWJ0b2tlbiI6dHJ1ZX0.AAA.BBB'>dashboard</a>"
        "</body></html>"
    )


# ─── apache_status — fake Apache mod_status page ─────────────────────────
@app.get("/server-status", response_class=HTMLResponse)
async def lab_apache_status(response: Response):
    if CLEAN_MODE:
        response.status_code = 403
        return HTMLResponse("Forbidden", status_code=403)
    return HTMLResponse(
        "<html><head><title>Apache Status</title></head><body>"
        "<h1>Apache Server Status for awspt-lab</h1>"
        "<dl><dt>Server Version: Apache/2.4.41 (Unix)</dt></dl>"
        "<table><tr><th>Srv</th><th>PID</th><th>Acc</th><th>Client</th><th>VHost</th><th>Request</th></tr>"
        "<tr><td>0-0</td><td>123</td><td>4/12</td><td>10.0.0.5</td><td>awspt-lab</td><td>GET /login?u=alice&p=lab</td></tr>"
        "</table></body></html>"
    )


# ─── mqtt_websocket — MQTT broker over WS (mock 400 + WS protocol hdr) ───
@app.get("/mqtt")
async def lab_mqtt():
    if CLEAN_MODE:
        raise HTTPException(404)
    return PlainTextResponse(
        "WebSocket Upgrade required",
        status_code=400,
        headers={"Sec-WebSocket-Protocol": "mqtt", "Upgrade": "websocket"},
    )


# ─── dns_rebinding fixture: lab already accepts arbitrary Host headers ───
# (no extra endpoint needed — middleware doesn't validate Host)


# ---------------------------------------------------------------------------
# Health & banner for the validator to verify the container is up.
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "awspt-lab"}
