"""Intentionally vulnerable injection lab (DVWA-style). For SAST validation ONLY.

Every handler reads untrusted input and flows it into a dangerous sink with no
sanitization. Do NOT deploy. Each function names the CWE it demonstrates.
"""
import os
import sys
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request
from fastapi import FastAPI, Query

app = Flask(__name__)
api = FastAPI()
db = sqlite3.connect(":memory:", check_same_thread=False)

# --- hardcoded fake secrets (CWE-798: Use of Hard-coded Credentials) ---
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY = "sk_live_51HxQ2eJ8sZ4kPq9mNvTbWxYz0aBcDeFgHiJkLmNoP"


@app.route("/sqli/fstring")
def sqli_fstring():
    # CWE-89: SQL Injection via f-string interpolation into execute()
    uid = request.args.get("id")
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return str(cur.fetchall())


@app.route("/sqli/format")
def sqli_format():
    # CWE-89: SQL Injection via str.format() into execute()
    name = request.args.get("name")
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name = '{0}'".format(name))
    return str(cur.fetchall())


@app.route("/sqli/percent", methods=["POST"])
def sqli_percent():
    # CWE-89: SQL Injection via %-formatting into execute()
    role = request.form["role"]
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE role = '%s'" % role)
    return str(cur.fetchall())


@app.route("/cmd/system")
def cmd_system():
    # CWE-78: OS Command Injection via os.system with concatenation
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "pinged"


@app.route("/cmd/popen")
def cmd_popen():
    # CWE-78: OS Command Injection via subprocess.Popen(shell=True)
    target = request.args.get("target")
    proc = subprocess.Popen("nslookup " + target, shell=True, stdout=subprocess.PIPE)
    return proc.stdout.read()


@app.route("/cmd/ospopen")
def cmd_ospopen():
    # CWE-78: OS Command Injection via os.popen
    f = request.args.get("file")
    return os.popen("cat " + f).read()


@app.route("/code/eval")
def code_eval():
    # CWE-95: Code Injection via eval() on user input
    expr = request.args.get("expr")
    return str(eval(expr))


@app.route("/code/exec", methods=["POST"])
def code_exec():
    # CWE-95: Code Injection via exec() on user input
    body = request.form["code"]
    exec(body)
    return "executed"


@app.route("/deser/pickle", methods=["POST"])
def deser_pickle():
    # CWE-502: Deserialization of Untrusted Data via pickle.loads
    raw = request.get_data()
    obj = pickle.loads(raw)
    return str(obj)


@app.route("/deser/yaml", methods=["POST"])
def deser_yaml():
    # CWE-502: Unsafe YAML deserialization (yaml.Loader allows object construction)
    data = request.form["doc"]
    obj = yaml.load(data, Loader=yaml.Loader)
    return str(obj)


@app.route("/import")
def dynamic_import():
    # CWE-470: Unsafe Reflection via __import__ on user-controlled module name
    mod = request.args.get("module")
    return str(__import__(mod))


@app.route("/header/sqli")
def header_sqli():
    # CWE-89: SQL Injection sourced from an HTTP header
    api_user = request.headers.get("X-User")
    cur = db.cursor()
    cur.execute(f"SELECT token FROM sessions WHERE user = '{api_user}'")
    return str(cur.fetchall())


@api.get("/api/search")
def fastapi_search(q: str = Query(...)):
    # CWE-89: SQL Injection from a FastAPI Query() parameter
    cur = db.cursor()
    cur.execute("SELECT * FROM products WHERE title LIKE '%" + q + "%'")
    return cur.fetchall()


@api.get("/api/run")
def fastapi_run(cmd: str = Query(...)):
    # CWE-78: OS Command Injection from a FastAPI Query() parameter
    return os.popen("sh -c " + cmd).read()


def cli_eval():
    # CWE-95: Code Injection via eval() on a CLI argument
    return eval(sys.argv[1])


def env_command():
    # CWE-78: OS Command Injection via environment variable into os.system
    payload = os.environ.get("USER_CMD", "")
    os.system("echo " + payload)


def stdin_import():
    # CWE-470: Unsafe Reflection via __import__ on a module name read from stdin
    line = sys.stdin.readline().strip()
    return __import__(line)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
