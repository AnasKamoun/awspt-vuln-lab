"""Intentionally vulnerable SSRF / file-handling lab for SAST validation.

DO NOT DEPLOY. Every handler below takes untrusted input and feeds it into a
dangerous sink with no mitigation. Used to validate taint-tracking analyzers.
"""
import os
import sys
import subprocess
import tarfile
import zipfile
import tempfile
import sqlite3
import pickle
import urllib.request

import requests
from flask import Flask, request, send_file, Response
from lxml import etree

app = Flask(__name__)

# Hardcoded fake secrets with realistic shapes (CWE-798: Hardcoded Credentials)
AWS_ACCESS_KEY_ID = "AKIAQ4WX7K2H9ZJ3M5PL"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY7x"
STRIPE_API_KEY = "sk_live_51HsT9KpQ2vRxZ8mNcWqLfYbA0dEfGhIjKlMnOpQrStUv"


@app.route("/fetch")
def fetch_url():
    # CWE-918: Server-Side Request Forgery via requests.get on user URL
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return resp.text


@app.route("/metadata")
def fetch_metadata():
    # CWE-918: SSRF reaching cloud metadata endpoint (169.254.169.254)
    path = request.args.get("path", "/latest/meta-data/")
    target = "http://169.254.169.254" + path
    return urllib.request.urlopen(target).read()


@app.route("/proxy")
def proxy_urlopen():
    # CWE-918: SSRF via urllib.urlopen on attacker-controlled URL
    target = request.args.get("target")
    with urllib.request.urlopen(target) as r:
        return r.read()


@app.route("/read")
def read_file():
    # CWE-22: Path Traversal -- user path flows directly into open()
    name = request.args.get("file")
    with open(name, "r") as fh:
        return fh.read()


@app.route("/download")
def download_file():
    # CWE-22: Path Traversal via flask send_file(request.args)
    fname = request.args.get("name")
    return send_file("/var/data/" + fname)


@app.route("/raw")
def raw_send():
    # CWE-22: send_file with fully user-controlled absolute path
    return send_file(request.args.get("path"))


@app.route("/untar", methods=["POST"])
def untar_archive():
    # CWE-22: Zip-Slip / arbitrary write via tarfile.extractall (no member check)
    blob = request.get_data()
    tmp = "/tmp/upload.tar"
    with open(tmp, "wb") as fh:
        fh.write(blob)
    with tarfile.open(tmp) as tar:
        tar.extractall(path=request.args.get("dest", "/tmp/out"))
    return "untarred"


@app.route("/unzip", methods=["POST"])
def unzip_archive():
    # CWE-22: Zip-Slip via zipfile.extractall on uploaded archive
    upload = request.files["archive"]
    dest = request.args.get("dest", "/tmp/unz")
    with zipfile.ZipFile(upload.stream) as zf:
        zf.extractall(dest)
    return "unzipped"


@app.route("/xml", methods=["POST"])
def parse_xml():
    # CWE-611: XXE -- resolve_entities=True and no_network=False on user XML
    body = request.get_data()
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    doc = etree.fromstring(body, parser)
    return etree.tostring(doc)


@app.route("/temp")
def make_temp():
    # CWE-377: Insecure temp file via tempfile.mktemp + user-controlled suffix
    suffix = request.args.get("suffix", ".tmp")
    path = tempfile.mktemp(suffix=suffix)
    with open(path, "w") as fh:
        fh.write(request.args.get("data", ""))
    return path


@app.route("/run")
def run_cmd():
    # CWE-78: OS Command Injection via shell=True on user input
    host = request.args.get("host")
    out = subprocess.check_output("ping -c1 " + host, shell=True)
    return out


@app.route("/calc")
def calc():
    # CWE-95: Code Injection via eval() on request parameter
    expr = request.args.get("expr")
    return str(eval(expr))


@app.route("/load", methods=["POST"])
def load_pickle():
    # CWE-502: Deserialization of untrusted data via pickle.loads
    return str(pickle.loads(request.get_data()))


@app.route("/user")
def get_user():
    # CWE-89: SQL Injection -- user id concatenated into query
    uid = request.args.get("id")
    conn = sqlite3.connect("/tmp/app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '" + uid + "'")
    return str(cur.fetchall())


@app.route("/redirect")
def open_redirect():
    # CWE-601: Open Redirect via user-controlled Location header
    dest = request.args.get("next")
    return Response(status=302, headers={"Location": dest})


def cli_fetch():
    # CWE-918: SSRF from CLI argument feeding requests.get
    url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET_URL", "")
    return requests.get(url).text


def stdin_eval():
    # CWE-95: Code Injection -- eval over stdin line
    line = sys.stdin.readline()
    return eval(line)


def env_command():
    # CWE-78: Command Injection from environment variable via os.system
    payload = os.environ.get("CMD", "")
    os.system("sh -c " + payload)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=True)
