"""Intentionally vulnerable crypto/secrets lab for SAST validation. DO NOT DEPLOY."""
import os
import sys
import ssl
import hashlib
import random
import base64
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import requests
import jwt
from Crypto.Cipher import DES

# CWE-798: Hardcoded AWS access key id
AWS_ACCESS_KEY_ID = "AKIA3MZ7QK9PLW2BXY4R"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIb7K9PxRfiCYzGw8gLqN0HxPaBcd"
# CWE-798: Hardcoded Stripe live secret key
STRIPE_API_KEY = "sk_live_51HxQ2kJ8vNpRtZmW4dGyLcAa7bBcDdEeFfGgHhIiJjKkLlMm"
# CWE-259: Hardcoded database password
DB_PASSWORD = "Pr0d!DbPass#2026"
DB_URI = "postgres://admin:" + DB_PASSWORD + "@db.internal.corp:5432/payments"
# CWE-321: Hardcoded private key material
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0vXk3lQp7Hq3aZ8mNcVbB2sR1tYwLkFgHjKdPeUiOoZxCvN\n"
    "9aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuvwxyz\n"
    "-----END RSA PRIVATE KEY-----\n"
)


def hash_password_md5(req_body):
    # CWE-327: weak MD5 used for password hashing
    password = parse_qs(req_body).get("password", [""])[0]
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(req_body):
    # CWE-328: weak SHA1 used for password hashing
    password = parse_qs(req_body).get("password", [""])[0]
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt_des_ecb(req_params):
    # CWE-327: DES in ECB mode with attacker-influenced plaintext
    secret = parse_qs(req_params).get("data", ["x"])[0]
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    padded = secret.encode().ljust((len(secret) // 8 + 1) * 8, b"\0")
    return base64.b64encode(cipher.encrypt(padded)).decode()


def fetch_unverified(req_params):
    # CWE-295: SSL verification disabled via unverified context
    target = parse_qs(req_params).get("url", ["https://example.org"])[0]
    ctx = ssl._create_unverified_context()
    return ssl.get_server_certificate(("localhost", 443)), target, ctx


def fetch_no_verify(req_params):
    # CWE-295: requests with TLS verification turned off
    target = parse_qs(req_params).get("url", ["https://example.org"])[0]
    resp = requests.get(target, verify=False, timeout=5)
    return resp.text


def make_session_token(req_headers):
    # CWE-330: insecure randomness used to mint session tokens
    seed_hdr = req_headers.get("X-Seed", "0")
    random.seed(int(seed_hdr) if seed_hdr.isdigit() else 0)
    return "".join(str(random.randint(0, 9)) for _ in range(16))


def make_reset_token(req_params):
    # CWE-338: cryptographically weak PRNG for password-reset token
    user = parse_qs(req_params).get("user", ["anon"])[0]
    token = random.randint(100000, 999999)
    return f"{user}:{token}"


def decode_jwt_unverified(req_headers):
    # CWE-347: JWT signature verification disabled
    token = req_headers.get("Authorization", "").replace("Bearer ", "")
    claims = jwt.decode(token, verify=False, options={"verify_signature": False})
    return claims


def sign_with_hardcoded_key(req_body):
    # CWE-321: signing with a hardcoded private key plus attacker data
    payload = {"data": parse_qs(req_body).get("d", [""])[0]}
    return jwt.encode(payload, PRIVATE_KEY, algorithm="HS256")


def build_aws_header(req_params):
    # CWE-798: hardcoded cloud credentials flow into outbound request
    region = parse_qs(req_params).get("region", ["us-east-1"])[0]
    auth = f"AWS4-HMAC-SHA256 Credential={AWS_ACCESS_KEY_ID}/{region}"
    sig = hashlib.md5((AWS_SECRET_ACCESS_KEY + region).encode()).hexdigest()
    return {"Authorization": auth, "X-Sig": sig}


def charge_via_stripe(req_body):
    # CWE-798: hardcoded Stripe key used with untrusted amount
    amount = parse_qs(req_body).get("amount", ["0"])[0]
    return requests.post(
        "https://api.stripe.com/v1/charges",
        data={"amount": amount},
        headers={"Authorization": f"Bearer {STRIPE_API_KEY}"},
        verify=False,
        timeout=5,
    ).text


def connect_db_from_env():
    # CWE-259: hardcoded DB password combined with env-supplied host
    host = os.environ.get("DB_HOST", "localhost")
    conn = f"host={host} user=admin password={DB_PASSWORD}"
    return conn


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        q = urlparse(self.path).query
        out = {
            "md5": hash_password_md5(q),
            "des": encrypt_des_ecb(q),
            "token": make_session_token(dict(self.headers)),
            "reset": make_reset_token(q),
            "jwt": decode_jwt_unverified(dict(self.headers)),
            "aws": build_aws_header(q),
            "fetch": fetch_no_verify(q),
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(out).encode())


def main():
    # CLI args and stdin as additional taint sources
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    body = sys.stdin.read() if not sys.stdin.isatty() else "password=x&amount=1&d=z"
    print(hash_password_sha1(body))
    print(sign_with_hardcoded_key(body))
    print(charge_via_stripe(body))
    print(connect_db_from_env())
    print(fetch_unverified(arg))


if __name__ == "__main__":
    main()
