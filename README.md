# awspt-vuln-lab — intentionally vulnerable test target

> ⚠️ **WARNING — this application is deliberately, massively insecure.**
> It exists only to exercise the [awspt](https://github.com/AnasKamoun/AWS_WEB_Pentest)
> security scanner (SAST + SCA + DAST). **Never deploy it on a public URL** — it has
> remote code execution, SSRF, command injection and more. Run it only inside an
> isolated/ephemeral sandbox (which is exactly what awspt's `build & run` does).

It is built to light up **the whole awspt chain — audit → build & run → scan → report**.

## What's inside (maximised vulnerability surface)

| Layer | Files | What it triggers |
|---|---|---|
| **DAST** (runtime) | `app.py` | ~60 vulnerable HTTP endpoints: SQLi, XSS, SSTI, command injection, SSRF, LFI/traversal, XXE, JWT `alg=none`, IDOR, open redirect, CSRF, CORS, exposed `.env`/`.git`, default creds, GraphQL introspection, host-header, cache poisoning… (≈180 findings on an elite scan) |
| **SAST** (source) | `vulns/*.py,*.js,*.php,*.java,*.go,*.rb,*.cs,*.tf,*.sh` | ~40 CWE classes across 9 languages: CWE-89/78/95/502/798/327/918/22/611/601/79/1321/434/90/643/295/330/347/284/732… each as a tainted source→sink flow |
| **SCA** (deps) | `requirements.txt`, `requirements.in`, `package.json`, `composer.json`, `Gemfile`, `go.mod`, `pom.xml` | Known-CVE pinned deps across PyPI / npm / Packagist / RubyGems / Go / Maven — incl. **Log4Shell** (log4j-core 2.14.1), jackson-databind, lodash, axios, Django 2.2, etc. |
| **Secrets** | `.env`, `.npmrc`, `secrets/`, `config/*`, inline in `vulns/*` | Hard-coded (fake) credentials across **18 detector classes**: AWS access-key id **and secret key**, Stripe, GitHub, Slack, OpenAI, Anthropic, HuggingFace, DigitalOcean, Discord, Telegram, Shopify, Square, JWT/signing keys, DB passwords — spread across `.env` / `.properties` / `.json` / `.toml` config formats, plus committed key files (`id_rsa`, `*.p12`, `.npmrc`, AWS `credentials`). `config/decoys.yml` is a **negative control** (placeholders / `${{ secrets.X }}` references / low-entropy values that MUST NOT fire). |

## Test it with awspt

**Full chain locally (Docker running) — one command does audit → build & run → scan → report:**
```bash
awspt --audit-repo https://github.com/AnasKamoun/awspt-vuln-lab \
      --build-run --format pro-html --out report.html
```

**Run it standalone, then scan the live URL:**
```bash
docker build -t vuln-lab . && docker run --rm -p 8000:8000 vuln-lab   # ISOLATED host only
awspt --target http://127.0.0.1:8000 --profile elite --format pro-html --out report.html
```

**Audit-only (works anywhere, no Docker — e.g. your deployed awspt on AWS):**
```bash
awspt-audit https://github.com/AnasKamoun/awspt-vuln-lab
# or POST the repo URL to /api/audit on your awspt server
```

## Layout
```
app.py            # runnable vulnerable FastAPI app (the DAST target)
Dockerfile        # build & run (used by awspt's sandbox)
requirements.txt  # runtime deps (old, CVE-bearing, still installable)
requirements.in   # extra ancient PyPI pins (SCA only, not installed)
package.json composer.json Gemfile go.mod pom.xml   # multi-ecosystem vulnerable deps (SCA)
.env              # fake hard-coded secrets (SAST)
.npmrc            # fake npm registry auth token (SAST)
secrets/          # committed key material — id_rsa, *.p12, AWS credentials (flagged by name)
config/           # secrets across .properties/.json/.toml/.env formats + decoys.yml (FP control)
vulns/            # standalone vulnerable source files in 9 languages (SAST)
```

_For authorised security testing and education only._
