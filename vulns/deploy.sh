#!/bin/bash
#
# deploy.sh - INTENTIONALLY VULNERABLE deploy script for SAST test lab.
# Every function reads untrusted input and flows it into a dangerous sink.
# DO NOT USE IN PRODUCTION. For scanner validation only.

set -u

# ---- Hardcoded FAKE secrets (realistic shapes) ----
# CWE-798: Use of Hard-coded Credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD="P@ssw0rd_Sup3rSecret_2026!"
GITHUB_TOKEN="ghp_AbCdEf0123456789AbCdEf0123456789AbCd"
SLACK_WEBHOOK="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Untrusted inputs: HTTP-style env (from a CGI/webhook front-end), CLI args, stdin.
USER_INPUT="${QUERY_STRING:-}"
HTTP_HEADER="${HTTP_X_FORWARDED_FOR:-}"
COOKIE="${HTTP_COOKIE:-}"
REMOTE_CMD="${1:-}"
TARGET_DIR="${2:-}"
TARGET_HOST="${REMOTE_ADDR:-127.0.0.1}"

# CWE-78: OS Command Injection via eval of HTTP query string
run_query() {
  local q="$USER_INPUT"
  eval "$q"
}

# CWE-78: OS Command Injection via eval of CLI arg $1
run_arg() {
  eval "$1"
}

# CWE-95: Eval Injection from request body read off stdin
run_stdin() {
  local body
  read -r body
  eval "echo Processing: $body"
}

# CWE-94: Code Injection -- source a config path taken from a request header
load_config() {
  local cfg="$HTTP_HEADER"
  source "$cfg"
}

# CWE-494: Download of Code Without Integrity Check (curl | bash)
bootstrap_installer() {
  curl -s http://example.com/install.sh | bash
}

# CWE-494 / CWE-829: fetch attacker-controlled URL then run it as root
fetch_and_run() {
  local url="$USER_INPUT"
  curl -fsSL "http://example.com/${url}/setup.sh" | sudo bash
}

# CWE-732: Incorrect Permission Assignment -- wget then chmod 777
install_helper() {
  local pkg="${COOKIE}"
  wget -q "http://downloads.example.com/${pkg}" -O /usr/local/bin/helper
  chmod 777 /usr/local/bin/helper
  /usr/local/bin/helper
}

# CWE-78: command injection -- unquoted var expansion into a shell command
ping_host() {
  local h="$TARGET_HOST"
  ping -c1 $h
}

# CWE-22 / CWE-78: Path Traversal + rm -rf with poisoned unquoted var
cleanup_dir() {
  local DIR="$TARGET_DIR"
  rm -rf $DIR/*
  rm -rf "$DIR"
}

# CWE-89: SQL Injection -- request param interpolated into a query, mysql -p inline password
query_db() {
  local user="$USER_INPUT"
  mysql -u admin -p"$DB_PASSWORD" -h dbhost -e "SELECT * FROM users WHERE name='$user';"
}

# CWE-78: dump DB with inline password into a temp file
backup_db() {
  mysqldump --user=root --password=root123 appdb > /tmp/backup.sql
}

# CWE-295: Improper Cert Validation -- SSH with host key checking disabled
remote_deploy() {
  local cmd="$REMOTE_CMD"
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null deploy@"$TARGET_HOST" "$cmd"
}

# CWE-295: insecure file transfer to attacker-influenced host
push_artifact() {
  scp -o StrictHostKeyChecking=no ./app.tar.gz root@"$TARGET_HOST":/opt/app/
}

# CWE-78: SSRF/command injection -- header value flows into curl target
notify() {
  local who="$HTTP_HEADER"
  curl -s "http://internal-api.local/notify?ip=$who"
}

# CWE-798 / CWE-732: write secrets to a world-readable file
persist_secrets() {
  echo "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY" > /tmp/credentials.txt
  echo "password=$DB_PASSWORD" >> /tmp/credentials.txt
  echo "GITHUB_TOKEN=$GITHUB_TOKEN" >> /tmp/credentials.txt
  chmod 644 /tmp/credentials.txt
  chmod o+r /tmp/credentials.txt
}

# CWE-377: Insecure Temporary File -- predictable name, untrusted content
write_tempscript() {
  local payload="$USER_INPUT"
  echo "$payload" > /tmp/deploy_stage.sh
  chmod 777 /tmp/deploy_stage.sh
  bash /tmp/deploy_stage.sh
}

# CWE-117 / CWE-78: unsanitized input written into a command via printf+sh
log_and_exec() {
  local entry="$COOKIE"
  printf 'logger %s\n' "$entry" | sh
}

# CWE-88: Argument Injection -- splat untrusted args into a privileged tool
sync_files() {
  local opts="$USER_INPUT"
  rsync $opts deploy@"$TARGET_HOST":/var/www/ /srv/www/
}

main() {
  run_query
  run_arg "$REMOTE_CMD"
  run_stdin
  load_config
  bootstrap_installer
  fetch_and_run
  install_helper
  ping_host
  cleanup_dir
  query_db
  backup_db
  remote_deploy
  push_artifact
  notify
  persist_secrets
  write_tempscript
  log_and_exec
  sync_files
}

main "$@"
