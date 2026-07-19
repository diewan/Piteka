#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
run_dir="$repo_dir/.diewan/run"
pid_file="$run_dir/piteka.pid"
log_file="$run_dir/piteka.log"
url="${PITEKA_URL:-http://127.0.0.1:3000}"

mkdir -p "$run_dir"
if [[ -f "$pid_file" ]] && kill -0 "$(<"$pid_file")" 2>/dev/null; then
  echo "Piteka is already running (PID $(<"$pid_file"), $url)."
  exit 0
fi
rm -f "$pid_file"

command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
(cd "$repo_dir" && nohup setsid cargo run -p piteka-web >>"$log_file" 2>&1 & echo $! >"$pid_file")

for _ in {1..120}; do
  if curl --fail --silent "$url/health" >/dev/null 2>&1; then
    echo "Piteka is ready at $url (log: $log_file)."
    exit 0
  fi
  if ! kill -0 "$(<"$pid_file")" 2>/dev/null; then
    echo "Piteka exited during startup; inspect $log_file" >&2
    exit 1
  fi
  sleep 1
done
echo "Piteka did not become healthy; inspect $log_file" >&2
exit 1
