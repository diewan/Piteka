#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pid_file="$repo_dir/.diewan/run/piteka.pid"
if [[ ! -f "$pid_file" ]]; then echo "Piteka is not tracked as running."; exit 0; fi
pid="$(<"$pid_file")"
if kill -0 "$pid" 2>/dev/null; then
  kill -- "-$pid" 2>/dev/null || kill "$pid"
  for _ in {1..20}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  kill -0 "$pid" 2>/dev/null && { kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid"; }
fi
rm -f "$pid_file"
echo "Piteka stopped."
