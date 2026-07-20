#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pid_file="$repo_dir/.diewan/run/piteka.pid"
pid=""
if [[ -f "$pid_file" ]]; then pid="$(<"$pid_file")"; fi

if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
  listener_pid="$(ss -ltnp 'sport = :3000' 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1)"
  if [[ -n "$listener_pid" ]] && [[ "$(readlink -f "/proc/$listener_pid/exe" 2>/dev/null || true)" == "$repo_dir/target/debug/piteka-web" ]]; then
    pid="$listener_pid"
  fi
fi

if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
  process_group="$(ps -o pgid= -p "$pid" | tr -d ' ')"
  if [[ -n "$process_group" ]]; then kill -- "-$process_group" 2>/dev/null || kill "$pid"; else kill "$pid"; fi
  for _ in {1..20}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  kill -0 "$pid" 2>/dev/null && kill -KILL "$pid"
fi

# `setsid` gives the web binary its own process group, so validate and stop the
# listener separately from the tracked Cargo launcher.
listener_pid="$(ss -ltnp 'sport = :3000' 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1)"
if [[ -n "$listener_pid" ]] && [[ "$(readlink -f "/proc/$listener_pid/exe" 2>/dev/null || true)" == "$repo_dir/target/debug/piteka-web" ]]; then
  kill -- "-$listener_pid" 2>/dev/null || kill "$listener_pid"
  for _ in {1..20}; do kill -0 "$listener_pid" 2>/dev/null || break; sleep 0.25; done
  kill -0 "$listener_pid" 2>/dev/null && kill -KILL "$listener_pid"
fi
rm -f "$pid_file"
echo "Piteka stopped."
