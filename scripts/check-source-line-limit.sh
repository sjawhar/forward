#!/usr/bin/env bash
set -euo pipefail

readonly max_lines=250
status=0

shopt -s globstar nullglob
sources=(src/**/*.rs tests/**/*.rs examples/**/*.rs benches/**/*.rs)
if [[ -f build.rs ]]; then
  sources+=(build.rs)
fi

for source in "${sources[@]}"; do
  line_count=$(wc -l < "$source")
  if (( line_count >= max_lines )); then
    printf 'error: %s has %d lines; Rust source files must stay under %d lines\n' \
      "$source" "$line_count" "$max_lines" >&2
    status=1
  fi
done

exit "$status"
