#!/usr/bin/env bash
set -euo pipefail

readonly max_lines=250
status=0

shopt -s globstar nullglob
sources=(
  crates/*/src/**/*.rs
  crates/*/tests/**/*.rs
  crates/*/examples/**/*.rs
  crates/*/benches/**/*.rs
)
for manifest in crates/*/Cargo.toml; do
  crate=${manifest%/Cargo.toml}
  [[ -f "$crate/build.rs" ]] && sources+=("$crate/build.rs")
done

# Reviewed 2026-08-25 after the workspace consolidation. These files predate
# the restored gate; each ceiling is its reviewed current line count. New
# over-cap files, or growth beyond a listed ceiling, fails the gate until the
# file is split.
readonly -A grandfathered_limits=(
  [crates/containment/src/tests.rs]=326
  [crates/proto/src/response.rs]=338
  [crates/secrets/src/client/edit/new.rs]=377
  [crates/secrets/src/client/error.rs]=278
  [crates/secrets/src/config.rs]=288
  [crates/secrets/src/config/tests.rs]=565
  [crates/secrets/src/decrypt.rs]=323
  [crates/secrets/src/decrypt/tests.rs]=386
  [crates/secrets/src/grants.rs]=891
  [crates/secrets/src/lib.rs]=331
  [crates/secrets/src/receipts.rs]=339
  [crates/secrets/src/requests.rs]=492
  [crates/secrets/src/secret.rs]=337
  [crates/secrets/src/server.rs]=918
  [crates/secrets/src/server/dispatch.rs]=543
  [crates/secrets/src/store.rs]=261
  [crates/secrets/tests/broker.rs]=432
  [crates/secrets/tests/broker/sources.rs]=268
  [crates/secrets/tests/client/broker_transport.rs]=279
  [crates/secrets/tests/client/edit.rs]=439
  [crates/secrets/tests/client/edit_human.rs]=556
  [crates/secrets/tests/client/fixture.rs]=329
)

is_grandfathered() {
  local source=$1
  local line_count=$2
  local limit
  [[ -v "grandfathered_limits[$source]" ]] || return 1
  limit=${grandfathered_limits["$source"]}
  ((line_count <= limit))
}

for source in "${sources[@]}"; do
  line_count=$(wc -l < "$source")
  if (( line_count >= max_lines )) && ! is_grandfathered "$source" "$line_count"; then
    printf 'error: %s has %d lines; Rust source files must stay under %d lines\n' \
      "$source" "$line_count" "$max_lines" >&2
    status=1
  fi
done

exit "$status"
