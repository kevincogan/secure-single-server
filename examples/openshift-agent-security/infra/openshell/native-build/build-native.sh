#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

test "$(rustc --version | cut -d ' ' -f 2)" = '1.95.0'
printf '%s  Cargo.lock\n' "$OPENSHELL_DEMO_CARGO_LOCK_SHA256" | sha256sum -c -

case "${1:-}" in
  fetch)
    cargo fetch --locked --target x86_64-unknown-linux-gnu
    ;;
  compile)
    # The caller runs this phase with networking disabled and no credential mounts.
    cargo auditable build --frozen --target x86_64-unknown-linux-gnu --release \
      -p openshell-gateway -p openshell-supervisor
    printf '%s  Cargo.lock\n' "$OPENSHELL_DEMO_CARGO_LOCK_SHA256" | sha256sum -c -
    cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/openshell-gateway" /work/output/openshell-gateway
    cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/openshell-supervisor" /work/output/openshell-supervisor
    cp /usr/local/share/identity-build-packages.txt /work/output/builder-packages.txt
    ;;
  *)
    echo 'Expected fetch or compile' >&2
    exit 2
    ;;
esac
