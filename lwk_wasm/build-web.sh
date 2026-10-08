#!/usr/bin/env bash
# Builds the browser package of the kit (`wasm-pack build --target web
# --release`) with every build-machine path remapped, so the .wasm carries
# no home directory, checkout path or cargo cache path in its panic
# locations, and two builds of one commit on two machines agree.
#
#   lwk_wasm/build-web.sh [out-dir] [extra wasm-pack args...]
#
# out-dir defaults to pkg. Set CARGO_PROFILE_RELEASE_OPT_LEVEL=z for the
# smaller build the browser extension ships. Needs clang with a wasm32
# backend (set CC_wasm32_unknown_unknown and AR_wasm32_unknown_unknown when
# it is not /usr/bin/clang).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
out="${1:-pkg}"
shift || true
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
flags=(
  "--remap-path-prefix=$repo=/swk"
  "--remap-path-prefix=$cargo_home/registry/src=/cargo/registry"
  "--remap-path-prefix=$cargo_home/git/checkouts=/cargo/git"
  "--remap-path-prefix=$rustup_home=/rustup"
)
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  flags+=("--remap-path-prefix=$CARGO_TARGET_DIR=/target")
fi
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${flags[*]}"
cd "$here"
wasm-pack build --target web --release --out-dir "$out" "$@"
# Fail rather than ship a package that still names this machine.
for p in "$HOME" "$repo" "$cargo_home"; do
  if grep -a -q -F "$p" "$out/lwk_wasm_bg.wasm"; then
    echo "error: $out/lwk_wasm_bg.wasm still contains $p" >&2
    exit 1
  fi
done
echo "built $out/lwk_wasm_bg.wasm ($(wc -c < "$out/lwk_wasm_bg.wasm") bytes, sha256 $(sha256sum "$out/lwk_wasm_bg.wasm" | cut -c1-16)…), no build-machine path"
