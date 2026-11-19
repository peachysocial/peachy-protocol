#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Build `peachy-mls-cabi` for the three Apple slices Peachy needs and assemble
# them into `build/PeachyMLSCore.xcframework`, plus the host archive that
# `swift test` links (see Package.swift for why those are two different
# things).
#
# Everything it writes lands under `mls/swift/build/`, which is gitignored —
# the repo's rule is that a build product goes under `build/`, and cargo's own
# `mls/target/` is the one standing exception (docs/mls-core.md §What exists) —
# or, when `$CARGO_TARGET_DIR` is set, cargo writes there instead.
#
#   ./build-xcframework.sh          builds everything and prints the sizes
#   ./build-xcframework.sh --host   host archive only, for a quick `swift test`
#   ./build-xcframework.sh --development-keys
#                                   the same, with the `development` server
#                                   keys in the app slices: local and e2e
#                                   builds only, never a release
#
# rustup's `~/.cargo/bin` is not always on PATH in a non-interactive shell, so
# the script puts it there itself rather than failing with
# "cargo: command not found".

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd "$here/.." && pwd)"
build="$here/build"

# Where cargo writes: $CARGO_TARGET_DIR when one is set, else mls/target.
target_dir="${CARGO_TARGET_DIR:-$workspace/target}"

export PATH="$HOME/.cargo/bin:$PATH"

# THE APP'S GRDB RUNS ON THIS ARCHIVE'S SQLCIPHER, not on the system SQLite.
#
# GRDB (the chat cache, the plaintext archive) calls sqlite3_* and links the
# system libsqlite3, but the linker takes each symbol from the first definition
# it loads, and the SQLCipher object inside libpeachy_mls_cabi.a is loaded
# because the MLS store needs it. So every sqlite3_* call GRDB makes lands
# here — which is what lets the Apple clients encrypt those databases with a
# `PRAGMA key` and no second copy of SQLCipher. GRDB is compiled with SQLITE_ENABLE_SNAPSHOT, so its
# sqlite3_snapshot_* calls need definitions here too; without this flag they
# alone fell through to the system library, which was being handed a
# connection from a different SQLite. `check_sqlcipher_slice` below holds it.
#
# Set here and not in a cargo config: it is Apple's concern alone, and every
# Apple build of the archive runs this script.
export LIBSQLITE3_FLAGS="-DSQLITE_ENABLE_SNAPSHOT"

# ONE DEPLOYMENT TARGET for the C and the Rust halves of each slice — the ones
# the link checks below build for. Unset, `cc` compiles SQLCipher for the SDK's
# own version while rustc links the cdylib for iOS 10.0, and SQLCipher's large
# stack frames then need `___chkstk_darwin`, which iOS 10's libSystem does not
# have: the iOS slices stopped linking the day SQLCipher replaced SQLite.
export IPHONEOS_DEPLOYMENT_TARGET=17.0
export MACOSX_DEPLOYMENT_TARGET=14.0

# Refuse an archive that is not SQLCipher, or lacks what GRDB calls.
check_sqlcipher_slice() {
  local archive="$1" symbols
  symbols="$(nm -g --defined-only "$archive" 2>/dev/null || true)"
  for symbol in _sqlite3_key _sqlite3_open_v2 _sqlite3_snapshot_get _sqlite3_snapshot_open \
    _sqlite3_snapshot_free _sqlite3_snapshot_cmp; do
    if ! grep -q " T $symbol\$" <<<"$symbols"; then
      echo "$archive does not define $symbol — GRDB would fall through to the system SQLite" >&2
      exit 1
    fi
  done
}

host_only=0
# The shipping slices carry no `development` server keys unless asked: that
# set's seed is public (mls/core/src/server_key_pins.rs). Builds for local
# development and e2e pass `--development-keys`; a release build never does.
slice_features=()
for arg in "$@"; do
  case "$arg" in
    --host) host_only=1 ;;
    --development-keys) slice_features=(--features development-keys) ;;
    *)
      echo "unknown argument: $arg (expected --host or --development-keys)" >&2
      exit 2
      ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is not on PATH (looked in \$HOME/.cargo/bin too)." >&2
  exit 1
fi

# The pinned toolchain, read from the file rather than written down twice.
toolchain="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$workspace/rust-toolchain.toml")"
if [[ -z "$toolchain" ]]; then
  echo "could not read the channel from $workspace/rust-toolchain.toml" >&2
  exit 1
fi
echo "toolchain: $toolchain"

# `rust-toolchain.toml` deliberately lists no targets — a Linux build would
# otherwise download two Apple standard libraries it never links — so the Apple
# ones are added here, on the machine that actually needs them. `rustup target
# add` is idempotent and quiet when the target is already installed.
device_targets=(aarch64-apple-ios aarch64-apple-ios-sim)
host_target=aarch64-apple-darwin
for target in "${device_targets[@]}" "$host_target"; do
  rustup target add --toolchain "$toolchain" "$target" >/dev/null
done

lib=libpeachy_mls_cabi.a
rm -rf "$build"
mkdir -p "$build"

# ---------------------------------------------------------------------------
# 1. The shipping slices: release, NO features. A release app must not carry
#    code that can mint a device credential, nor the `development` server
#    keys. `--development-keys` adds only the latter, for a local or e2e build.
# ---------------------------------------------------------------------------
if [[ "$host_only" -eq 0 ]]; then
  for target in "${device_targets[@]}" "$host_target"; do
    echo "building $target (release, ${slice_features[1]:-no features})"
    (cd "$workspace" && cargo build --release -p peachy-mls-cabi ${slice_features[@]+"${slice_features[@]}"} --target "$target")
    mkdir -p "$build/slices/$target"
    cp "$target_dir/$target/release/$lib" "$build/slices/$target/$lib"
    check_sqlcipher_slice "$build/slices/$target/$lib"
  done

  # The headers directory each slice points at. One copy, shared by all three:
  # the ABI does not vary by platform, and three copies would be three chances
  # for one of them to be the stale one.
  #
  # `-L` on cp, so the symlinked header is copied as a FILE — an xcframework
  # carrying a relative symlink out of its own directory is a link to nothing
  # the moment it is copied anywhere.
  mkdir -p "$build/Headers"
  cp -L "$here/Sources/PeachyMLSCore/include/peachy_mls.h" "$build/Headers/peachy_mls.h"
  # A module map so `import PeachyMLSCore` works against the xcframework the
  # same way it works against the system-library target. `link` names the
  # archive here, because inside an xcframework there is exactly one right
  # answer and the consumer should not have to spell it.
  cat >"$build/Headers/module.modulemap" <<'MODULEMAP'
module PeachyMLSCore {
  header "peachy_mls.h"
  link framework "Security"
  export *
}
MODULEMAP

  echo "assembling the xcframework"
  args=()
  for target in "${device_targets[@]}" "$host_target"; do
    args+=(-library "$build/slices/$target/$lib" -headers "$build/Headers")
  done
  xcodebuild -create-xcframework "${args[@]}" \
    -output "$build/PeachyMLSCore.xcframework" >"$build/create-xcframework.log" 2>&1 ||
    {
      echo "xcodebuild -create-xcframework failed:" >&2
      cat "$build/create-xcframework.log" >&2
      exit 1
    }

  # -------------------------------------------------------------------------
  # Every slice must actually LINK the wrapper, not merely exist.
  #
  # This is the one thing `swift test` cannot tell us. It runs on the host
  # only, so an iOS-specific break — a missing symbol in a cross-compiled
  # archive, a header that says something clang accepts on macOS and not on
  # iOS — would sail past a green suite and surface in Xcode, in whatever app
  # first tried to adopt this. Building the wrapper against each slice's own
  # header and linking against that slice's own archive costs a couple of
  # seconds and answers it here.
  # -------------------------------------------------------------------------
  probe="$build/link-check"
  mkdir -p "$probe"
  cat >"$probe/main.swift" <<'PROBE'
import Foundation

// Touches the class, both throwing initializers and a static — enough that the
// linker has to resolve the entry points rather than dead-strip them all.
//
// Both initializers, because they call different C symbols:
// `peachy_mls_client_new` and `peachy_mls_client_open`. A slice whose archive
// is missing the newer one would link fine against the older probe and fail in
// whatever app first tried to persist anything.
let ephemeral = try? MLSClient(
    credential: Data(),
    signatureSeed: Data(repeating: 0, count: 32),
    trustedKeysJSON: "{}",
    storePath: nil
)
let persistent = try? MLSClient(
    credential: Data(),
    signatureSeed: Data(repeating: 0, count: 32),
    trustedKeysJSON: "{}",
    storeURL: MLSClient.storeURL(forDevice: "probe", in: FileManager.default.temporaryDirectory)
)
print(MLSClient.coreVersion, ephemeral == nil, persistent == nil)
PROBE

  link_check() {
    local slice="$1" sdk="$2" triple="$3"
    local headers="$build/PeachyMLSCore.xcframework/$slice/Headers"
    echo "link check: $slice"
    xcrun --sdk "$sdk" swiftc \
      -target "$triple" \
      -o "$probe/$slice.out" \
      -Xcc "-fmodule-map-file=$headers/module.modulemap" \
      -I "$headers" \
      -L "$build/PeachyMLSCore.xcframework/$slice" \
      -lpeachy_mls_cabi \
      "$here/Sources/PeachyMLS/"*.swift \
      "$probe/main.swift" >"$probe/$slice.log" 2>&1 ||
      {
        echo "the $slice slice did not link:" >&2
        cat "$probe/$slice.log" >&2
        exit 1
      }
  }

  link_check ios-arm64 iphoneos arm64-apple-ios17.0
  link_check ios-arm64-simulator iphonesimulator arm64-apple-ios17.0-simulator
  link_check macos-arm64 macosx arm64-apple-macos14.0
fi

# ---------------------------------------------------------------------------
# 2. The host archive `swift test` links: same target as the macOS slice, but
#    WITH the two test-only features, so the suite can reach through the C door
#    instead of re-implementing anything in Swift.
#
#      - `test-issuer` mints a `pdc1` credential, rather than a second
#        implementation of the token format (`docs/identity.md` §Format).
#      - `fixture` evaluates one case of `mls/fixtures/rules.json`, rather than
#        a second implementation of the group policy. `RulesFixtureTests`
#        replays all 53 cases through it; without the feature the symbol is not
#        in the archive and the test target does not link.
#
#    Neither reaches the xcframework above, which is the whole point of them
#    being features: a shipped app carries no issuer and no test harness.
#
#    This build overwrites `target/aarch64-apple-darwin/release/` — hence the
#    order: the xcframework's copy is already taken by the time we get here.
# ---------------------------------------------------------------------------
echo "building $host_target (release, test-issuer + fixture + development-keys + insecure-plaintext-store) for swift test"
(cd "$workspace" && cargo build --release -p peachy-mls-cabi --features test-issuer,fixture,development-keys,insecure-plaintext-store --target "$host_target")
mkdir -p "$build/host"
cp "$target_dir/$host_target/release/$lib" "$build/host/$lib"
check_sqlcipher_slice "$build/host/$lib"

# ---------------------------------------------------------------------------
# Sizes. The static archive is mostly rlib metadata and objects the app linker
# drops, so the number that matters to an app's download size is not here —
# docs/mls-core.md §Cross-compiling measures the stripped dylib for that. What
# these numbers are good for is noticing a slice that did not build, or one
# that suddenly grew by a multiple.
# ---------------------------------------------------------------------------
echo
echo "sizes"
# -s, because the xcframework is a directory and `du` without it prints a line
# per subdirectory — which looked, in the first run of this script, exactly
# like the sizes of slices that do not exist.
size_of() { du -sh "$1" | cut -f1 | tr -d ' '; }
if [[ "$host_only" -eq 0 ]]; then
  for target in "${device_targets[@]}" "$host_target"; do
    printf '  %-26s %s\n' "$target" "$(size_of "$build/slices/$target/$lib")"
  done
  printf '  %-26s %s\n' "PeachyMLSCore.xcframework" "$(size_of "$build/PeachyMLSCore.xcframework")"
fi
printf '  %-26s %s\n' "host (test features)" "$(size_of "$build/host/$lib")"
echo
echo "built into $build"
