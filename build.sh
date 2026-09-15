#!/usr/bin/env bash
#
# build.sh -- one-step build for the Crystal binding: (re)builds
# libitb3.so if absent (or when ITB_REBUILD_LIBITB3=1), then compiles
# the eitb CLI binary. Prerequisites (Go, Crystal) must be installed
# separately; see README.md "Prerequisites".
#
# Every artefact this binding owns is removed first, so nothing the
# build produces can be a leftover from an earlier invocation.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels
#                          # (use on hosts without AVX-512+VL)
#   ITB_SKIP_CLEAN=1 ./build.sh   # keep existing artefacts

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# ---- Clean ----------------------------------------------------------
# Artefacts this binding owns. The Go shared library under
# dist/linux-amd64/ is shared by every binding and stays untouched.
# eitb/ itself is out of scope: eitb/eitb is a committed launcher
# script, and the binary it starts lives in bin/. shard.yml declares
# no dependencies, so the shard trees below hold nothing that needs
# re-fetching; shard.lock is left in place as resolution state rather
# than build output.
CLEAN_TARGETS=(
    bin                   # eitb + bench binaries
    .crystal              # compiler cache
    lib                   # installed shard tree
    .shards               # shard metadata tree
)

clean_artefacts() {
    local rel abs tracked

    # A build artefact is never tracked, so a hit here means the list
    # above is wrong. Abort rather than delete a source file.
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        tracked="$(git ls-files -- "${CLEAN_TARGETS[@]}")"
        if [ -n "$tracked" ]; then
            echo "clean: tracked files inside the clean scope:" >&2
            printf '%s\n' "$tracked" | sed 's/^/    /' >&2
            exit 1
        fi
    fi

    for rel in "${CLEAN_TARGETS[@]}"; do
        abs="$(readlink -m -- "$SCRIPT_DIR/$rel")"
        case "$abs" in
            "$SCRIPT_DIR"/?*) ;;
            *) echo "clean: '$rel' escapes $SCRIPT_DIR ($abs)" >&2; exit 1;;
        esac
        [ -e "$abs" ] || continue
        echo "[clean] rm -rf $abs"
        rm -rf -- "$abs"
    done
}

if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing artefacts"
else
    echo "==> cleaning previous artefacts"
    clean_artefacts
fi

if [[ ! -f "$DIST_DIR/libitb3.so" || "${ITB_REBUILD_LIBITB3:-0}" == "1" || ${#TAGS[@]} -gt 0 ]]; then
    echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
    (cd "$REPO_ROOT" && go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
        -o dist/linux-amd64/libitb3.so ./cmd/cshared)
else
    echo "==> libitb3.so present; skipping Go rebuild (set ITB_REBUILD_LIBITB3=1 to force)"
fi

echo "==> compiling the eitb CLI (crystal build)"
mkdir -p bin
crystal build -o bin/eitb eitb/itb_eitb.cr

echo "==> ready: ./run_tests.sh"
