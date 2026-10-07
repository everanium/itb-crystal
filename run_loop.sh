#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Crystal binding:
# rebuilds the utility when a source is newer than the binary (a no-op
# otherwise; libitb3.so is assumed built by build.sh) and execs it with
# every argument passed through.
#
# The compiler output is captured rather than discarded: Crystal
# reports warnings and deprecations on stderr, and a redirect of stdout
# alone would let its lines join the utility's own output. Nothing is
# printed unless the build fails, in which case everything it said is.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

stale=0
if [ ! -x loop/loop ]; then
    stale=1
else
    for src in loop/*.cr src/libitb3.cr src/itb/*.cr; do
        if [ "$src" -nt loop/loop ]; then
            stale=1
            break
        fi
    done
fi

if [ "$stale" = 1 ]; then
    if ! build_output="$(crystal build -o loop/loop loop/main.cr 2>&1)"; then
        printf '%s\n' "$build_output" >&2
        exit 1
    fi
fi

exec ./loop/loop "$@"
