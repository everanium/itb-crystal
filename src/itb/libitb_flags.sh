#!/bin/sh
#
# libitb_flags.sh -- emits the linker flags that resolve libitb for the
# Crystal binding. Executed by the compiler through the backtick form
# in the @[Link(ldflags: ...)] annotation of src/itb/ffi_bridge.cr.
#
# Search order:
#   1. ITB_LIBITB_PATH environment variable (path to the shared
#      library file).
#   2. <repo>/dist/<os>-<arch>/libitb.<ext> resolved by walking up
#      from this script's directory (in-repo builds).
#   3. The OS default loader path (-litb only).
#
# The resolved directory is baked into the binary as an RPATH so the
# produced executables run without LD_LIBRARY_PATH.

set -eu

emit() {
    printf '%s' "-L$1 -Wl,-rpath,$1 -litb"
}

if [ -n "${ITB_LIBITB_PATH:-}" ] && [ -f "$ITB_LIBITB_PATH" ]; then
    emit "$(CDPATH= cd -- "$(dirname -- "$ITB_LIBITB_PATH")" && pwd)"
    exit 0
fi

here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

case "$(uname -s)" in
    Darwin) os=darwin; ext=dylib ;;
    *)      os=linux;  ext=so ;;
esac
case "$(uname -m)" in
    x86_64)          arch=amd64 ;;
    aarch64|arm64)   arch=arm64 ;;
    *)               arch="$(uname -m)" ;;
esac

dist="$here/../../../../dist/$os-$arch"
if [ -f "$dist/libitb.$ext" ]; then
    emit "$(CDPATH= cd -- "$dist" && pwd)"
    exit 0
fi

printf '%s' "-litb"
