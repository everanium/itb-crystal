#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Crystal binding.
# Builds libitb.so + the eitb binary via build.sh, then runs the spec
# suite under the Crystal compiler.
#
# Usage:
#   ./run_tests.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

crystal spec
