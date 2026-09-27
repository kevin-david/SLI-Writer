#!/usr/bin/env bash
set -euo pipefail

CC="${CC:-clang}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building and running SLI-Writer host regression test suite..."
"$CC" -Wall -Wextra -Werror "$REPO_ROOT/tests/test_gen3_regression.c" -o "$REPO_ROOT/tests/test_gen3_regression"
"$REPO_ROOT/tests/test_gen3_regression"
rm -f "$REPO_ROOT/tests/test_gen3_regression"
