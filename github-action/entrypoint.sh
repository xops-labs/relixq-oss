#!/bin/sh
# Copyright (c) 2026 Yasvanth Udayakumar
# SPDX-License-Identifier: Apache-2.0
#
# GitHub Action entrypoint for the Relix-Q PQC scanner. GitHub passes each
# action input as an INPUT_<NAME> environment variable (uppercased, dashes ->
# underscores). We translate them into a `relixq scan ...` invocation, write
# SARIF, and surface the output path. The job is failed only when --fail-on is
# set and a finding meets it; the SARIF is always produced and its path is
# always exported so a later upload-sarif step runs even on failure.
set -e

SCAN_TYPE="${INPUT_SCAN_TYPE:-code}"
SCAN_PATH="${INPUT_PATH:-.}"
TARGET="${INPUT_TARGET:-}"
FORMAT="${INPUT_FORMAT:-sarif}"
OUTPUT="${INPUT_OUTPUT:-relixq.sarif}"
SEVERITY="${INPUT_SEVERITY_THRESHOLD:-medium}"
FAIL_ON="${INPUT_FAIL_ON:-}"
BASELINE="${INPUT_BASELINE:-}"

case "$SCAN_TYPE" in
  code) set -- scan "$SCAN_PATH" ;;
  deps) set -- scan deps "$SCAN_PATH" ;;
  tls)
    if [ -z "$TARGET" ]; then
      echo "relixq-action: scan-type 'tls' requires the 'target' input" >&2
      exit 2
    fi
    # shellcheck disable=SC2086 # intentional word-split: allow multiple targets
    set -- scan tls $TARGET ;;
  *)
    echo "relixq-action: unknown scan-type '$SCAN_TYPE' (want code|deps|tls)" >&2
    exit 2 ;;
esac

set -- "$@" --format "$FORMAT" --output "$OUTPUT" --severity-threshold "$SEVERITY"
[ -n "$FAIL_ON" ] && set -- "$@" --exit-on "$FAIL_ON"
[ -n "$BASELINE" ] && set -- "$@" --baseline "$BASELINE"

echo "+ relixq $*" >&2
set +e
relixq "$@"
status=$?
set -e

# Always export the SARIF path so the workflow can upload it (and get PR
# annotations) even when --fail-on tripped a non-zero exit.
if [ -n "$GITHUB_OUTPUT" ]; then
  echo "sarif=$OUTPUT" >> "$GITHUB_OUTPUT"
fi
exit "$status"
