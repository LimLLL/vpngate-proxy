#!/usr/bin/env bash
# Native session integration tests run only on a disposable Linux CI runner.
set -euo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "${root_dir}/scripts/testbed.sh"

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  testbed_cleanup
  if [[ ${status} -ne 0 && -f "${TB_WORK}/server.log" ]]; then
    cat "${TB_WORK}/server.log"
  fi
  if [[ -f "${RUNNER_TEMP:-/tmp}/go-session-report.json" ]]; then
    cat "${RUNNER_TEMP}/go-session-report.json"
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

testbed_init "${RUNNER_TEMP:?}/go-session-test" "${root_dir}/go_backend"
testbed_start 16
testbed_profiles 4 "${TB_WORK}/profiles"
(
  cd "${root_dir}/go_backend"
  go test -race -count=1 -timeout 240s ./gateway -run 'TestControlledSessionGateway$' -v
)
