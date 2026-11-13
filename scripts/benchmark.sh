#!/usr/bin/env bash
# Compares the embedded OpenVPN 3 Core with the OpenVPN 2.x CLI on the CI
# testbed. Every tunnel count runs both engines, each against a fresh server,
# alternating which engine goes first. CI only (root, TUN).
set -euo pipefail

counts=${1:?usage: benchmark.sh <counts such as 1,16,64> <bench binary> <report dir>}
bench=${2:?bench binary required}
reports=${3:?report directory required}
root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "${root_dir}/scripts/testbed.sh"
trap testbed_cleanup EXIT

IFS=, read -ra list <<< "${counts// /}"
for count in "${list[@]}"; do
  if ! [[ "${count}" =~ ^[0-9]+$ ]] || ((count < 1 || count > 128)); then
    printf 'tunnel counts must be 1-128, got %q\n' "${count}" >&2
    exit 2
  fi
done

mkdir -p "${reports}"
testbed_init "${RUNNER_TEMP:?}/bench" "${root_dir}/go_backend"
status=0
round=0
for count in "${list[@]}"; do
  profiles=${TB_WORK}/profiles-${count}
  testbed_profiles "${count}" "${profiles}"
  engines=(core cli)
  if ((round % 2 == 1)); then
    engines=(cli core)
  fi
  for engine in "${engines[@]}"; do
    testbed_start $((count + 8))
    "${bench}" --engine "${engine}" --profiles "${profiles}/*.ovpn" --target "${TB_TARGET}" \
      --report "${reports}/${engine}-${count}.json" || status=1
    testbed_stop
  done
  round=$((round + 1))
done

# first <engine> <jq filter> applies the filter to any one report of engine.
first() {
  local report
  for report in "${reports}/$1"-*.json; do
    [[ -f "${report}" ]] && jq -r "$2" "${report}" && return
  done
  printf '?'
}

{
  printf '## Engine benchmark\n\n'
  printf '| Tunnels | Engine | Connected / traffic / stopped | Ready wall ms | Median / max connect ms | Max stop ms | Processes | Threads | PSS MiB | RSS MiB | CPU ms |\n'
  printf '| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
  for count in "${list[@]}"; do
    for engine in core cli; do
      report=${reports}/${engine}-${count}.json
      if [[ ! -f "${report}" ]]; then
        printf '| %s | %s | no report | | | | | | | | |\n' "${count}" "${engine}"
        continue
      fi
      jq -r '"| \(.tunnels) | \(.engine) | \(.connected) / \(.traffic_ok) / \(.stopped) | \(.wall_ready_ms | round) | \(.median_connect_ms | round) / \(.max_connect_ms | round) | \(.max_stop_ms | round) | \(.processes) | \(.threads) | \(.pss_kb / 1024 * 10 | round / 10) | \(.rss_kb / 1024 * 10 | round / 10) | \(.cpu_ms | round) |"' "${report}"
    done
  done
  printf '\nCore rows are the whole benchmark process, including the Go controller (%s MiB before any tunnel). ' \
    "$(first core '.baseline_rss_kb / 1024 * 10 | round / 10')"
  printf 'CLI rows sum the openvpn processes. PSS splits shared pages between processes; RSS counts them once per process. '
  printf 'Versions: %s / %s.\n' "$(first core .version)" "$(first cli .version)"
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
exit "${status}"
