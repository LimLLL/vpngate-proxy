#!/usr/bin/env bash
# Runs the real proxy against public VPNGate nodes and checks the username
# contract end to end. CI only: it needs root, TUN and public VPNGate access.
set -euo pipefail

binary=${1:?usage: live_proxy_check.sh <vpngate-proxy binary>}
work=${RUNNER_TEMP:?}/live-proxy
port=17928
user=live
password=live-check-password
mkdir -p "${work}/data"
# tun_base keeps clear of the tun0 used by the earlier probe steps.
cat > "${work}/data/config.json" <<CONFIG
{"username": "${user}", "password": "${password}", "proxy_host": "127.0.0.1",
 "proxy_port": ${port}, "tun_base": 100}
CONFIG

"${binary}" --data-dir "${work}/data" > "${work}/proxy.log" 2>&1 &
proxy_pid=$!
cleanup() {
  local status=$?
  trap - EXIT
  kill -TERM "${proxy_pid}" 2>/dev/null || true
  timeout 30 tail --pid="${proxy_pid}" -f /dev/null || kill -KILL "${proxy_pid}" 2>/dev/null || true
  printf '\n----- proxy log -----\n'
  cat "${work}/proxy.log"
  exit "${status}"
}
trap cleanup EXIT

summary() {
  printf '%s\n' "$*"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$*" >> "${GITHUB_STEP_SUMMARY}"
  fi
}

# egress <username> prints the public IP seen through the proxy, or nothing.
# Each request may connect a node first, trying another when one fails.
egress() {
  curl --silent --max-time 100 --proxy "http://$1:${password}@127.0.0.1:${port}" \
    https://api.ipify.org 2>/dev/null || true
}

country_of() {
  curl --silent --max-time 30 --proxy "http://$1:${password}@127.0.0.1:${port}" \
    'http://ip-api.com/line/?fields=countryCode' 2>/dev/null || true
}

# fail writes to stderr because check() runs with stdout captured.
fail() {
  summary "**FAILED:** $*" >&2
  exit 1
}

direct=$(curl --silent --max-time 15 https://api.ipify.org)
summary "## Live proxy check" "" "Runner IP: \`${direct}\`" ""

first=""
for attempt in $(seq 1 8); do
  first=$(egress "${user}")
  [[ -n "${first}" ]] && break
  sleep 10
done
[[ -n "${first}" ]] || fail "no tunnel came up after 8 attempts"

summary "| Username | Egress IP |" "| --- | --- |"
# check prints the egress IP and fails on a missing or direct egress. It runs
# in a command substitution, so always assign its output to a variable: set -e
# then stops the script when it fails.
check() {
  local username=$1 ip
  ip=$(egress "${username}")
  summary "| \`${username}\` | \`${ip:-none}\` |" >&2
  [[ -n "${ip}" ]] || fail "${username} got no egress"
  [[ "${ip}" != "${direct}" ]] || fail "${username} left through the runner itself"
  printf '%s' "${ip}"
}

rotating=()
for _ in 1 2 3 4 5; do
  ip=$(check "${user}")
  rotating+=("${ip}")
done
sticky=$(check "${user}-session-s1-t-1")
again=$(check "${user}-session-s1-t-1")
[[ "${again}" == "${sticky}" ]] || fail "session s1 changed IP before its TTL"
other=$(check "${user}-session-s2-t-1")
[[ "${other}" != "${sticky}" ]] || fail "sessions s1 and s2 share ${sticky}"
japan=$(check "${user}-country-jp-session-jp1")
japan_code=$(country_of "${user}-country-jp-session-jp1")

summary "" "Waiting 65 s for the one-minute TTL of s1 to expire..."
sleep 65
rotated=$(check "${user}-session-s1-t-1")
[[ "${rotated}" != "${sticky}" ]] || fail "session s1 kept ${sticky} after its TTL"

distinct=$(printf '%s\n' "${rotating[@]}" | sort -u | wc -l)
summary "" "- Rotating requests used ${distinct} distinct IPs out of ${#rotating[@]}."
(( distinct >= 2 )) || fail "rotating requests all left through ${rotating[0]}"
summary "- \`country-jp\` egress ${japan} geolocates to \`${japan_code:-unknown}\` (ip-api; informational)."
summary "- Sticky, distinct-session and TTL rotation checks passed."
