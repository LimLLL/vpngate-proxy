#!/usr/bin/env bash
# Native session integration tests run only on a disposable Linux CI runner.
set -euo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=${RUNNER_TEMP:?}/go-session-test
namespace=vpg-session-$$
mkdir -p "${work}/private" "${work}/profiles"
chmod 700 "${work}" "${work}/private"

server_pid=
http_pid=
echo_pid=
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  for pid in "${echo_pid}" "${http_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]]; then
      kill -TERM "${pid}" 2>/dev/null || true
    fi
  done
  for pid in "${echo_pid}" "${http_pid}" "${server_pid}"; do
    if [[ -n "${pid}" ]]; then
      timeout 15 tail --pid="${pid}" -f /dev/null || kill -KILL "${pid}" 2>/dev/null || true
    fi
  done
  ip netns del "${namespace}" 2>/dev/null || true
  if [[ ${status} -ne 0 && -f "${work}/server.log" ]]; then
    cat "${work}/server.log"
  fi
  if [[ -f "${RUNNER_TEMP:-/tmp}/go-session-report.json" ]]; then
    cat "${RUNNER_TEMP}/go-session-report.json"
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=vpngate-session-ca' \
  -keyout "${work}/private/ca.key" -out "${work}/private/ca.crt"
openssl req -newkey rsa:2048 -nodes \
  -subj '/CN=vpngate-session-server' \
  -keyout "${work}/private/server.key" -out "${work}/server.csr"
openssl x509 -req -in "${work}/server.csr" \
  -CA "${work}/private/ca.crt" -CAkey "${work}/private/ca.key" -CAcreateserial -days 1 \
  -extfile <(printf 'extendedKeyUsage=serverAuth\nsubjectAltName=IP:192.0.2.2\n') \
  -out "${work}/private/server.crt"

(
  cd "${root_dir}/go_backend"
  CGO_ENABLED=0 go build -o "${work}/testauth" ./cmd/testauth
  CGO_ENABLED=0 go build -o "${work}/testserver" ./cmd/testserver
)
openvpn --genkey secret "${work}/private/tls.key"

for index in 0 1 2 3; do
  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=session-client-${index}" \
    -keyout "${work}/private/client${index}.key" -out "${work}/client${index}.csr"
  openssl x509 -req -in "${work}/client${index}.csr" \
    -CA "${work}/private/ca.crt" -CAkey "${work}/private/ca.key" -CAcreateserial -days 1 \
    -out "${work}/private/client${index}.crt"
done

cat > "${work}/server.conf" <<CONFIG
local 192.0.2.2
port 11940
proto udp
dev tun10
topology subnet
server 10.66.0.0 255.255.255.0
dh none
ca ${work}/private/ca.crt
cert ${work}/private/server.crt
key ${work}/private/server.key
tls-crypt ${work}/private/tls.key
script-security 2
auth-user-pass-verify ${work}/testauth via-file
max-clients 16
keepalive 10 120
persist-tun
verb 3
log-append ${work}/server.log
CONFIG

readonly link_host=vpg-h-$$
readonly link_server=vpg-s-$$
ip netns add "${namespace}"
ip link add "${link_host}" type veth peer name "${link_server}"
ip link set "${link_server}" netns "${namespace}"
ip address add 192.0.2.1/30 dev "${link_host}"
ip link set "${link_host}" up
ip netns exec "${namespace}" ip link set lo up
ip netns exec "${namespace}" ip address add 192.0.2.2/30 dev "${link_server}"
ip netns exec "${namespace}" ip link set "${link_server}" up

ip netns exec "${namespace}" openvpn --config "${work}/server.conf" \
  > "${work}/server-console.log" 2>&1 &
server_pid=$!
ready=false
for attempt in $(seq 1 120); do
  if grep -q 'Initialization Sequence Completed' "${work}/server.log" 2>/dev/null; then
    ready=true
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    printf 'OpenVPN test server exited unexpectedly\n'
    exit 1
  fi
  sleep 0.1
done
if ! "${ready}"; then
  printf 'OpenVPN test server did not initialize within 12 seconds\n'
  exit 1
fi

ip netns exec "${namespace}" "${work}/testserver" \
  --listen 10.66.0.1:18080 --mode http --ready-file "${work}/http.ready" &
http_pid=$!
ip netns exec "${namespace}" "${work}/testserver" \
  --listen 10.66.0.1:18081 --mode raw --ready-file "${work}/raw.ready" &
echo_pid=$!
for attempt in $(seq 1 100); do
  if [[ -f "${work}/http.ready" && -f "${work}/raw.ready" ]]; then
    break
  fi
  kill -0 "${http_pid}"
  kill -0 "${echo_pid}"
  sleep 0.1
done
[[ -f "${work}/http.ready" && -f "${work}/raw.ready" ]]
ip netns exec "${namespace}" curl --silent --show-error --fail \
  --max-time 5 http://10.66.0.1:18080/status

for index in 0 1 2 3; do
  {
    printf 'client\ndev tun%d\nproto udp\nremote 192.0.2.2 11940\n' "${index}"
    printf 'resolv-retry 2\nnobind\npersist-key\npersist-tun\n'
    printf 'auth-user-pass\nauth-nocache\nremote-cert-tls server\nroute-nopull\n'
    printf '<ca>\n'; cat "${work}/private/ca.crt"; printf '</ca>\n'
    printf '<cert>\n'; cat "${work}/private/client${index}.crt"; printf '</cert>\n'
    printf '<key>\n'; cat "${work}/private/client${index}.key"; printf '</key>\n'
    printf '<tls-crypt>\n'; cat "${work}/private/tls.key"; printf '</tls-crypt>\n'
  } > "${work}/profiles/session-${index}.ovpn"
done

(
  cd "${root_dir}/go_backend"
  go test -race -count=1 -timeout 240s ./gateway -run 'TestControlledSessionGateway$' -v
)
