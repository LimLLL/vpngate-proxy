# Shared CI testbed, sourced by test_session_gateway.sh and benchmark.sh: a
# disposable OpenVPN server in its own network namespace behind a veth pair,
# plus HTTP and TCP-echo endpoints that only a tunnel can reach. Root only.

TB_SERVER_IP=192.0.2.2
TB_PORT=11940
TB_TARGET=http://10.66.0.1:18080/status
TB_WORK=
TB_NS=
TB_SERVER_PID=
TB_HTTP_PID=
TB_ECHO_PID=

# testbed_init <work dir> <go_backend dir>: helper binaries, PKI and network.
testbed_init() {
  TB_WORK=$1
  local private=${TB_WORK}/private
  mkdir -p "${private}"
  chmod 700 "${TB_WORK}" "${private}"
  (
    cd "$2"
    CGO_ENABLED=0 go build -o "${TB_WORK}/testauth" ./cmd/testauth
    CGO_ENABLED=0 go build -o "${TB_WORK}/testserver" ./cmd/testserver
  )
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=vpngate-test-ca' \
    -keyout "${private}/ca.key" -out "${private}/ca.crt"
  openssl req -newkey rsa:2048 -nodes -subj '/CN=vpngate-test-server' \
    -keyout "${private}/server.key" -out "${TB_WORK}/server.csr"
  openssl x509 -req -in "${TB_WORK}/server.csr" -days 1 \
    -CA "${private}/ca.crt" -CAkey "${private}/ca.key" -CAcreateserial \
    -extfile <(printf 'extendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "${TB_SERVER_IP}") \
    -out "${private}/server.crt"
  # One client certificate for every tunnel; the server sets duplicate-cn.
  openssl req -newkey rsa:2048 -nodes -subj '/CN=vpngate-test-client' \
    -keyout "${private}/client.key" -out "${TB_WORK}/client.csr"
  openssl x509 -req -in "${TB_WORK}/client.csr" -days 1 \
    -CA "${private}/ca.crt" -CAkey "${private}/ca.key" -CAcreateserial \
    -out "${private}/client.crt"
  openvpn --genkey secret "${private}/tls.key"

  TB_NS=vpg-tb-$$
  ip netns add "${TB_NS}"
  ip link add "vpg-h-$$" type veth peer name "vpg-s-$$"
  ip link set "vpg-s-$$" netns "${TB_NS}"
  ip address add 192.0.2.1/30 dev "vpg-h-$$"
  ip link set "vpg-h-$$" up
  ip netns exec "${TB_NS}" ip link set lo up
  ip netns exec "${TB_NS}" ip address add "${TB_SERVER_IP}/30" dev "vpg-s-$$"
  ip netns exec "${TB_NS}" ip link set "vpg-s-$$" up
}

# testbed_start <max clients>: a fresh server and endpoints, so no client
# state carries over from a previous run.
testbed_start() {
  local private=${TB_WORK}/private attempt
  : > "${TB_WORK}/server.log"
  cat > "${TB_WORK}/server.conf" <<CONFIG
local ${TB_SERVER_IP}
port ${TB_PORT}
proto udp
dev tun10
topology subnet
server 10.66.0.0 255.255.255.0
dh none
ca ${private}/ca.crt
cert ${private}/server.crt
key ${private}/server.key
tls-crypt ${private}/tls.key
script-security 2
auth-user-pass-verify ${TB_WORK}/testauth via-file
duplicate-cn
max-clients $1
keepalive 10 120
persist-tun
verb 3
log-append ${TB_WORK}/server.log
CONFIG
  ip netns exec "${TB_NS}" openvpn --config "${TB_WORK}/server.conf" \
    >> "${TB_WORK}/server-console.log" 2>&1 &
  TB_SERVER_PID=$!
  for attempt in $(seq 1 120); do
    grep -q 'Initialization Sequence Completed' "${TB_WORK}/server.log" && break
    kill -0 "${TB_SERVER_PID}" 2>/dev/null || { printf 'OpenVPN test server exited\n' >&2; return 1; }
    sleep 0.1
  done
  grep -q 'Initialization Sequence Completed' "${TB_WORK}/server.log" ||
    { printf 'OpenVPN test server did not initialize within 12 seconds\n' >&2; return 1; }

  rm -f "${TB_WORK}/http.ready" "${TB_WORK}/raw.ready"
  ip netns exec "${TB_NS}" "${TB_WORK}/testserver" \
    --listen 10.66.0.1:18080 --mode http --ready-file "${TB_WORK}/http.ready" &
  TB_HTTP_PID=$!
  ip netns exec "${TB_NS}" "${TB_WORK}/testserver" \
    --listen 10.66.0.1:18081 --mode raw --ready-file "${TB_WORK}/raw.ready" &
  TB_ECHO_PID=$!
  for attempt in $(seq 1 100); do
    [[ -f "${TB_WORK}/http.ready" && -f "${TB_WORK}/raw.ready" ]] && break
    kill -0 "${TB_HTTP_PID}"
    kill -0 "${TB_ECHO_PID}"
    sleep 0.1
  done
  [[ -f "${TB_WORK}/http.ready" && -f "${TB_WORK}/raw.ready" ]]
  ip netns exec "${TB_NS}" curl --silent --show-error --fail --max-time 5 "${TB_TARGET}"
}

testbed_stop() {
  local pid
  for pid in "${TB_ECHO_PID}" "${TB_HTTP_PID}" "${TB_SERVER_PID}"; do
    if [[ -n "${pid}" ]]; then
      kill -TERM "${pid}" 2>/dev/null || true
    fi
  done
  for pid in "${TB_ECHO_PID}" "${TB_HTTP_PID}" "${TB_SERVER_PID}"; do
    if [[ -n "${pid}" ]]; then
      timeout 15 tail --pid="${pid}" -f /dev/null || kill -KILL "${pid}" 2>/dev/null || true
    fi
  done
  TB_SERVER_PID= TB_HTTP_PID= TB_ECHO_PID=
}

# testbed_profiles <count> <dir>: session-<i>.ovpn, each on its own tun<i>.
testbed_profiles() {
  local private=${TB_WORK}/private index
  mkdir -p "$2"
  for ((index = 0; index < $1; index++)); do
    {
      printf 'client\ndev tun%d\nproto udp\nremote %s %d\n' "${index}" "${TB_SERVER_IP}" "${TB_PORT}"
      printf 'resolv-retry 2\nnobind\npersist-key\npersist-tun\n'
      printf 'auth-user-pass\nauth-nocache\nremote-cert-tls server\nroute-nopull\n'
      printf '<ca>\n'; cat "${private}/ca.crt"; printf '</ca>\n'
      printf '<cert>\n'; cat "${private}/client.crt"; printf '</cert>\n'
      printf '<key>\n'; cat "${private}/client.key"; printf '</key>\n'
      printf '<tls-crypt>\n'; cat "${private}/tls.key"; printf '</tls-crypt>\n'
    } > "$2/session-${index}.ovpn"
  done
}

testbed_cleanup() {
  testbed_stop
  if [[ -n "${TB_NS}" ]]; then
    ip netns del "${TB_NS}" 2>/dev/null || true
  fi
}
