package gateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// TestControlledSessionGateway runs only when the isolated CI network has
// supplied real native profiles. Default unit tests do not create privileged TUNs.
func TestControlledSessionGateway(t *testing.T) {
	pattern := os.Getenv("VPNGATE_E2E_PROFILE_GLOB")
	if pattern == "" {
		t.Skip("the controlled server workflow provides native profiles")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Fatal(err)
	}
	profiles, err := nodes.LoadProfiles(pattern)
	if err != nil {
		t.Fatal(err)
	}
	// Each profile has its own client certificate, so it stands in for a
	// distinct node: the server hands every profile its own VPN address.
	registry, err := nodes.OpenRegistry(nodes.RegistryConfig{MaxAge: time.Hour, MaxFailures: 3, Cooldown: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Merge(profiles, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The testbed server uses tls-crypt, which a bare handshake check cannot
	// pass, so the profiles are marked reachable directly.
	for _, profile := range profiles {
		registry.ReportProbe(profile.ID, true, time.Now())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := NewPool(ctx, PoolConfig{
		Nodes: registry, Connect: NativeConnector(0, 20*time.Second), MaxTunnels: 8,
		ConnectTimeout: 20 * time.Second, ConnectAttempts: 3, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pool.Close(); err != nil {
			t.Errorf("controlled pool close: %v", err)
		}
	}()
	proxy, err := NewProxy(ctx, pool, "test", "test-password", 64)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- proxy.Serve(listener) }()

	request := func(username string) string {
		t.Helper()
		proxyURL := &url.URL{Scheme: "http", Host: listener.Addr().String(),
			User: url.UserPassword(username, "test-password")}
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 45 * time.Second}
		response, err := client.Get("http://10.66.0.1:18080/status")
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("proxy request %s: %s %q %v %v", username, response.Status, body, readErr, closeErr)
		}
		host, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimSpace(string(body)), "vpn-client="))
		if err != nil || !strings.HasPrefix(host, "10.66.0.") || port == "" {
			t.Fatalf("response did not traverse the controlled VPN: %q %v", body, err)
		}
		return host
	}
	// node names the node a session's live tunnel goes through. Devices are
	// not compared: tunnels close when unused, so TUN slots are reused.
	node := func(session string) string {
		t.Helper()
		for _, status := range pool.Status().Sessions {
			if status.ID == session && status.Device != "" {
				return status.Node
			}
		}
		return ""
	}

	first := request("test-session-alpha-t-1")
	second := request("test-session-alpha-t-1")
	if first != second {
		t.Fatalf("session changed before expiration: %q %q", first, second)
	}
	firstNode := node("alpha")
	if firstNode == "" {
		t.Fatal("alpha has no native TUN")
	}
	independentIP := request("test-session-beta-t-1")
	if independentIP == first || node("beta") == firstNode {
		t.Fatalf("session beta did not receive an independent TUN: %s", independentIP)
	}
	_ = request("test-session-holding-t-1")
	holdNode := node("holding")
	if holdNode == "" || holdNode == firstNode {
		t.Fatalf("holding stream has no independent endpoint: %s", holdNode)
	}
	stream, reader := openHoldingCONNECT(t, listener.Addr().String())
	defer stream.Close()
	writePing := func() string {
		t.Helper()
		if _, err := io.WriteString(stream, "ping\n"); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	firstEcho := writePing()
	t.Logf("wait 62 seconds for a complete one-minute session TTL while a CONNECT remains active")
	time.Sleep(62 * time.Second)
	rotatedIP := request("test-session-alpha-t-1")
	rotatedNode := node("alpha")
	if rotatedNode == "" || rotatedNode == firstNode {
		t.Fatalf("TTL did not move the session to another node: %s -> %s", firstNode, rotatedNode)
	}
	if got := writePing(); got != firstEcho {
		t.Fatalf("the existing TCP upstream was silently reopened during TTL: %q -> %q", firstEcho, got)
	}
	if got := writePing(); got != firstEcho {
		t.Fatalf("second post-TTL ping left the original stream: %q", got)
	}
	_ = stream.Close()
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"tunneled_http": true, "sticky_before_ttl": first == second,
		"new_node_after_ttl":       rotatedNode != firstNode,
		"existing_stream_survives": true,
		"first_node":               firstNode, "rotated_node": rotatedNode,
		"first_vpn_ip": first, "independent_vpn_ip": independentIP, "rotated_vpn_ip": rotatedIP,
	}
	if path := os.Getenv("VPNGATE_SESSION_REPORT"); path != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("controlled session report: %+v", report)
}

func openHoldingCONNECT(t *testing.T, proxyAddress string) (net.Conn, *bufio.Reader) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("test-session-holding-t-1:test-password"))
	request := fmt.Sprintf("CONNECT 10.66.0.1:18081 HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n", credentials)
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("holding CONNECT failed: %s", response.Status)
	}
	return connection, reader
}
