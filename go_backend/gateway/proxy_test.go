package gateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type recordedDialer struct {
	received           chan []byte
	response           string
	host               string
	port               int
	respondImmediately bool
}

func (d *recordedDialer) DialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	d.host, d.port = host, port
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 256)
		readPayload := func() {
			length, _ := io.ReadAtLeast(server, buffer, 1)
			d.received <- append([]byte(nil), buffer[:length]...)
		}
		if d.respondImmediately {
			_, _ = io.WriteString(server, d.response)
			readPayload()
			return
		}
		readPayload()
		_, _ = io.WriteString(server, d.response)
	}()
	return client, nil
}

func (d *recordedDialer) ResolveIPv4(ctx context.Context, host string) ([]net.IP, error) {
	return nil, errors.New("whole host should be forwarded by the protocol tests")
}

func testProxy(t *testing.T) *Proxy {
	t.Helper()
	pool, _ := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{})
	proxy, err := NewProxy(context.Background(), pool, "acct", "secret", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func proxyAuth(username string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":secret"))
}

// httpStatus sends one request line plus headers and returns the status code.
func httpStatus(t *testing.T, proxy *Proxy, request string) int {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		proxy.handle(server)
	}()
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

func TestHTTPRejectsMissingProxyCredentials(t *testing.T) {
	proxy := testProxy(t)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		proxy.handle(server)
	}()
	request := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("authentication should fail before opening a tunnel: %s", response.Status)
	}
}

func TestCONNECTPreservesBufferedPayloadAndForwardsThroughLease(t *testing.T) {
	proxy := testProxy(t)
	dialer := &recordedDialer{received: make(chan []byte, 1), response: "server-response"}
	proxy.DialerForLease = func(lease *Lease) (LeaseDialer, error) {
		if lease.Request.Session != "work" || lease.Request.TTL != time.Minute {
			return nil, fmt.Errorf("wrong session allocation: %+v", lease.Request)
		}
		return dialer, nil
	}
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		proxy.handle(server)
	}()
	payload := "opaque-tls-payload"
	request := "CONNECT example.com:443 HTTP/1.1\r\n" +
		"Proxy-Authorization: " + proxyAuth("acct-session-work-t-1") + "\r\n\r\n" + payload
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: %+v %v", response, err)
	}
	received := <-dialer.received
	if string(received) != payload {
		t.Fatalf("data read into the HTTP reader was not preserved: %q", received)
	}
	if dialer.host != "example.com" || dialer.port != 443 {
		t.Fatalf("target was changed before tunnel dialing: %s:%d", dialer.host, dialer.port)
	}
	result := make([]byte, len(dialer.response))
	if _, err := io.ReadFull(client, result); err != nil || string(result) != dialer.response {
		t.Fatalf("relay response: %q %v", result, err)
	}
}

func TestHTTPStripsProxyCredentialsFromTargetRequest(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header
		_, _ = io.WriteString(w, "real-upstream")
	}))
	defer upstream.Close()
	proxy := testProxy(t)
	proxy.DialerForLease = func(lease *Lease) (LeaseDialer, error) {
		return plainDialer{}, nil
	}
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		proxy.handle(server)
	}()
	request := "GET " + upstream.URL + "/path HTTP/1.1\r\nHost: " + strings.TrimPrefix(upstream.URL, "http://") +
		"\r\nConnection: close\r\nProxy-Authorization: " + proxyAuth("acct-session-work-t-1") +
		"\r\nAuthorization: AuthorizationIsNotProxyAuthentication\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "real-upstream" || response.StatusCode != http.StatusOK {
		t.Fatalf("upstream response: %q %s %v", body, response.Status, err)
	}
	header := <-received
	if header.Get("Proxy-Authorization") != "" {
		t.Fatal("proxy credentials leaked to the destination")
	}
}

type plainDialer struct{}

func (plainDialer) DialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}
func (plainDialer) ResolveIPv4(ctx context.Context, host string) ([]net.IP, error) {
	return []net.IP{net.ParseIP(host)}, nil
}

func TestHTTPStatusSeparatesRejectionFromShortage(t *testing.T) {
	proxy := testProxy(t)
	connect := func(username string) int {
		return httpStatus(t, proxy, "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: "+proxyAuth(username)+"\r\n\r\n")
	}
	if status := connect("acct-country-kr"); status != http.StatusServiceUnavailable {
		t.Fatalf("no KR node: want 503, got %d", status)
	}
	if status := connect("acct-session-bad-name"); status != http.StatusProxyAuthRequired {
		t.Fatalf("malformed username: want 407, got %d", status)
	}
	proxy.DialerForLease = func(*Lease) (LeaseDialer, error) {
		return &recordedDialer{received: make(chan []byte, 1), respondImmediately: true}, nil
	}
	if status := connect("acct-session-s-t-5"); status != http.StatusOK {
		t.Fatalf("session start: want 200, got %d", status)
	}
	if status := connect("acct-session-s-t-6"); status != http.StatusProxyAuthRequired {
		t.Fatalf("changed TTL on a live session: want 407, got %d", status)
	}
}

// timeoutDialer fails the way a dial through a tunnel that stopped forwarding does.
type timeoutDialer struct{}

func (timeoutDialer) DialContext(context.Context, string, int) (net.Conn, error) {
	return nil, &net.DNSError{Err: "i/o timeout", Name: "example.com", Server: "8.8.8.8:53", IsTimeout: true}
}
func (timeoutDialer) ResolveIPv4(context.Context, string) ([]net.IP, error) {
	return nil, errors.New("not used")
}

func TestTimedOutDialMovesToAnotherTunnel(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{egress: distinctEgress})
	proxy, err := NewProxy(context.Background(), pool, "acct", "secret", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	proxy.DialerForLease = func(lease *Lease) (LeaseDialer, error) {
		if lease.NodeID == "10.0.0.1" {
			network.kill(lease.NodeID)
			return timeoutDialer{}, nil
		}
		return &recordedDialer{received: make(chan []byte, 1), respondImmediately: true}, nil
	}
	request := "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: " + proxyAuth("acct-session-s") + "\r\n\r\n"
	if status := httpStatus(t, proxy, request); status != http.StatusOK {
		t.Fatalf("the request should have been retried on a working tunnel, got %d", status)
	}
	eventually(t, "the dead tunnel to close", func() bool { return network.endpoint("10.0.0.1").isClosed() })
}

func TestTimedOutDialThroughAWorkingTunnelIsABadGateway(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{egress: distinctEgress})
	proxy, err := NewProxy(context.Background(), pool, "acct", "secret", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	proxy.DialerForLease = func(*Lease) (LeaseDialer, error) { return timeoutDialer{}, nil }
	request := "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: " + proxyAuth("acct-session-s") + "\r\n\r\n"
	if status := httpStatus(t, proxy, request); status != http.StatusBadGateway {
		t.Fatalf("an unreachable target behind a working tunnel: want 502, got %d", status)
	}
	if network.endpoint("10.0.0.1").isClosed() {
		t.Fatal("a working tunnel was dropped")
	}
}

// failingDialer fails every dial with err.
type failingDialer struct{ err error }

func (d failingDialer) DialContext(context.Context, string, int) (net.Conn, error) { return nil, d.err }
func (failingDialer) ResolveIPv4(context.Context, string) ([]net.IP, error) {
	return nil, errors.New("not used")
}

func TestDialOnADroppedTunnelMovesToAnotherOne(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{egress: distinctEgress})
	proxy, err := NewProxy(context.Background(), pool, "acct", "secret", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	proxy.DialerForLease = func(lease *Lease) (LeaseDialer, error) {
		if lease.NodeID == "10.0.0.1" {
			// Core restarted and took the TUN with it: no timeout, just gone.
			network.kill(lease.NodeID)
			network.endpoint(lease.NodeID).drop()
			return failingDialer{&net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("setsockopt", syscall.ENODEV)}}, nil
		}
		return &recordedDialer{received: make(chan []byte, 1), respondImmediately: true}, nil
	}
	request := "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: " + proxyAuth("acct-session-s") + "\r\n\r\n"
	if status := httpStatus(t, proxy, request); status != http.StatusOK {
		t.Fatalf("the request should have moved to a working tunnel, got %d", status)
	}
}

func TestRefusedDialKeepsTheTunnel(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{egress: distinctEgress})
	proxy, err := NewProxy(context.Background(), pool, "acct", "secret", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	proxy.DialerForLease = func(lease *Lease) (LeaseDialer, error) {
		// Were the tunnel probed now, it would fail; a refusal proves it works.
		network.kill(lease.NodeID)
		return failingDialer{&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}, nil
	}
	request := "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: " + proxyAuth("acct-session-s") + "\r\n\r\n"
	if status := httpStatus(t, proxy, request); status != http.StatusBadGateway {
		t.Fatalf("a refused target: want 502, got %d", status)
	}
	if network.endpoint("10.0.0.1").isClosed() {
		t.Fatal("a refusal from the target dropped the tunnel")
	}
}

func TestForwardTargetDefaultsToPort80AndKeepsThePath(t *testing.T) {
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := forwardTarget(request)
	if err != nil || host != "example.com" || port != 80 {
		t.Fatalf("target %s:%d %v", host, port, err)
	}
	if uri := request.URL.RequestURI(); uri != "/path?q=1" || request.Header.Get("Proxy-Connection") != "" {
		t.Fatalf("forwarded as %q with headers %v", uri, request.Header)
	}
}

func TestSOCKS5InvalidCredentials(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP"), poolOptions{})
	proxy, err := NewProxy(context.Background(), pool, "acct", "secret", 8)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		proxy.handle(server)
	}()
	username := []byte("acct-session-work-t-1")
	request := []byte{5, 1, 2, 1, byte(len(username))}
	request = append(request, username...)
	request = append(request, 5)
	request = append(request, []byte("wrong")...)
	writing := make(chan error, 1)
	go func() {
		_, err := client.Write(request)
		writing <- err
	}()
	reply := make([]byte, 4)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 2 || reply[2] != 1 || reply[3] == 0 {
		t.Fatalf("invalid authentication response: %v", reply)
	}
	if status := pool.Status(); len(status.Tunnels) != 0 || len(status.Sessions) != 0 {
		t.Fatalf("failed authentication opened a tunnel: %+v", status)
	}
	if err := <-writing; err != nil {
		t.Fatal(err)
	}
}

func TestCredentialAndAuthorityParsing(t *testing.T) {
	user, password, err := proxyBasicCredentials("Basic " + base64.StdEncoding.EncodeToString([]byte("acct-session-app:sec:ret")))
	if err != nil || user != "acct-session-app" || password != "sec:ret" {
		t.Fatalf("unexpected proxy credentials %q %q %v", user, password, err)
	}
	if _, _, err := proxyBasicCredentials("Basic bm9jb2xvbg=="); err == nil {
		t.Fatal("missing colon unexpectedly authenticated")
	}
	host, port, err := proxyAuthority("example.com:8443")
	if err != nil || host != "example.com" || port != 8443 {
		t.Fatalf("unexpected target %s %d %v", host, port, err)
	}
	host, port, err = proxyAuthority("[2001:db8::1]:443")
	if err != nil || host != "2001:db8::1" || port != 443 {
		t.Fatalf("IPv6 target parsed incorrectly: %s %d %v", host, port, err)
	}
}
