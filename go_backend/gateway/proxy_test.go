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
	"strconv"
	"strings"
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
	pool := testPool(t, 0, 2, time.Minute)
	proxy, err := NewProxy(context.Background(), pool, "secret", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func proxySessionAuth(session string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("session-"+session+":secret"))
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
		if lease.Session.ID != "work" || lease.Session.TTL != time.Minute {
			return nil, fmt.Errorf("wrong session allocation: %+v", lease.Session)
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
		"Proxy-Authorization: " + proxySessionAuth("work-t-1") + "\r\n\r\n" + payload
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
		"\r\nConnection: close\r\nProxy-Authorization: " + proxySessionAuth("work-t-1") +
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

func TestSOCKS5InvalidCredentials(t *testing.T) {
	pool := testPool(t, 0, 1, time.Minute)
	proxy, err := NewProxy(context.Background(), pool, "secret", 8)
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
	request := []byte{5, 1, 2, 1, 16}
	request = append(request, []byte("session-work-t-1")...)
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
	count, _, sessions := pool.Status()
	if count != 0 || len(sessions) != 0 {
		t.Fatalf("failed authentication opened a tunnel: %+v", sessions)
	}
	if err := <-writing; err != nil {
		t.Fatal(err)
	}
}
