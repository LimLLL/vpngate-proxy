package gateway

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestSOCKS5CredentialsDomainAndBufferedData(t *testing.T) {
	proxy := testProxy(t)
	dialer := &recordedDialer{received: make(chan []byte, 1), response: "socks-upstream-ok", respondImmediately: true}
	proxy.DialerForLease = func(lease *Lease) (LeaseDialer, error) {
		if lease.Session.ID != "socks" {
			t.Errorf("unexpected SOCKS session: %+v", lease.Session)
		}
		return dialer, nil
	}
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		proxy.handle(server)
	}()
	username, password := []byte("session-socks-t-1"), []byte("secret")
	request := []byte{5, 1, 2, 1, byte(len(username))}
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	host := []byte("example.com")
	request = append(request, 5, 1, 0, 3, byte(len(host)))
	request = append(request, host...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, 443)
	request = append(request, port...)
	job := make(chan error, 1)
	go func() {
		_, err := client.Write(request)
		job <- err
	}()
	var greeting, credentials [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting != [2]byte{5, 2} {
		t.Fatalf("SOCKS authentication selection: %v %v", greeting, err)
	}
	if _, err := io.ReadFull(client, credentials[:]); err != nil || credentials != [2]byte{1, 0} {
		t.Fatalf("SOCKS authentication response: %v %v", credentials, err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS CONNECT reply: %v %v", reply, err)
	}
	if err := <-job; err != nil {
		t.Fatal(err)
	}
	if dialer.host != "example.com" || dialer.port != 443 {
		t.Fatalf("wrong domain target: %s:%d", dialer.host, dialer.port)
	}
	// After negotiation, arbitrary proxy payload must reach the same upstream.
	if _, err := io.WriteString(client, "post-negotiation"); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, len(dialer.response))
	if _, err := io.ReadFull(client, result); err != nil || string(result) != dialer.response {
		t.Fatalf("SOCKS relay: %q %v", result, err)
	}
	if got := <-dialer.received; string(got) != "post-negotiation" {
		t.Fatalf("SOCKS payload did not reach its assigned egress: %q", got)
	}
}
