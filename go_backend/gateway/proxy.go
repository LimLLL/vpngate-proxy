package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LeaseDialer is acquired only after authentication, then resolves and dials
// through that lease's tunnel. Unknown usernames are never granted an egress.
type LeaseDialer interface {
	DialContext(context.Context, string, int) (net.Conn, error)
	ResolveIPv4(context.Context, string) ([]net.IP, error)
}

type Proxy struct {
	pool       *Pool
	passwordMu sync.RWMutex
	password   string
	ctx        context.Context
	cancel     context.CancelFunc
	listeners  sync.Map
	wg         sync.WaitGroup
	MaxConns   chan struct{}
	// Enabled can reject new proxy traffic after a management-level stop.
	Enabled        func() bool
	DialerForLease func(*Lease) (LeaseDialer, error)
}

func NewProxy(parent context.Context, pool *Pool, password string, maxConnections int) (*Proxy, error) {
	if pool == nil {
		return nil, errors.New("proxy requires a session pool")
	}
	if password == "" {
		return nil, errors.New("proxy password must not be empty")
	}
	if maxConnections < 1 {
		return nil, errors.New("max connections must be positive")
	}
	ctx, cancel := context.WithCancel(parent)
	return &Proxy{ctx: ctx, pool: pool, password: password, cancel: cancel, MaxConns: make(chan struct{}, maxConnections)}, nil
}

// Serve supports both HTTP proxying and SOCKS5 on the same listener. Binding
// is explicit in main and loopback by default; the gateway still requires auth.
func (p *Proxy) Serve(listener net.Listener) error {
	defer listener.Close()
	p.listeners.Store(listener, struct{}{})
	defer p.listeners.Delete(listener)
	go func() {
		<-p.ctx.Done()
		_ = listener.Close()
	}()
	for {
		client, err := listener.Accept()
		if err != nil {
			if p.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("proxy accept: %w", err)
		}
		select {
		case p.MaxConns <- struct{}{}:
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer func() { <-p.MaxConns }()
				defer client.Close()
				p.handle(client)
			}()
		default:
			_ = client.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(client, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
			_ = client.Close()
		}
	}
}

func (p *Proxy) Close() error {
	p.cancel()
	p.listeners.Range(func(key, _ any) bool {
		if listener, ok := key.(net.Listener); ok {
			_ = listener.Close()
		}
		return true
	})
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("proxy close timed out waiting for active streams")
	}
}

func (p *Proxy) handle(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-p.ctx.Done():
			_ = client.SetDeadline(time.Now())
		case <-finished:
		}
	}()
	reader := bufio.NewReader(client)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	if bytes.Equal(first, []byte{5}) {
		p.handleSocks(client, reader)
		return
	}
	p.handleHTTP(client, reader)
}

// SetPassword atomically applies a saved management credential update.
func (p *Proxy) SetPassword(password string) {
	p.passwordMu.Lock()
	p.password = password
	p.passwordMu.Unlock()
}

func (p *Proxy) lease(ctx context.Context, username, password string) (*Lease, error) {
	if p.Enabled != nil && !p.Enabled() {
		return nil, errors.New("proxy is disabled by the management configuration")
	}

	if !p.validCredentials(username, password) {
		return nil, errors.New("proxy authentication failed or session is invalid")
	}
	spec, err := ParseSession(username)
	if err != nil {
		return nil, err
	}
	return p.pool.Acquire(ctx, spec)
}

func (p *Proxy) validCredentials(username, password string) bool {
	p.passwordMu.RLock()
	expected := p.password
	p.passwordMu.RUnlock()
	if subtle.ConstantTimeCompare([]byte(password), []byte(expected)) != 1 {
		return false
	}
	_, err := ParseSession(username)
	return err == nil
}

func (p *Proxy) acquireTunnel(ctx context.Context, username, password string) (*Lease, LeaseDialer, error) {
	lease, err := p.lease(ctx, username, password)
	if err != nil {
		return nil, nil, err
	}
	if p.DialerForLease != nil {
		dialer, err := p.DialerForLease(lease)
		if err != nil {
			lease.Release()
			return nil, nil, err
		}
		return lease, dialer, nil
	}
	if lease.Info.TUNName == "" {
		lease.Release()
		return nil, nil, errors.New("session has no tunnel interface")
	}
	return lease, DeviceDialer{Device: lease.Info.TUNName, DNS: "8.8.8.8"}, nil
}

func (p *Proxy) handleHTTP(client net.Conn, reader *bufio.Reader) {
	header, err := readHTTPHeaders(reader, 64*1024)
	if err != nil {
		writeHTTP(client, http.StatusRequestHeaderFieldsTooLarge, "Proxy-Connection: close")
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		writeHTTP(client, http.StatusBadRequest, "Proxy-Connection: close")
		return
	}
	user, password, err := proxyBasicCredentials(request.Header.Get("Proxy-Authorization"))
	ctx, cancel := context.WithTimeout(p.ctx, 45*time.Second)
	defer cancel()
	lease, egress, err := p.acquireTunnel(ctx, user, password)
	if err != nil {
		p.authenticationError(client, err)
		return
	}
	defer lease.Release()
	if request.Method == http.MethodConnect {
		host, port, err := proxyAuthority(request.Host)
		if err != nil {
			writeHTTP(client, http.StatusBadRequest, "Content-Length: 0")
			return
		}
		p.connectHTTP(ctx, readerConn{Reader: reader, Conn: client}, egress, host, port)
		return
	}
	target := request.URL
	if target.Hostname() == "" {
		authority := request.Host
		if authority == "" {
			authority = request.Header.Get("Host")
		}
		parsed, err := url.Parse("http://" + authority)
		if err != nil {
			writeHTTP(client, http.StatusBadRequest, "Content-Length: 0")
			return
		}
		target = parsed
	}
	if target.Scheme != "http" {
		writeHTTP(client, http.StatusNotImplemented, "Content-Length: 0")
		return
	}
	port, err := strconv.Atoi(target.Port())
	if target.Port() == "" {
		port = 80
	}
	if err != nil || port < 1 || port > 65535 {
		writeHTTP(client, http.StatusBadRequest, "Content-Length: 0")
		return
	}
	request.URL.Path = target.Path
	if request.URL.Path == "" {
		request.URL.Path = "/"
	}
	request.URL.RawQuery = target.RawQuery
	request.URL.Host = target.Host
	request.RequestURI = ""
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	request.Header.Set("Connection", "close")
	// Original buffers may already contain body bytes; connect parsing above
	// only used a header-specific reader, so retain those bytes for forwarding.
	if request.ContentLength > 0 {
		request.Body = io.NopCloser(io.LimitReader(reader, request.ContentLength))
	} else if len(request.TransferEncoding) > 0 && request.TransferEncoding[0] == "chunked" {
		request.Body = io.NopCloser(httputil.NewChunkedReader(reader))
	}
	upstream, err := egress.DialContext(ctx, target.Hostname(), port)
	if err != nil {
		log.Printf("%s HTTP %s: %v", lease.Info.TUNName, target.Host, err)
		writeHTTP(client, http.StatusBadGateway, "Content-Length: 0")
		return
	}
	defer upstream.Close()
	if err := request.Write(upstream); err != nil {
		return
	}
	relay(p.ctx, client, upstream)
}

func (p *Proxy) connectHTTP(ctx context.Context, client net.Conn, egress LeaseDialer, host string, port int) {
	upstream, err := egress.DialContext(ctx, host, port)
	if err != nil {
		log.Printf("CONNECT host=%s port=%d: %v", host, port, err)
		writeHTTP(client, http.StatusBadGateway, "Content-Length: 0")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	relay(p.ctx, client, upstream)
}

func (p *Proxy) authenticationError(client net.Conn, err error) {
	log.Printf("proxy authentication/session rejected: %v", err)
	writeHTTP(client, http.StatusProxyAuthRequired, "Proxy-Authenticate: Basic realm=vpngate-proxy", "Content-Length: 0")
}

func proxyAuthority(authority string) (string, int, error) {
	if strings.HasPrefix(authority, "[") {
		parsed, err := url.Parse("http://" + authority)
		if err != nil {
			return "", 0, err
		}
		port, err := strconv.Atoi(parsed.Port())
		if parsed.Port() == "" {
			port = 443
		}
		return parsed.Hostname(), port, err
	}
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		host, portText, err = authority, "443", nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil || host == "" || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid CONNECT target")
	}
	return host, port, nil
}

func relay(ctx context.Context, left, right net.Conn) {
	_ = left.SetDeadline(time.Time{})
	_ = right.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		<-ctx.Done()
		_ = left.Close()
		_ = right.Close()
	}()
	go func() {
		_, _ = io.Copy(right, left)
		if tcp, ok := right.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(left, right)
		if tcp, ok := left.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func readHTTPHeaders(reader *bufio.Reader, limit int) ([]byte, error) {
	var data []byte
	for {
		line, more, err := reader.ReadLine()
		if err != nil {
			return nil, err
		}
		if len(data)+len(line)+2 > limit {
			return nil, errors.New("HTTP header exceeds configured limit")
		}
		data = append(data, line...)
		data = append(data, '\r', '\n')
		if !more && len(line) == 0 {
			return data, nil
		}
	}
}

func writeHTTP(writer io.Writer, status int, headers ...string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for _, header := range headers {
		response += header + "\r\n"
	}
	response += "Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(writer, response)
}
