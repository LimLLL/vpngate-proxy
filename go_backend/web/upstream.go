package web

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type UpstreamEndpoint struct {
	Kind     string
	Host     string
	Port     int
	Username string
	Password string
}

const (
	upstreamSocks = "socks"
	upstreamHTTP  = "http"
)

// UpstreamFromEnvironment preserves the source application's priority and
// URL-decoding rules without relying on a third-party SOCKS implementation.
func UpstreamFromEnvironment() (*UpstreamEndpoint, error) {
	for _, item := range []struct{ name, forced string }{
		{"OPENVPN_UPSTREAM_SOCKS", upstreamSocks},
		{"OPENVPN_UPSTREAM_HTTP", upstreamHTTP},
		{"http_proxy", ""}, {"HTTP_PROXY", ""}, {"https_proxy", ""}, {"HTTPS_PROXY", ""},
	} {
		value := strings.TrimSpace(os.Getenv(item.name))
		if value == "" {
			continue
		}
		kind := item.forced
		callback := strings.TrimSpace(value)
		if strings.Contains(callback, "://") {
			parsed, err := url.Parse(callback)
			if err != nil || parsed.Hostname() == "" {
				return nil, fmt.Errorf("invalid upstream proxy URL in %s", item.name)
			}
			if kind == "" {
				kind = parsed.Scheme
			}
			if kind == "socks5" || kind == "socks5h" {
				kind = upstreamSocks
			}
			if kind != upstreamSocks && kind != upstreamHTTP && kind != "https" {
				return nil, fmt.Errorf("unsupported upstream scheme %q", parsed.Scheme)
			}
			username, password := "", ""
			if parsed.User != nil {
				username = parsed.User.Username()
				password, _ = parsed.User.Password()
			}
			port, err := strconv.Atoi(parsed.Port())
			if parsed.Port() == "" {
				port = 10808
			}
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid upstream proxy port")
			}
			if kind == "https" {
				return nil, errors.New("TLS-encrypted upstream proxies are not supported by this deployment")
			}
			return &UpstreamEndpoint{Kind: kind, Host: parsed.Hostname(), Port: port, Username: username, Password: password}, nil
		}
		host, port, err := net.SplitHostPort(callback)
		if err != nil && !strings.HasPrefix(callback, "[") {
			host = callback
			port = "10808"
			err = nil
		}
		if err != nil {
			return nil, fmt.Errorf("SOCKS proxy endpoint must include port: %w", err)
		}
		number, err := strconv.Atoi(port)
		if kind == "" {
			kind = upstreamHTTP
		}
		if number < 1 || number > 65535 || strings.TrimSpace(host) == "" {
			return nil, errors.New("invalid upstream proxy endpoint")
		}
		return &UpstreamEndpoint{Kind: kind, Host: host, Port: number}, nil
	}
	return nil, nil
}

func (u *UpstreamEndpoint) transport() (*http.Transport, error) {
	if u == nil {
		return &http.Transport{Proxy: http.ProxyFromEnvironment}, nil
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Transport{DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
		connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
		if err != nil {
			return nil, fmt.Errorf("upstream %s proxy: %w", u.Kind, err)
		}
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			_ = connection.Close()
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			_ = connection.Close()
			return nil, errors.New("invalid upstream target port")
		}
		if err := ctx.Err(); err != nil {
			_ = connection.Close()
			return nil, err
		}
		if u.Kind == upstreamSocks {
			connection, err = socksViaProxy(ctx, connection, u, host, port)
		} else {
			connection, err = httpViaProxy(ctx, connection, u, host, port)
		}
		return connection, err
	}}, nil
}

func httpViaProxy(ctx context.Context, connection net.Conn, upstream *UpstreamEndpoint, host string, port int) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	reader := bufio.NewReader(connection)
	var request strings.Builder
	target := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if upstream.Username != "" || upstream.Password != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(upstream.Username + ":" + upstream.Password))
		request.WriteString("Proxy-Authorization: Basic " + credentials + "\r\n")
	}
	request.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if _, err := io.WriteString(connection, request.String()); err != nil {
		_ = connection.Close()
		return nil, err
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_ = connection.Close()
		return nil, fmt.Errorf("upstream CONNECT returned %s", response.Status)
	}
	return &upstreamBufferedConn{Reader: reader, Conn: connection}, nil
}

func socksViaProxy(ctx context.Context, connection net.Conn, upstream *UpstreamEndpoint, host string, port int) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	reader := bufio.NewReader(connection)
	greeting := []byte{5, 1, 0}
	if upstream.Username != "" || upstream.Password != "" {
		greeting = []byte{5, 1, 2}
	}
	if _, err := connection.Write(greeting); err != nil {
		_ = connection.Close()
		return nil, err
	}
	if response, err := readUpstream(reader, 2); err != nil || response[0] != 5 || response[1] != greeting[2] {
		_ = connection.Close()
		return nil, fmt.Errorf("upstream refused SOCKS5 authentication")
	}
	if greeting[2] == 2 {
		if len(upstream.Username) > 255 || len(upstream.Password) > 255 {
			_ = connection.Close()
			return nil, errors.New("upstream credentials are longer than the SOCKS5 maximum")
		}
		payload := []byte{1, byte(len(upstream.Username))}
		payload = append(payload, []byte(upstream.Username)...)
		payload = append(payload, byte(len(upstream.Password)))
		payload = append(payload, []byte(upstream.Password)...)
		if _, err := connection.Write(payload); err != nil {
			_ = connection.Close()
			return nil, err
		}
		if result, err := readUpstream(reader, 2); err != nil || result[1] != 0 {
			_ = connection.Close()
			return nil, errors.New("upstream username/password authentication failed")
		}
	}
	request := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		request = append(request, 1)
		request = append(request, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		request = append(request, 4)
		request = append(request, ip.To16()...)
	case len(host) > 255:
		_ = connection.Close()
		return nil, errors.New("upstream domain is longer than 255 bytes")
	default:
		request = append(request, 3, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	portEncoded := make([]byte, 2)
	binary.BigEndian.PutUint16(portEncoded, uint16(port))
	request = append(request, portEncoded...)
	if _, err := connection.Write(request); err != nil {
		_ = connection.Close()
		return nil, err
	}
	header, err := readUpstream(reader, 4)
	if err != nil || header[0] != 5 || header[1] != 0 {
		_ = connection.Close()
		return nil, errors.New("upstream could not reach the requested host")
	}
	remaining := 0
	switch header[3] {
	case 1:
		remaining = 6
	case 3:
		length, err := readUpstream(reader, 1)
		if err != nil {
			_ = connection.Close()
			return nil, err
		}
		remaining = int(length[0]) + 2
	case 4:
		remaining = 18
	default:
		_ = connection.Close()
		return nil, errors.New("invalid upstream SOCKS address type")
	}
	if _, err := readUpstream(reader, remaining); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return &upstreamBufferedConn{Reader: reader, Conn: connection}, nil
}

func readUpstream(reader io.Reader, length int) ([]byte, error) {
	var result = make([]byte, length)
	_, err := io.ReadFull(reader, result)
	return result, err
}

type upstreamBufferedConn struct {
	*bufio.Reader
	net.Conn
}

func (c *upstreamBufferedConn) Read(data []byte) (int, error) { return c.Reader.Read(data) }

func newHTTPClient() (*http.Client, error) {
	config, err := UpstreamFromEnvironment()
	if err != nil {
		return nil, err
	}
	transport, err := config.transport()
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}
