package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// DeviceTransport is an HTTP transport whose connections and DNS lookups all
// leave through device. Keep-alives are off: each caller makes few requests.
func DeviceTransport(device string) *http.Transport {
	dialer := DeviceDialer{Device: device, DNS: "8.8.8.8"}
	return &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			number, err := strconv.Atoi(port)
			if err != nil {
				return nil, fmt.Errorf("invalid port in %q", address)
			}
			return dialer.DialContext(ctx, host, number)
		},
	}
}

// ProbeEgress asks an IP echo service such as https://api.ipify.org, through
// device, which public IPv4 address it sees.
func ProbeEgress(ctx context.Context, device, url string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	response, err := (&http.Client{Transport: DeviceTransport(device)}).Do(request)
	if err != nil {
		return "", fmt.Errorf("egress probe through %s: %w", device, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if response.StatusCode != http.StatusOK || ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("egress probe through %s: status %d, body %q", device, response.StatusCode, body)
	}
	return ip.String(), nil
}
