package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"
)

// DeviceDialer binds only the customer sockets to the lease's native tunnel.
// The OpenVPN transport socket retains the physical route via route-nopull.
type DeviceDialer struct {
	Device string
	DNS    string
}

func (d DeviceDialer) DialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	control := func(_ string, _ string, raw syscall.RawConn) error {
		var bindErr error
		err := raw.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, d.Device)
		})
		return errors.Join(err, bindErr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		addresses, err := d.ResolveIPv4(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s through %s: %w", host, d.Device, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve %s through %s: no IPv4 address", host, d.Device)
		}
		ip = addresses[0]
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("IPv6 target %s requires an IPv6 VPN tunnel", host)
	}
	dialer := &net.Dialer{Timeout: 20 * time.Second, Control: control}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

func (d DeviceDialer) ResolveIPv4(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		dialer := net.Dialer{Control: func(_ string, _ string, raw syscall.RawConn) error {
			var bindErr error
			err := raw.Control(func(fd uintptr) {
				bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, d.Device)
			})
			return errors.Join(err, bindErr)
		}}
		return dialer.DialContext(ctx, "udp", net.JoinHostPort(d.DNS, "53"))
	}}
	return resolver.LookupIP(ctx, "ip4", host)
}
