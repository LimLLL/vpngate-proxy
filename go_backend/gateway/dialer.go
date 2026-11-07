package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
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

// RouteInstall runs this platform's per-tunnel policy-route setup after native
// CONNECTED. Calls use explicit device, table and priority to avoid overlaps.
func RouteInstall(device string, id uint64) (func() error, error) {
	if device == "" {
		return nil, fmt.Errorf("device name is empty")
	}
	table := 2000 + id
	if table > 4294967295 || id > 2100000000 {
		return nil, fmt.Errorf("tunnel routing identifier %d is outside the supported range", id)
	}
	priority := 20000 + id
	cleanup := func() error {
		var first error
		for _, command := range [][]string{
			{"ip", "rule", "del", "priority", strconv.FormatUint(priority, 10)},
			{"ip", "route", "flush", "table", strconv.FormatUint(table, 10)},
		} {
			if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil && first == nil {
				first = fmt.Errorf("%s: %w: %s", strings.Join(command, " "), err, output)
			}
		}
		return first
	}
	for _, command := range [][]string{
		{"ip", "route", "replace", "default", "dev", device, "table", strconv.FormatUint(table, 10)},
		{"ip", "rule", "add", "priority", strconv.FormatUint(priority, 10), "oif", device, "table", strconv.FormatUint(table, 10)},
	} {
		if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				log.Printf("rollback route setup: %v", cleanupErr)
			}
			return nil, fmt.Errorf("%s: %w: %s", strings.Join(command, " "), err, output)
		}
	}
	for _, prefix := range []string{"all", "default", device} {
		key := "net.ipv4.conf." + prefix + ".rp_filter"
		if output, err := exec.Command("sysctl", "-w", key+"=2").CombinedOutput(); err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				log.Printf("rollback rp_filter setup: %v", cleanupErr)
			}
			return nil, fmt.Errorf("%s=2: %w: %s", key, err, output)
		}
	}
	return cleanup, nil
}

type nativeEndpoint struct {
	client   *core.Client
	cleanup  func() error
	nodeID   string
	stopOnce atomic.Bool
}

func (n *nativeEndpoint) CandidateID() string { return n.nodeID }
func (n *nativeEndpoint) Device() string {
	info, _ := n.client.ConnectionInfo()
	return info.TUNName
}
func (n *nativeEndpoint) Info() (core.ConnectionInfo, error) { return n.client.ConnectionInfo() }
func (n *nativeEndpoint) Failure() <-chan struct{}           { return n.client.Failure() }
func (n *nativeEndpoint) FailureError() error                { return n.client.FailureError() }
func (n *nativeEndpoint) Close(ctx context.Context) error {
	clientErr := n.client.Close(ctx)
	var routeErr error
	if n.cleanup != nil && n.stopOnce.CompareAndSwap(false, true) {
		routeErr = n.cleanup()
	}
	return errors.Join(clientErr, routeErr)
}
