package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// NativeConnector opens tunnels with the embedded OpenVPN 3 Core. Slot n
// uses device tun<tunBase+n>, routing table 2000+n and rule priority 20000+n.
func NativeConnector(tunBase int, timeout time.Duration) Connector {
	return func(ctx context.Context, node nodes.Candidate, slot int) (Endpoint, error) {
		tunnel, err := ConnectNative(ctx, node, fmt.Sprintf("tun%d", tunBase+slot), slot, timeout)
		if err != nil {
			return nil, err
		}
		return tunnel, nil
	}
}

// NativeTunnel is one OpenVPN 3 Core session with its policy route.
type NativeTunnel struct {
	client  *core.Client
	device  string
	cleanup func() error
	routed  atomic.Bool
}

// ConnectNative connects node on device and routes traffic from sockets bound
// to that device through it. VPNGate accepts the fixed vpn/vpn login.
func ConnectNative(ctx context.Context, node nodes.Candidate, device string, slot int, timeout time.Duration) (*NativeTunnel, error) {
	seconds := max(1, int(timeout/time.Second))
	client, err := core.NewClient(nodes.PrepareProfile(node.Profile, device), "vpn", "vpn", seconds)
	if err != nil {
		return nil, err
	}
	client.OnEvent = func(event core.Event) {
		if event.Fatal || event.Error {
			log.Printf("%s %s: %s", device, event.Name, event.Info)
		}
	}
	info, err := client.Connect(ctx)
	if err != nil {
		closeClient(client)
		return nil, err
	}
	if info.TUNName != device {
		closeClient(client)
		return nil, fmt.Errorf("expected %s, Core opened %q", device, info.TUNName)
	}
	cleanup, err := InstallRoute(device, slot)
	if err != nil {
		closeClient(client)
		return nil, err
	}
	tunnel := &NativeTunnel{client: client, device: device, cleanup: cleanup}
	tunnel.routed.Store(true)
	return tunnel, nil
}

func (n *NativeTunnel) Device() string                     { return n.device }
func (n *NativeTunnel) Info() (core.ConnectionInfo, error) { return n.client.ConnectionInfo() }
func (n *NativeTunnel) Failure() <-chan struct{}           { return n.client.Failure() }
func (n *NativeTunnel) FailureError() error                { return n.client.FailureError() }

func (n *NativeTunnel) Close(ctx context.Context) error {
	clientErr := n.client.Close(ctx)
	var routeErr error
	if n.routed.CompareAndSwap(true, false) {
		routeErr = n.cleanup()
	}
	return errors.Join(clientErr, routeErr)
}

func closeClient(client *core.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Close(ctx); err != nil {
		log.Printf("close native client: %v", err)
	}
}

// InstallRoute sends traffic leaving device through it via a per-slot table.
// The profile's route-nopull keeps the main table, and with it the OpenVPN
// transport socket, on the physical uplink.
func InstallRoute(device string, slot int) (func() error, error) {
	if slot < 0 || slot > 10000 {
		return nil, fmt.Errorf("tunnel slot %d is outside the supported range", slot)
	}
	table := strconv.Itoa(2000 + slot)
	priority := strconv.Itoa(20000 + slot)
	cleanup := func() error {
		var first error
		for _, command := range [][]string{
			{"ip", "rule", "del", "priority", priority},
			{"ip", "route", "flush", "table", table},
		} {
			if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil && first == nil {
				first = fmt.Errorf("%s: %w: %s", strings.Join(command, " "), err, output)
			}
		}
		return first
	}
	for _, command := range [][]string{
		{"ip", "route", "replace", "default", "dev", device, "table", table},
		{"ip", "rule", "add", "priority", priority, "oif", device, "table", table},
	} {
		if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				log.Printf("roll back routes for %s: %v", device, cleanupErr)
			}
			return nil, fmt.Errorf("%s: %w: %s", strings.Join(command, " "), err, output)
		}
	}
	// Loose reverse-path filtering, or replies arriving on the TUN are dropped.
	for _, prefix := range []string{"all", "default", device} {
		key := "net.ipv4.conf." + prefix + ".rp_filter"
		if output, err := exec.Command("sysctl", "-w", key+"=2").CombinedOutput(); err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				log.Printf("roll back routes for %s: %v", device, cleanupErr)
			}
			return nil, fmt.Errorf("%s=2: %w: %s", key, err, output)
		}
	}
	return cleanup, nil
}
