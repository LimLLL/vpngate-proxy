package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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

	failure chan struct{}
	once    sync.Once
	mu      sync.Mutex
	lost    error
}

// ConnectNative connects node on device and routes traffic from sockets bound
// to that device through it. VPNGate accepts the fixed vpn/vpn login.
func ConnectNative(ctx context.Context, node nodes.Candidate, device string, slot int, timeout time.Duration) (*NativeTunnel, error) {
	seconds := max(1, int(timeout/time.Second))
	client, err := core.NewClient(nodes.PrepareProfile(node.Profile, device), "vpn", "vpn", seconds)
	if err != nil {
		return nil, err
	}
	tunnel := &NativeTunnel{client: client, device: device, failure: make(chan struct{})}
	var connected atomic.Bool
	client.OnEvent = func(event core.Event) {
		if event.Fatal || event.Error {
			log.Printf("%s %s: %s", device, event.Name, event.Info)
		}
		if event.Name == "CONNECTED" {
			connected.Store(true)
			return
		}
		// After a lost connection Core reconnects on its own, keeping the
		// TUN up while traffic is dropped, possibly to come back on another
		// VPN address; callers are better served by another tunnel.
		if connected.Load() && (event.Name == "RECONNECTING" || event.Error || event.Fatal) {
			tunnel.fail(fmt.Errorf("OpenVPN 3 %s after connecting: %s", event.Name, event.Info))
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
	if tunnel.cleanup, err = InstallRoute(device, slot); err != nil {
		closeClient(client)
		return nil, err
	}
	tunnel.routed.Store(true)
	go func() {
		<-client.Failure()
		tunnel.fail(nil)
	}()
	return tunnel, nil
}

func (n *NativeTunnel) Device() string                     { return n.device }
func (n *NativeTunnel) Info() (core.ConnectionInfo, error) { return n.client.ConnectionInfo() }

// Failure closes when Core stops, planned or not, or reconnects.
func (n *NativeTunnel) Failure() <-chan struct{} { return n.failure }

func (n *NativeTunnel) FailureError() error {
	if err := n.client.FailureError(); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lost
}

// fail closes Failure; reason is nil when Core itself stopped.
func (n *NativeTunnel) fail(reason error) {
	n.mu.Lock()
	if n.lost == nil {
		n.lost = reason
	}
	n.mu.Unlock()
	n.once.Do(func() { close(n.failure) })
}

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
	if err := looseReversePath(device); err != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			log.Printf("roll back routes for %s: %v", device, cleanupErr)
		}
		return nil, err
	}
	return cleanup, nil
}

// looseReversePath makes sure replies arriving on device are not dropped by
// strict reverse-path filtering. The kernel applies the larger of the "all"
// and per-device values, so nothing is written when that is already 2 (loose):
// containers usually mount /proc/sys read-only and preset it with --sysctl.
func looseReversePath(device string) error {
	effective := 0
	for _, prefix := range []string{"all", device} {
		data, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + prefix + "/rp_filter")
		if err != nil {
			return err
		}
		value, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return fmt.Errorf("rp_filter of %s: %w", prefix, err)
		}
		effective = max(effective, value)
	}
	if effective == 2 {
		return nil
	}
	for _, prefix := range []string{"all", "default", device} {
		key := "net.ipv4.conf." + prefix + ".rp_filter"
		if output, err := exec.Command("sysctl", "-w", key+"=2").CombinedOutput(); err != nil {
			return fmt.Errorf("%s=2 (in Docker, pass --sysctl net.ipv4.conf.all.rp_filter=2): %w: %s", key, err, output)
		}
	}
	return nil
}
