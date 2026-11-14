package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

const (
	refreshInterval = 20 * time.Minute
	retryInterval   = time.Minute
	connectTimeout  = 15 * time.Second
	// Every node is checked this often with a bare OpenVPN handshake, which
	// costs it two small packets; only nodes that answered get connected.
	livenessInterval = 5 * time.Minute
	livenessTimeout  = 4 * time.Second
	livenessWorkers  = 32
)

func main() {
	defaultDir := os.Getenv("VPNGATE_DATA_DIR")
	if defaultDir == "" {
		defaultDir = "vpngate_data"
	}
	dataDir := flag.String("data-dir", defaultDir, "directory holding config.json and nodes.json")
	printOnly := flag.Bool("print-credentials", false, "print the proxy credentials and exit")
	flag.Parse()
	if err := run(*dataDir, *printOnly); err != nil {
		log.Fatal(err)
	}
}

func run(dataDir string, printOnly bool) error {
	config, err := loadConfig(dataDir)
	if err != nil {
		return err
	}
	if printOnly {
		return printCredentials(config)
	}
	if os.Geteuid() != 0 {
		return errors.New("root is required to create TUN devices and policy routes")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	registry, err := nodes.OpenRegistry(nodes.RegistryConfig{
		Path:        filepath.Join(dataDir, "nodes.json"),
		MaxAge:      time.Duration(config.NodeMaxAgeDays) * 24 * time.Hour,
		MaxFailures: config.NodeMaxFailures,
		Cooldown:    10 * time.Minute,
		Unreachable: 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	// The default transport honors HTTPS_PROXY/HTTP_PROXY for the listing.
	client := &http.Client{Timeout: time.Minute}
	refreshed := refresh(ctx, registry, client, config.APIURLs)
	// Serve only once every node has been checked, so the first requests do
	// not wait on nodes that went offline.
	checkLiveness(ctx, registry, false)

	pool, err := gateway.NewPool(ctx, gateway.PoolConfig{
		Nodes:           registry,
		Connect:         gateway.NativeConnector(config.TUNBase, connectTimeout),
		MaxTunnels:      config.MaxTunnels,
		ConnectTimeout:  connectTimeout,
		ConnectAttempts: 5,
		Egress:          probeEgress,
	})
	if err != nil {
		return err
	}
	proxy, err := gateway.NewProxy(ctx, pool, config.Username, config.Password, 1024)
	if err != nil {
		return errors.Join(err, pool.Close())
	}
	address := net.JoinHostPort(config.ProxyHost, strconv.Itoa(config.ProxyPort))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Join(fmt.Errorf("listen %s: %w", address, err), pool.Close())
	}
	log.Printf("proxy on %s, user %s[-country-XX][-session-ID[-t-MINUTES]], %d nodes known",
		listener.Addr(), config.Username, registry.Len())

	go refreshLoop(ctx, registry, client, config.APIURLs, refreshed)
	go livenessLoop(ctx, registry)
	served := make(chan error, 1)
	go func() { served <- proxy.Serve(listener) }()
	select {
	case <-ctx.Done():
	case err = <-served:
		log.Printf("proxy stopped: %v", err)
	}
	stop()
	return errors.Join(err, proxy.Close(), pool.Close(), registry.Save())
}

// probeEgress asks two independent IP echo services in turn, so one service
// being down does not make every tunnel look dead.
func probeEgress(ctx context.Context, device string) (string, error) {
	var failures []error
	for _, url := range []string{"https://api.ipify.org", "https://icanhazip.com"} {
		attemptCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
		ip, err := gateway.ProbeEgress(attemptCtx, device, url)
		cancel()
		if err == nil {
			return ip, nil
		}
		failures = append(failures, err)
	}
	return "", errors.Join(failures...)
}

// refresh merges one listing into the registry; failures are logged because
// the accumulated table keeps the proxy usable until the next attempt.
func refresh(ctx context.Context, registry *nodes.Registry, client *http.Client, urls []string) bool {
	fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	listing, err := nodes.Fetch(fetchCtx, client, urls)
	if err != nil {
		log.Printf("fetch VPNGate listing: %v", err)
		return false
	}
	added, err := registry.Merge(listing, time.Now())
	if err != nil {
		log.Printf("save node table: %v", err)
	}
	log.Printf("VPNGate listing: %d nodes, %d new, %d known", len(listing), added, registry.Len())
	return true
}

// refreshLoop also checks the nodes each listing added, so they become usable
// without waiting for the next full round.
func refreshLoop(ctx context.Context, registry *nodes.Registry, client *http.Client, urls []string, ok bool) {
	for {
		wait := refreshInterval
		if !ok {
			wait = retryInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if ok = refresh(ctx, registry, client, urls); ok {
			checkLiveness(ctx, registry, true)
		}
	}
}

func livenessLoop(ctx context.Context, registry *nodes.Registry) {
	ticker := time.NewTicker(livenessInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkLiveness(ctx, registry, false)
		}
	}
}

// checkLiveness checks every node, or with onlyNew those never checked, and
// saves the results so a restart can serve before its first round ends.
func checkLiveness(ctx context.Context, registry *nodes.Registry, onlyNew bool) {
	started := time.Now()
	alive, total := registry.Probe(ctx, handshake, onlyNew, livenessWorkers)
	if total == 0 {
		return
	}
	log.Printf("liveness: %d of %d nodes answer (%s)", alive, total, time.Since(started).Round(time.Second))
	if err := registry.Save(); err != nil {
		log.Printf("save node table: %v", err)
	}
}

func handshake(ctx context.Context, node nodes.Candidate) error {
	ctx, cancel := context.WithTimeout(ctx, livenessTimeout)
	defer cancel()
	return nodes.Handshake(ctx, node.RemoteHost, node.RemotePort, node.Protocol)
}

func printCredentials(config Config) error {
	host := config.ProxyHost
	if host == "0.0.0.0" || host == "::" {
		host = "<server-ip>"
	}
	address := net.JoinHostPort(host, strconv.Itoa(config.ProxyPort))
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(map[string]any{
		"username": config.Username,
		"password": config.Password,
		"listen":   net.JoinHostPort(config.ProxyHost, strconv.Itoa(config.ProxyPort)),
		"example":  fmt.Sprintf("http://%s-country-jp-session-abc-t-10:%s@%s", config.Username, config.Password, address),
	})
}
