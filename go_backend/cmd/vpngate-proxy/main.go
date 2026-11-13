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
	})
	if err != nil {
		return err
	}
	// The default transport honors HTTPS_PROXY/HTTP_PROXY for the listing.
	client := &http.Client{Timeout: time.Minute}
	refreshed := refresh(ctx, registry, client, config.APIURLs)

	pool, err := gateway.NewPool(ctx, gateway.PoolConfig{
		Nodes:           registry,
		Connect:         gateway.NativeConnector(config.TUNBase, connectTimeout),
		MaxTunnels:      config.MaxTunnels,
		MinIdle:         config.MinIdleTunnels,
		IdleTimeout:     10 * time.Minute,
		ConnectTimeout:  connectTimeout,
		ConnectAttempts: 3,
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
		ok = refresh(ctx, registry, client, urls)
	}
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
