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
	"strings"
	"syscall"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
	"github.com/LimLLL/vpngate-proxy/go_backend/web"
)

func main() {
	defaultDir := nonempty(os.Getenv("VPNGATE_DATA_DIR"), filepath.Join(".", "vpngate_data"))
	dataDir := flag.String("data-dir", defaultDir, "private node and authentication directory")
	printCredentials := flag.Bool("print-credentials", false, "print management and proxy credentials from this data directory")
	initialize := flag.Bool("initialize", false, "write a new or migrated Go configuration, then exit")
	flag.Parse()
	if err := run(*dataDir, *initialize, *printCredentials); err != nil {
		log.Fatal(err)
	}
}

func run(dataDir string, initialize, printCredentials bool) error {
	if initialize && printCredentials {
		return errors.New("use either --initialize or --print-credentials")
	}
	store, err := web.NewDataStore(dataDir)
	if err != nil {
		return err
	}
	cfg, err := normalizedConfig(store.Snapshot())
	if err != nil {
		return err
	}
	if initialize {
		if _, err := store.Save(cfg); err != nil {
			return err
		}
		return displayCredentials("http://"+net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))+"/"+cfg.SecretPath+"/", cfg)
	}
	if printCredentials {
		if cfg.Username == "" || cfg.Password == "" {
			return errors.New("no initialized credentials; run --initialize first on the data directory")
		}
		return displayCredentials("http://"+net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))+"/"+cfg.SecretPath+"/", cfg)
	}
	if _, err := store.Save(cfg); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("the native OpenVPN gateway requires root privileges for TUN and policy routing")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	source := gateway.RemoteSource(nonempty(os.Getenv("VPNGATE_API_HTTPS_URL"), "https://www.vpngate.net/api/iphone/"))
	catalog, err := web.NewCatalog(store, source)
	if err != nil {
		return err
	}
	factory, err := gateway.NewNativeFactory(gateway.NativeConfig{
		Source: &web.CatalogSource{Catalog: catalog}, Timeout: 30 * time.Second, Backoff: 500 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	catalog.Native = factory
	pool, err := gateway.NewPool(ctx, gateway.PoolConfig{
		MinSpare: 4, MaxTunnels: 128, CreateAttempts: 3,
		ConnectTimeout: 30 * time.Second, IdleTimeout: 5 * time.Minute,
		Factory: factory.Factory(), Logf: log.Printf,
	})
	if err != nil {
		return err
	}
	catalog.Pool = pool
	proxyPassword := nonempty(os.Getenv("LOCAL_PROXY_PASS"), cfg.Password)
	proxy, err := gateway.NewProxy(ctx, pool, proxyPassword, envInteger("LOCAL_PROXY_MAX_CONNECTIONS", 1024))
	if err != nil {
		return err
	}
	proxy.Enabled = func() bool { return store.Snapshot().ConnectionEnabled }
	runtime := web.NewRuntime(catalog, pool)
	runtime.Proxy = proxy
	catalog.Runtime = runtime

	manager := web.NewServer(ctx, runtime)
	manager.Restart = cancel
	runtime.ListenerAddr = net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort))

	proxyListener, err := listen(cfg.ProxyHost, cfg.ProxyPort)
	if err != nil {
		_ = pool.Close()
		return fmt.Errorf("proxy listener: %w", err)
	}
	runtime.ListenerAddr = proxyListener.Addr().String()
	uiListener, err := listen(cfg.Host, cfg.Port)
	if err != nil {
		_ = proxyListener.Close()
		_ = pool.Close()
		return fmt.Errorf("management listener: %w", err)
	}
	fmt.Printf("Go proxy: %s (mandatory session authentication)\n", runtime.ListenerAddr)
	fmt.Printf("Management: http://%s/%s/\n", uiListener.Addr(), cfg.SecretPath)
	fmt.Printf("Use session-<ID>-t-<minutes> and the management password, or LOCAL_PROXY_PASS.\n")

	server := &http.Server{
		Handler: manager, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		WriteTimeout: 10 * time.Minute,
	}
	go func() {
		if err := server.Serve(uiListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("management server: %v", err)
			cancel()
		}
	}()
	go func() {
		if err := proxy.Serve(proxyListener); err != nil {
			log.Printf("proxy server: %v", err)
			cancel()
		}
	}()
	go runtime.Maintain(ctx, envDuration("FETCH_INTERVAL_SECONDS", 21*time.Minute))
	go healthLoop(ctx, runtime)
	go pingLoop(ctx, runtime)

	<-ctx.Done()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	_ = server.Shutdown(shutdownCtx)
	_ = proxy.Close()
	if err := pool.Close(); err != nil {
		return fmt.Errorf("native pool shutdown: %w", err)
	}
	return nil
}

func healthLoop(ctx context.Context, runtime *web.Runtime) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !runtime.Store.Snapshot().ConnectionEnabled {
				continue
			}
			checkCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
			result, err := runtime.CheckPublicEgress(checkCtx, "webcheck")
			cancel()
			if err != nil {
				log.Printf("public egress: %s", result.Error)
			} else {
				web.AddLog(runtime.Store.Dir, "INFO", "Proxy", "实际隧道出口 IP: "+result.IP)
			}
		}
	}
}

func pingLoop(ctx context.Context, runtime *web.Runtime) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			id := runtime.ActiveNode()
			if id == "" {
				continue
			}
			node, err := runtime.Catalog.ByID(id)
			if err == nil {
				latency := web.TCPPingPublic(node.String("remote_host"), node.String("remote_port"))
				runtime.SetPingResult(latency)
			}
		}
	}
}

func listen(host string, port int) (net.Listener, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	listener, err := net.Listen("tcp", address)
	if err == nil || !strings.Contains(host, ":") {
		return listener, err
	}
	fallback := "127.0.0.1"
	if host == "::" || host == "" {
		fallback = "0.0.0.0"
	}
	log.Printf("IPv6 listener %s failed; falling back to %s: %v", address, fallback, err)
	return net.Listen("tcp", net.JoinHostPort(fallback, strconv.Itoa(port)))
}

func normalizedConfig(config web.Config) (web.Config, error) {
	original := config
	var err error
	if config.Username == "" {
		config.Username, err = web.RandomCredential(8)
		if err != nil {
			return config, err
		}
	}
	if config.Password == "" {
		config.Password, err = web.RandomCredential(32)
		if err != nil {
			return config, err
		}
	}
	config.SecretPath = nonempty(config.SecretPath, "EJsW2EeBo9lY")
	config.Host = nonempty(os.Getenv("UI_HOST"), nonempty(config.Host, "::"))
	config.ProxyHost = nonempty(os.Getenv("LOCAL_PROXY_HOST"), nonempty(config.ProxyHost, "127.0.0.1"))
	config.Port = envInteger("UI_PORT", config.Port)
	config.ProxyPort = envInteger("LOCAL_PROXY_PORT", config.ProxyPort)
	// Imported legacy JSON may omit newer port fields.
	if original.Port == 0 && config.Port == 0 {
		config.Port = 8787
	}
	if original.ProxyPort == 0 && config.ProxyPort == 0 {
		config.ProxyPort = 7928
	}
	if config.RoutingMode == "" {
		config.RoutingMode = "auto"
	}
	if config.RoutingIPType == "" {
		config.RoutingIPType = "all"
	}
	if config.SecretPath == "" || strings.Contains(config.SecretPath, "/") {
		return config, errors.New("management secret path is invalid")
	}
	if config.Port < 1 || config.Port > 65535 || config.ProxyPort < 1024 || config.ProxyPort > 65535 || config.Port == config.ProxyPort {
		return config, errors.New("management/proxy port configuration is invalid or conflicts")
	}
	if config.RoutingMode != "auto" && config.RoutingMode != "fixed_ip" && config.RoutingMode != "fixed_region" && config.RoutingMode != "favorites" {
		return config, errors.New("unknown saved routing mode")
	}
	return config, nil
}

func displayCredentials(url string, cfg web.Config) error {
	value := map[string]any{
		"username": cfg.Username, "password": cfg.Password, "management_url": url,
		"proxy_username_template": "session-<ID>-t-<minutes>", "proxy_password": nonempty(os.Getenv("LOCAL_PROXY_PASS"), cfg.Password),
		"proxy_host": cfg.ProxyHost, "proxy_port": cfg.ProxyPort,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func nonempty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func envInteger(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	seconds := envInteger(name, int(fallback.Seconds()))
	if seconds < 1 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}
