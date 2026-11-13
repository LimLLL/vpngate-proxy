package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// Config is data-dir/config.json. Missing fields take the defaults below;
// LOCAL_PROXY_* environment variables override fields without being saved.
type Config struct {
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	ProxyHost       string   `json:"proxy_host"`
	ProxyPort       int      `json:"proxy_port"`
	MaxTunnels      int      `json:"max_tunnels"`
	MinIdleTunnels  int      `json:"min_idle_tunnels"`
	TUNBase         int      `json:"tun_base"`
	NodeMaxAgeDays  int      `json:"node_max_age_days"`
	NodeMaxFailures int      `json:"node_max_failures"`
	APIURLs         []string `json:"api_urls"`
}

var accountPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func defaultConfig() Config {
	return Config{
		ProxyHost: "127.0.0.1", ProxyPort: 7928,
		MaxTunnels: 64, MinIdleTunnels: 4,
		NodeMaxAgeDays: 7, NodeMaxFailures: 5,
		APIURLs: []string{"https://www.vpngate.net/api/iphone/", "http://www.vpngate.net/api/iphone/"},
	}
}

// loadConfig reads the config, creating it with random credentials on first
// run so the password stays stable across restarts.
func loadConfig(dir string) (Config, error) {
	path := filepath.Join(dir, "config.json")
	config := defaultConfig()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &config); err != nil {
			return Config{}, fmt.Errorf("read %s: %w", path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return Config{}, err
	}
	if config.Username == "" || config.Password == "" {
		if config.Username == "" {
			config.Username = "u" + randomHex(4)
		}
		if config.Password == "" {
			config.Password = randomHex(12)
		}
		encoded, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return Config{}, err
		}
		if err := nodes.WriteFileAtomic(path, append(encoded, '\n')); err != nil {
			return Config{}, err
		}
	}
	if value := strings.TrimSpace(os.Getenv("LOCAL_PROXY_USER")); value != "" {
		config.Username = value
	}
	if value := os.Getenv("LOCAL_PROXY_PASS"); value != "" {
		config.Password = value
	}
	if value := strings.TrimSpace(os.Getenv("LOCAL_PROXY_HOST")); value != "" {
		config.ProxyHost = value
	}
	if value := strings.TrimSpace(os.Getenv("LOCAL_PROXY_PORT")); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil {
			return Config{}, fmt.Errorf("LOCAL_PROXY_PORT: %w", err)
		}
		config.ProxyPort = port
	}
	return config, config.validate()
}

func (c Config) validate() error {
	switch {
	case !accountPattern.MatchString(c.Username):
		return errors.New("username must be 1-64 letters, digits, '_', '.' or '-'")
	case c.Password == "":
		return errors.New("password must not be empty")
	case c.ProxyPort < 1 || c.ProxyPort > 65535:
		return fmt.Errorf("proxy port %d is invalid", c.ProxyPort)
	case c.MaxTunnels < 1 || c.MaxTunnels > 1000:
		return fmt.Errorf("max_tunnels must be 1-1000, got %d", c.MaxTunnels)
	case c.MinIdleTunnels < 0 || c.MinIdleTunnels > c.MaxTunnels:
		return fmt.Errorf("min_idle_tunnels must be 0-%d, got %d", c.MaxTunnels, c.MinIdleTunnels)
	case c.TUNBase < 0:
		return errors.New("tun_base must not be negative")
	case c.NodeMaxAgeDays < 1 || c.NodeMaxFailures < 1:
		return errors.New("node_max_age_days and node_max_failures must be positive")
	case len(c.APIURLs) == 0:
		return errors.New("api_urls must not be empty")
	}
	return nil
}

func randomHex(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		// crypto/rand only fails when the OS entropy source is broken.
		panic(err)
	}
	return hex.EncodeToString(buffer)
}
