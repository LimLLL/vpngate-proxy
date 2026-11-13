package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is persisted in ui_auth.json; the file name predates the removal of
// the management UI and is kept so existing data directories still load.
// Password is the proxy password unless LOCAL_PROXY_PASS overrides it.
type Config struct {
	Password           string    `json:"password"`
	ProxyHost          string    `json:"proxy_host"`
	ProxyPort          int       `json:"proxy_port"`
	RoutingMode        string    `json:"routing_mode"`
	ForceCountry       string    `json:"force_country"`
	RoutingIPType      string    `json:"routing_ip_type"`
	ConnectionEnabled  bool      `json:"connection_enabled"`
	FixedNodeID        string    `json:"fixed_node_id"`
	FavoriteNodeIDs    []string  `json:"favorite_node_ids"`
	FavFailFallback    bool      `json:"fav_fail_fallback"`
	DiscoveryCountries []string  `json:"discovery_countries"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

type DataStore struct {
	mu     sync.Mutex
	Config Config
	Dir    string
}

func NewDataStore(dir string) (*DataStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("data directory is required")
	}
	config := Config{
		ProxyHost: "127.0.0.1", ProxyPort: 7928, RoutingMode: "auto",
		RoutingIPType: "all", ConnectionEnabled: true, FavoriteNodeIDs: []string{},
		DiscoveryCountries: []string{},
	}
	store := &DataStore{Config: config, Dir: dir}
	if err := os.MkdirAll(filepath.Join(dir, "configs"), 0o700); err != nil {
		return nil, err
	}
	filename := store.authFile()
	if data, err := os.ReadFile(filename); err == nil {
		_ = os.Chmod(filename, 0o600)
		if err := json.Unmarshal(data, &store.Config); err != nil {
			return nil, fmt.Errorf("read ui_auth.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return store, nil
}

func (d *DataStore) authFile() string { return filepath.Join(d.Dir, "ui_auth.json") }

func (d *DataStore) Snapshot() Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := d.Config
	result.FavoriteNodeIDs = append([]string(nil), d.Config.FavoriteNodeIDs...)
	result.DiscoveryCountries = append([]string(nil), d.Config.DiscoveryCountries...)
	return result
}

func (d *DataStore) Save(config Config) (Config, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	config.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return Config{}, err
	}
	temp, err := os.CreateTemp(d.Dir, ".ui-auth-*")
	if err != nil {
		return Config{}, err
	}
	temporary := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(temporary)
	}
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return Config{}, err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		cleanup()
		return Config{}, err
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return Config{}, err
	}
	if err := temp.Close(); err != nil {
		cleanup()
		return Config{}, err
	}
	if err := os.Rename(temporary, d.authFile()); err != nil {
		cleanup()
		return Config{}, err
	}
	d.Config = config
	return config, nil
}

func nonempty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func intBetween(value any, fallback, low, high int) int {
	switch value := value.(type) {
	case float64:
		return int(value)
	case int:
		return value
	case string:
		number, err := strconv.Atoi(value)
		if err == nil {
			return number
		}
	}
	return fallback
}

// RandomCredential generates only proxy credentials, never a node profile.
func RandomCredential(length int) (string, error) {
	if length < 1 || length > 256 {
		return "", errors.New("credential length must be between 1 and 256")
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}
