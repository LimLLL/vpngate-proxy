package web

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
	"sync"
	"time"
)

// Config keeps the existing management JSON fields so existing deployments can
// upgrade without moving secrets into node or proxy API responses.
type Config struct {
	Username           string    `json:"username"`
	Password           string    `json:"password"`
	SecretPath         string    `json:"secret_path"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
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
		SecretPath: "EJsW2EeBo9lY", Host: "::", Port: 8787,
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
			return nil, fmt.Errorf("read management config: %w", err)
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

// RandomCredential generates only UI/session credentials, never a node profile.
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

var countryPattern = regexp.MustCompile(`^[A-Za-z]{2}$`)

func normalizeCountries(input any) []string {
	var result []string
	seen := make(map[string]bool)
	switch values := input.(type) {
	case []any:
		for _, value := range values {
			text := strings.ToUpper(strings.TrimSpace(fmt.Sprint(value)))
			if !countryPattern.MatchString(text) || seen[text] {
				continue
			}
			seen[text] = true
			result = append(result, text)
		}
	case []string:
		for _, value := range values {
			text := strings.ToUpper(strings.TrimSpace(value))
			if !countryPattern.MatchString(text) || seen[text] {
				continue
			}
			seen[text] = true
			result = append(result, text)
		}
	}
	return result
}
