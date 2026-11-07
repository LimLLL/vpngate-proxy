package web

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (d *DataStore) stateFile() string { return filepath.Join(d.Dir, "state.json") }

func (d *DataStore) SetState(update map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := make(map[string]any)
	if data, err := os.ReadFile(d.stateFile()); err == nil {
		if err := json.Unmarshal(data, &state); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for key, value := range update {
		if key == "password" {
			return errors.New("password must be stored only in ui_auth.json")
		}
		state[key] = value
	}
	return writeJSON(d.stateFile(), state)
}

func (d *DataStore) State() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := make(map[string]any)
	_ = readJSON(d.stateFile(), &state)
	config := d.Config
	delete(state, "password")
	state["username"] = config.Username
	state["password_set"] = config.Password != ""
	state["secret_path"] = config.SecretPath
	state["port"] = config.Port
	state["proxy_port"] = config.ProxyPort
	state["proxy_host"] = config.ProxyHost
	state["routing_mode"] = config.RoutingMode
	state["force_country"] = config.ForceCountry
	state["routing_ip_type"] = config.RoutingIPType
	state["connection_enabled"] = config.ConnectionEnabled
	state["fixed_node_id"] = config.FixedNodeID
	state["favorite_node_ids"] = append([]string(nil), config.FavoriteNodeIDs...)
	state["discovery_countries"] = append([]string(nil), config.DiscoveryCountries...)
	state["fav_fail_fallback"] = false
	proxyHost := config.ProxyHost
	if strings.Contains(proxyHost, ":") {
		proxyHost = "[" + proxyHost + "]"
	}
	state["local_proxy"] = "http://" + proxyHost + ":" + strconv.Itoa(config.ProxyPort)
	return state
}
