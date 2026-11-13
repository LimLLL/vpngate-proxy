package web

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
