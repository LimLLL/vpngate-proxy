package main

import (
	"os"
	"path/filepath"
)

func writeReady(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("ready\n"), 0o600)
}
