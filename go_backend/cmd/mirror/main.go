package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
)

const maxSnapshotSize = 12 * 1024 * 1024

type mirrorMetadata struct {
	SchemaVersion  int    `json:"schema_version"`
	Source         string `json:"source"`
	GeneratedAt    int64  `json:"generated_at"`
	GeneratedAtISO string `json:"generated_at_iso"`
	RowCount       int    `json:"row_count"`
	ByteCount      int    `json:"byte_count"`
	SHA256         string `json:"sha256"`
}

func main() {
	output := flag.String("output-dir", "mirror", "snapshot destination")
	source := flag.String("source", env("VPNGATE_API_HTTPS_URL", "https://www.vpngate.net/api/iphone/"), "VPNGate API source")
	fixture := flag.String("fixture", "", "validated local input, used by continuous integration without live VPNGate availability")
	timeout := flag.Duration("timeout", 20*time.Second, "source fetch timeout")
	flag.Parse()
	var data []byte
	var err error
	if *fixture != "" {
		data, err = os.ReadFile(*fixture)
		if err == nil {
			if len(data) > maxSnapshotSize {
				err = fmt.Errorf("input exceeds %d bytes", maxSnapshotSize)
			}
		}
	} else {
		data, err = fetch(*source, *timeout)
	}
	if err != nil {
		log.Fatal(err)
	}
	metadata, err := validate(data, *source)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*output, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := atomic(filepath.Join(*output, "vpngate.csv"), data); err != nil {
		log.Fatal(err)
	}
	encoded, _ := json.MarshalIndent(metadata, "", "  ")
	if err := atomic(filepath.Join(*output, "vpngate.meta.json"), append(encoded, '\n')); err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(encoded))
}

func env(key, fallback string) string {
	if value := os.Getenv(key); strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func fetch(source string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 || timeout > time.Minute {
		return nil, fmt.Errorf("timeout must be between 1ms and 1m")
	}
	req, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AimiliVPN-Go-Mirror/1.0")
	req.Header.Set("Accept", "text/plain,*/*")
	response, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPNGate returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 12*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 12*1024*1024 {
		return nil, fmt.Errorf("VPNGate snapshot exceeds 12 MiB")
	}
	return data, nil
}

func validate(data []byte, source string) (mirrorMetadata, error) {
	sourceReader := &gateway.Source{}
	if err := sourceReader.LoadSnapshot(data); err != nil {
		return mirrorMetadata{}, err
	}
	now := time.Now().UTC()
	digest := sha256.Sum256(data)
	return mirrorMetadata{
		SchemaVersion: 1, Source: source, GeneratedAt: now.Unix(),
		GeneratedAtISO: now.Format(time.RFC3339Nano), RowCount: len(sourceReader.Candidates()),
		ByteCount: len(data), SHA256: hex.EncodeToString(digest[:]),
	}, nil
}

func atomic(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
