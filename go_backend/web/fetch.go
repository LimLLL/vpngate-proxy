package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
)

// SnapshotFetcher pulls the node list straight from the VPNGate API. The last
// fetched copy and the bundled snapshot are offline fallbacks, never proof of
// connection.
type SnapshotFetcher struct {
	Dir      string
	Mirror   string
	Client   *http.Client
	LastInfo map[string]any
}

func (f *SnapshotFetcher) fetch(ctx context.Context, target *gateway.Source) error {
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	urls := []string{
		nonempty(os.Getenv("VPNGATE_API_HTTPS_URL"), "https://www.vpngate.net/api/iphone/"),
		nonempty(os.Getenv("VPNGATE_API_HTTP_URL"), "http://www.vpngate.net/api/iphone/"),
	}
	var failures []error
	for _, address := range urls {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", address, err))
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 12*1024*1024+1))
		_ = response.Body.Close()
		if readErr != nil {
			failures = append(failures, readErr)
			continue
		}
		if response.StatusCode != http.StatusOK {
			failures = append(failures, fmt.Errorf("%s: HTTP %d", address, response.StatusCode))
			continue
		}
		if len(data) > 12*1024*1024 {
			failures = append(failures, fmt.Errorf("%s: response exceeds 12 MiB", address))
			continue
		}
		candidate := &gateway.Source{}
		if err := candidate.LoadSnapshot(data); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", address, err))
			continue
		}
		target.SetCandidates(candidate.Candidates())
		_ = os.WriteFile(filepath.Join(f.Dir, "api_snapshot.csv"), data, 0o600)
		_ = writeJSON(filepath.Join(f.Dir, "api_snapshot.meta.json"), map[string]any{
			"source": address, "fetched_at": time.Now().Unix(),
		})
		return nil
	}
	for _, path := range []string{filepath.Join(f.Dir, "api_snapshot.csv"), f.Mirror} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := target.LoadSnapshot(data); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", path, err))
			continue
		}
		fmt.Printf("Using offline OpenVPN snapshot: %s\n", path)
		return nil
	}
	if len(failures) == 0 {
		failures = append(failures, errors.New("no valid snapshot source"))
	}
	return errors.Join(failures...)
}
