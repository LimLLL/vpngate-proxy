package nodes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Fetch downloads and parses the first VPNGate listing that succeeds. The
// client should honor HTTPS_PROXY etc. (http.DefaultTransport does) for hosts
// that cannot reach vpngate.net directly.
func Fetch(ctx context.Context, client *http.Client, urls []string) ([]Candidate, error) {
	var failures []error
	for _, url := range urls {
		candidates, err := fetchOne(ctx, client, url)
		if err == nil {
			return candidates, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", url, err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(failures) == 0 {
		return nil, errors.New("no VPNGate API URL configured")
	}
	return nil, errors.Join(failures...)
}

func fetchOne(ctx context.Context, client *http.Client, url string) ([]Candidate, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSnapshotSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSnapshotSize {
		return nil, errors.New("listing exceeds 12 MiB")
	}
	return ParseCSV(body)
}
