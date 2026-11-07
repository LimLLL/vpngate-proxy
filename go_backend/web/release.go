package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func checkLatestRelease(ctx context.Context) (map[string]any, error) {
	ownerRepository := nonempty(os.Getenv("GITHUB_REPOSITORY"), "LimLLL/vpngate-proxy")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+ownerRepository+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "vpngate-proxy/"+AppVersion)
	client, err := newHTTPClient()
	if err != nil {
		return nil, err
	}
	client.Timeout = 10 * time.Second
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub release lookup returned HTTP %d", response.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&release); err != nil {
		return nil, err
	}
	return map[string]any{
		"current_version":  AppVersion,
		"version":          AppVersion,
		"version_label":    "V" + AppVersion + " Go 原生版",
		"latest_version":   release.TagName,
		"update_available": isNewerRelease(release.TagName, AppVersion),
		"release_url":      release.HTMLURL,
		"name":             release.Name,
	}, nil
}

func isNewerRelease(latest, current string) bool {
	newelVersional := parseVersion(latest)
	curentVersional := parseVersion(current)
	for i := 0; i < 3; i++ {
		if newelVersional[i] > curentVersional[i] {
			return true
		}
		if newelVersional[i] < curentVersional[i] {
			return false
		}
	}
	return false
}

func parseVersion(version string) [3]int {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	var result [3]int
	for i := range min(3, len(parts)) {
		before, _, _ := strings.Cut(parts[i], "-")
		result[i], _ = strconv.Atoi(before)
	}
	return result
}
