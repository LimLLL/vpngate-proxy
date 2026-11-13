package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

func main() {
	source := flag.String("source", "https://www.vpngate.net/api/iphone/", "VPNGate CSV endpoint")
	fixture := flag.String("fixture", "", "use a prepared CSV rather than downloading")
	fallback := flag.String("fallback", "nodes/testdata/vpngate.csv", "offline snapshot if the official endpoint fails")
	outputDir := flag.String("output-dir", "candidates", "directory for the validated native profiles, 01.ovpn first")
	count := flag.Int("count", 5, "number of profiles, each from a different /24 network")
	snapshotOutput := flag.String("snapshot-output", "", "optional exact source CSV retention path")
	device := flag.String("device", "tun0", "fixed client TUN interface")
	flag.Parse()
	if err := prepare(*source, *fixture, *fallback, *outputDir, *snapshotOutput, *device, *count); err != nil {
		log.Fatal(err)
	}
}

// prepare writes the best scored candidates, at most one per /24 network so
// that a busy cluster such as VPNGate's academic servers cannot take every
// slot, for the probe to try in order.
func prepare(sourceURL, fixture, fallback, outputDir, snapshotOutput, device string, count int) error {
	if !regexp.MustCompile(`^tun[0-9]*$`).MatchString(device) {
		return errors.New("client device must be tun or tunN")
	}
	if count < 1 {
		return errors.New("count must be positive")
	}
	var data []byte
	var err error
	if fixture != "" {
		data, err = os.ReadFile(fixture)
	} else {
		data, err = download(sourceURL)
		if err != nil {
			log.Printf("official VPNGate download failed; using verified offline snapshot: %v", err)
			data, err = os.ReadFile(fallback)
		}
	}
	if err != nil {
		return err
	}
	candidates, err := nodes.ParseCSV(data)
	if err != nil {
		return err
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return err
	}
	var written []map[string]any
	taken := make(map[string]bool)
	for _, candidate := range candidates {
		if len(written) == count {
			break
		}
		if network := nodes.Network(candidate.IP); !taken[network] {
			taken[network] = true
			file := filepath.Join(outputDir, fmt.Sprintf("%02d.ovpn", len(written)+1))
			profile := nodes.PrepareProfile(candidate.Profile, device)
			if err := os.WriteFile(file, []byte(profile), 0o600); err != nil {
				return err
			}
			written = append(written, map[string]any{"candidate": candidate.ID, "score": candidate.Score, "file": file})
		}
	}
	if snapshotOutput != "" {
		if err := os.WriteFile(snapshotOutput, data, 0o600); err != nil {
			return err
		}
	}
	formatted, err := json.MarshalIndent(written, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(formatted))
	return nil
}

func download(source string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPNGate API returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 12*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 12*1024*1024 {
		return nil, fmt.Errorf("snapshot exceeds 12 MiB")
	}
	return body, nil
}
