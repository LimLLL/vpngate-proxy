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
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
)

func main() {
	source := flag.String("source", "https://www.vpngate.net/api/iphone/", "VPNGate CSV endpoint")
	fixture := flag.String("fixture", "", "use a prepared CSV rather than downloading")
	fallback := flag.String("fallback", "mirror/vpngate.csv", "offline snapshot if the official endpoint fails")
	output := flag.String("output", "candidate.ovpn", "validated native profile path")
	snapshotOutput := flag.String("snapshot-output", "", "optional exact source CSV retention path")
	device := flag.String("device", "tun0", "fixed client TUN interface")
	flag.Parse()
	if err := prepare(*source, *fixture, *fallback, *output, *snapshotOutput, *device); err != nil {
		log.Fatal(err)
	}
}

func prepare(sourceURL, fixture, fallback, output, snapshotOutput, device string) error {
	if !regexp.MustCompile(`^tun[0-9]*$`).MatchString(device) {
		return errors.New("client device must be tun or tunN")
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
	source := &gateway.Source{}
	if err := source.LoadSnapshot(data); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	candidate, err := source.Next(ctx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	profile := gateway.PrepareProfile(candidate.Profile, device)
	if err := os.WriteFile(output, []byte(profile), 0o600); err != nil {
		return err
	}
	if snapshotOutput != "" {
		if err := os.WriteFile(snapshotOutput, data, 0o600); err != nil {
			return err
		}
	}
	metadata := map[string]any{"candidate": candidate.ID, "host": candidate.IP,
		"file": output, "profile_bytes": len(profile)}
	formatted, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(formatted))
	return nil
}

func download(source string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
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
