package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

func run() (resultErr error) {
	profilePath := flag.String("profile", "", "validated native profile path")
	stay := flag.Duration("stay", 10*time.Second, "time to keep the tunnel alive after traffic verification")
	readyFile := flag.String("connected-file", "", "optional native readiness report")
	target := flag.String("url", "", "verify real egress through this TUN when provided")
	flag.Parse()
	if *profilePath == "" || *stay < 0 {
		return errors.New("a profile and a nonnegative stay duration are required")
	}
	candidates, err := nodes.LoadProfiles(*profilePath)
	if err != nil {
		return err
	}
	candidate := candidates[0]
	started := time.Now()
	contextConnect, cancelConnect := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancelConnect()
	endpoint, err := gateway.ConnectNative(contextConnect, candidate, "tun0", 0, 30*time.Second)
	if err != nil {
		return fmt.Errorf("connect native tunnel: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stopStarted := time.Now()
		if err := endpoint.Close(closeCtx); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close native tunnel: %w", err))
		}
		log.Printf("stop_ms=%d", time.Since(stopStarted).Milliseconds())
	}()
	info, err := endpoint.Info()
	if err != nil {
		return err
	}
	if info.TUNName != "tun0" {
		return fmt.Errorf("native probe expected tun0, got %q", info.TUNName)
	}
	result := map[string]any{
		"connected": true, "native_route": true, "connect_ms": time.Since(started).Milliseconds(),
		"candidate": candidate.ID, "info": info, "proxy_verified": false,
	}
	if *target != "" {
		egress, err := verifyEgress(context.Background(), info.TUNName, *target)
		if err != nil {
			return err
		}
		result["egress_ip"] = egress
		result["proxy_verified"] = true
		result["verified_url"] = *target
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	if *readyFile != "" {
		if err := os.WriteFile(*readyFile, encoded, 0o600); err != nil {
			return fmt.Errorf("write native readiness: %w", err)
		}
	}
	time.Sleep(*stay)
	return nil
}

func verifyEgress(parent context.Context, device, target string) (string, error) {
	dialer := gateway.DeviceDialer{Device: device, DNS: "8.8.8.8"}
	transport := &http.Transport{DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
		host, rawPort, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port := 80
		if rawPort != "" {
			if _, err := fmt.Sscanf(rawPort, "%d", &port); err != nil {
				return nil, fmt.Errorf("invalid requested port %q", rawPort)
			}
		}
		return dialer.DialContext(ctx, host, port)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("verify public egress through %s: %w", device, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if response.StatusCode != http.StatusOK || ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("public egress service returned invalid response: status=%d body=%q", response.StatusCode, body)
	}
	return ip.String(), nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
