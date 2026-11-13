package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
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
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		egress, err := gateway.ProbeEgress(ctx, info.TUNName, *target)
		cancel()
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
