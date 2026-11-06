package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
)

func run() (resultErr error) {
	src := flag.String("profile", "", "path to a prepared VPNGate profile")
	stay := flag.Duration("stay", 10*time.Second, "how long to keep the connected tunnel active")
	readyFile := flag.String("connected-file", "", "optional path for the ready tunnel JSON")
	flag.Parse()
	if *src == "" {
		log.Fatal("--profile is required")
	}
	profile, err := os.ReadFile(*src)
	if err != nil {
		return err
	}

	started := time.Now()
	client, err := core.NewClient(string(profile), "vpn", "vpn", 15)
	if err != nil {
		return err
	}
	go func() {
		for text := range client.Logs {
			fmt.Printf("[native] %s", text)
		}
	}()
	client.OnEvent = func(event core.Event) {
		fmt.Printf("[go event] %+v\n", event)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	defer func() {
		stopped := time.Now()
		if err := client.Close(closeCtx); err != nil && resultErr == nil {
			resultErr = fmt.Errorf("close native connection: %w", err)
		}
		fmt.Printf("stop_ms=%d\n", time.Since(stopped).Milliseconds())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	info, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	result := map[string]any{
		"connected":  true,
		"connect_ms": time.Since(started).Milliseconds(),
		"info":       info,
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	if info.TUNName != "tun0" {
		return fmt.Errorf("expected tun0, got %q", info.TUNName)
	}
	if *readyFile != "" {
		if err := os.WriteFile(*readyFile, encoded, 0o600); err != nil {
			return fmt.Errorf("write ready file: %w", err)
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
