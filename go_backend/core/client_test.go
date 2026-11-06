package core

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNativePlatform(t *testing.T) {
	if platform := Platform(); !strings.Contains(platform, "OpenVPN") && !strings.Contains(platform, "x86_64") {
		t.Fatalf("unexpected native platform string: %q", platform)
	}
}

func TestInvalidProfileIsRejectedByNativeEval(t *testing.T) {
	_, err := NewClient("client\nnot an OpenVPN profile\n", "vpn", "vpn", 2)
	if err == nil {
		t.Fatal("native profile evaluation unexpectedly accepted invalid input")
	}
}

func TestRealVPNGateProfileEvalAndRelease(t *testing.T) {
	path := os.Getenv("VPNGATE_TEST_PROFILE")
	if path == "" {
		t.Skip("workflow sets VPNGATE_TEST_PROFILE to a prepared live candidate")
	}
	profile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(string(profile), "vpn", "vpn", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Close(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	}()
}
