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

func loopbackProfile(profile string) (string, bool) {
	var output strings.Builder
	insideInlineBlock := false
	replaced := false
	for _, line := range strings.Split(profile, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if insideInlineBlock {
			output.WriteString(line + "\n")
			if strings.HasPrefix(lower, "</") {
				insideInlineBlock = false
			}
			continue
		}
		if strings.HasPrefix(lower, "<") {
			insideInlineBlock = true
			output.WriteString(line + "\n")
			continue
		}
		if strings.HasPrefix(lower, "remote ") {
			if !replaced {
				output.WriteString("remote 127.0.0.1 1 udp\n")
				replaced = true
			}
			continue
		}
		output.WriteString(line + "\n")
	}
	return output.String(), replaced
}

func TestFailedNativeConnectionCanBeClosed(t *testing.T) {
	path := os.Getenv("VPNGATE_TEST_PROFILE")
	if path == "" {
		t.Skip("workflow provides a real profile for the native failure-path test")
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	profile, foundRemote := loopbackProfile(string(bytes))
	if !foundRemote {
		t.Fatal("candidate has no top-level remote to redirect to loopback")
	}
	client, err := NewClient(profile, "vpn", "vpn", 2)
	if err != nil {
		t.Fatal(err)
	}

	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	_, connectErr := client.Connect(connectCtx)
	cancelConnect()
	if connectErr == nil {
		t.Fatal("native connection to an unused loopback UDP port unexpectedly connected")
	}
	t.Logf("expected native connection failure: %v", connectErr)

	closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClose()
	if err := client.Close(closeCtx); err != nil {
		t.Fatalf("close after failed connection: %v", err)
	}
	if err := client.Close(closeCtx); err != nil {
		t.Fatalf("repeated close after failed connection: %v", err)
	}
}
