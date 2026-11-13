package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// TestBundledProfilesPassNativeEvaluation checks that profiles accepted by the
// Go validator, after PrepareProfile, are also accepted by OpenVPN 3 Core.
func TestBundledProfilesPassNativeEvaluation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "nodes", "testdata", "vpngate.csv"))
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := nodes.ParseCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates[:min(5, len(candidates))] {
		client, err := core.NewClient(nodes.PrepareProfile(candidate.Profile, "tun0"), "vpn", "vpn", 2)
		if err != nil {
			t.Fatalf("%s: %v", candidate.ID, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = client.Close(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
}
