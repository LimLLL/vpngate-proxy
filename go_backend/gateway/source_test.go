package gateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
)

func testProfile(extra string) string {
	return fmt.Sprintf(`client
dev tun
proto udp
remote 192.0.2.10 443
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
data-ciphers AES-128-CBC
%s
<ca>
-----BEGIN CERTIFICATE-----
test-certificates-are-parsed-by-native-core-not-this-validator
</ca>
`, extra)
}

func TestSourceRejectsProfileScriptsAndInvalidCSV(t *testing.T) {
	for _, profile := range []string{
		"client\ndev tun\nup /tmp/arbitrary-command\nremote 192.0.2.10 443\n",
		"client\ndev tun\nremote 192.0.2.10 443\nup-restart\n",
		"client\ndev tun\nremote 192.0.2.10 443\nauth-user-pass /etc/passwd\n",
	} {
		if err := SafeProfile(profile); err == nil {
			t.Fatalf("unsafe profile was accepted: %q", profile)
		}
	}
	if err := SafeProfile(testProfile("cipher AES-128-CBC")); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotPingFallback(t *testing.T) {
	header := "HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
	record := func(host, ip, ping string) string {
		return fmt.Sprintf("%s,%s,1,%s,100,Japan,JP,1,1,1,1,test,test,,%s", host, ip, ping, base64.StdEncoding.EncodeToString([]byte(testProfile(""))))
	}
	data := "*vpn_servers\n#" + strings.TrimSuffix(header, "\n") + "\n" + record("low", "192.0.2.11", "1") + "\n" +
		record("unknown", "192.0.2.12", "-") + "\n"
	source := &Source{}
	if err := source.LoadSnapshot([]byte(data)); err != nil {
		t.Fatal(err)
	}
	candidates := source.Candidates()
	if len(candidates) != 2 || candidates[0].Ping != 1 || candidates[1].Ping != 999999 || candidates[1].HostName != "unknown" {
		t.Fatalf("unexpected ranked candidates: %+v", candidates)
	}
}

func TestBundledSnapshotAndNativeProfileEvaluation(t *testing.T) {
	source := NewSnapshotFileSource(filepath.Join("..", "..", "mirror", "vpngate.csv"))
	candidate, err := source.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	client, err := core.NewClient(candidate.Profile, "vpn", "vpn", 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialAndHeaderParsing(t *testing.T) {
	user, password, err := proxyBasicCredentials("Basic c2Vzc2lvbi1hcHAtdC0xOnNlY3JldA==")
	if err != nil || user != "session-app-t-1" || password != "secret" {
		t.Fatalf("unexpected proxy credentials %q %q %v", user, password, err)
	}
	if _, _, err := proxyBasicCredentials("Basic bm9jb2xvbg=="); err == nil {
		t.Fatal("missing colon unexpectedly authenticated")
	}
	host, port, err := proxyAuthority("example.com:8443")
	if err != nil || host != "example.com" || port != 8443 {
		t.Fatalf("unexpected target %s %d %v", host, port, err)
	}
	host, port, err = proxyAuthority("[2001:db8::1]:443")
	if err != nil || host != "2001:db8::1" || port != 443 {
		t.Fatalf("IPv6 target parsed incorrectly: %s %d %v", host, port, err)
	}
}
