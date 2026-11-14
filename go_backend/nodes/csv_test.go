package nodes

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testProfile(extra string) string {
	return fmt.Sprintf(`client
dev tun
proto udp
remote 192.0.2.10 443
nobind
persist-key
persist-tun
cipher AES-128-CBC
%s
<ca>
syntax-only-ca
</ca>
<cert>
syntax-only-cert
</cert>
<key>
syntax-only-key
</key>
`, extra)
}

func testListing(rows ...string) []byte {
	header := "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
	return []byte("*vpn_servers\n" + header + "\n" + strings.Join(rows, "\n") + "\n*\n")
}

func testRow(host, ip, country, ping, score, profile string) string {
	return fmt.Sprintf("%s,%s,%s,%s,100,Country %s,%s,1,1,1,1,test,test,,%s",
		host, ip, score, ping, country, country, base64.StdEncoding.EncodeToString([]byte(profile)))
}

func TestParseCSV(t *testing.T) {
	data := testListing(
		testRow("a", "192.0.2.11", "jp", "1", "50", testProfile("")),
		testRow("b", "192.0.2.12", "US", "-", "70", testProfile("")),
		testRow("dup", "192.0.2.11", "JP", "3", "10", testProfile("")),
		testRow("unsafe", "192.0.2.13", "JP", "1", "10", testProfile("up /bin/sh")),
	)
	candidates, err := ParseCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("want 2 candidates (duplicate IP and unsafe profile dropped), got %+v", candidates)
	}
	first, second := candidates[0], candidates[1]
	if first.ID != "192.0.2.11" || first.Country != "JP" || first.HostName != "a" || first.Ping != 1 || first.Score != 50 {
		t.Fatalf("unexpected first candidate: %+v", first)
	}
	if second.Ping != 999999 || second.RemoteHost != "192.0.2.10" || second.RemotePort != "443" || second.Protocol != "udp" {
		t.Fatalf("unexpected second candidate: %+v", second)
	}
	tcp, err := ParseCSV(testListing(testRow("t", "192.0.2.15", "JP", "1", "1", strings.Replace(testProfile(""), "proto udp", "proto tcp-client", 1))))
	if err != nil || tcp[0].Protocol != "tcp" {
		t.Fatalf("the proto directive was ignored: %+v %v", tcp, err)
	}
	if _, err := ParseCSV(testListing(testRow("x", "192.0.2.14", "JP", "1", "1", "client\n"))); err == nil {
		t.Fatal("a listing without usable profiles was accepted")
	}
}

func TestSafeProfileRejectsScriptsAndFiles(t *testing.T) {
	for _, profile := range []string{
		"client\ndev tun\nup /tmp/arbitrary-command\nremote 192.0.2.10 443\n",
		"client\ndev tun\nremote 192.0.2.10 443\nup-restart\n",
		"client\ndev tun\nremote 192.0.2.10 443\nauth-user-pass /etc/passwd\n",
		"client\ndev tap0\nremote 192.0.2.10 443\n",
	} {
		if err := SafeProfile(profile); err == nil {
			t.Errorf("unsafe profile was accepted: %q", profile)
		}
	}
	if err := SafeProfile(testProfile("")); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareProfilePinsDeviceAndRoutes(t *testing.T) {
	prepared := PrepareProfile(testProfile(""), "tun7")
	if !strings.Contains(prepared, "\ndev tun7\n") || strings.Contains(prepared, "\ndev tun\n") {
		t.Fatalf("device was not pinned:\n%s", prepared)
	}
	if !strings.Contains(prepared, "route-nopull") {
		t.Fatal("route-nopull was not added")
	}
	if err := SafeProfile(prepared); err != nil {
		t.Fatalf("prepared profile is no longer safe: %v", err)
	}
}

func TestBundledSnapshotParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vpngate.csv"))
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := ParseCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if candidate.ID != candidate.IP || len(candidate.Country) != 2 {
			t.Fatalf("malformed candidate %+v", candidate)
		}
	}
}

func TestLoadProfiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.ovpn", "a.ovpn"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(testProfile("")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := LoadProfiles(filepath.Join(dir, "*.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].ID != "a.ovpn" || candidates[1].ID != "b.ovpn" {
		t.Fatalf("unexpected profiles: %+v", candidates)
	}
}
