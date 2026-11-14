package nodes

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const maxProfileSize = 128 * 1024

// PrepareProfile pins the requested TUN and blocks provider route replacement,
// so only sockets bound to that TUN use the tunnel.
func PrepareProfile(profile, device string) string {
	var output strings.Builder
	block := false
	seenDev, routeNoPull := false, false
	for _, line := range strings.Split(strings.ReplaceAll(profile, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if block {
			output.WriteString(line + "\n")
			if strings.HasPrefix(lower, "</") {
				block = false
			}
			continue
		}
		directive := strings.TrimLeft(lower, "-")
		switch {
		case strings.HasPrefix(lower, "<"):
			block = true
		case strings.HasPrefix(directive, "dev ") || directive == "dev":
			output.WriteString("dev " + device + "\n")
			seenDev = true
			continue
		case directive == "route-nopull":
			routeNoPull = true
		}
		output.WriteString(line + "\n")
	}
	if !seenDev {
		output.WriteString("dev " + device + "\n")
	}
	if !routeNoPull {
		output.WriteString("route-nopull\n")
	}
	return output.String()
}

var acceptedProfileDirectives = map[string]bool{
	"auth": true, "auth-user-pass": true, "auth-nocache": true, "cipher": true, "client": true,
	"comp-lzo": true, "compress": true, "comp-noadapt": true, "connect-retry": true,
	"connect-timeout": true, "explicit-exit-notify": true,
	"connect-retry-max": true, "data-ciphers": true, "data-ciphers-fallback": true,
	"dev": true, "dev-type": true, "dhcp-option": true, "keepalive": true,
	"key-direction": true, "mute": true, "nobind": true, "persist-key": true,
	"persist-tun": true, "ping": true, "ping-restart": true, "ping-timer-rem": true,
	"proto": true, "pull": true, "rcvbuf": true, "remote": true, "remote-cert-tls": true,
	"remote-random": true, "remote-random-hostname": true, "reneg-sec": true,
	"resolv-retry": true, "route-delay": true, "route-nopull": true, "sndbuf": true,
	"tls-cipher": true, "tls-ciphersuites": true, "tls-client": true,
	"tls-version-min": true, "verb": true, "verify-x509-name": true,
}

// SafeProfile limits third-party profiles to plain connection settings:
// scripts, plugins, external files and unknown directives are rejected.
func SafeProfile(profile string) error {
	if len(profile) == 0 || len(profile) > maxProfileSize || strings.ContainsRune(profile, '\x00') {
		return errors.New("profile has invalid size or contains a NUL byte")
	}
	block := ""
	seenClient, seenRemote := false, false
	scanner := bufio.NewScanner(strings.NewReader(profile))
	scanner.Buffer(make([]byte, 1024), 8192)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if block != "" {
			if line == "</"+block+">" {
				block = ""
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			block = strings.Trim(line, "<>")
			if block != "ca" && block != "cert" && block != "key" && block != "tls-auth" && block != "tls-crypt" {
				return fmt.Errorf("unsafe profile block %s", block)
			}
			continue
		}
		parts := strings.Fields(line)
		name := strings.TrimLeft(parts[0], "-")
		if (name == "auth-user-pass" || name == "ca" || name == "cert" || name == "key" || name == "tls-auth" || name == "tls-crypt") && len(parts) > 1 {
			return fmt.Errorf("external files are not allowed for %s", name)
		}
		if !acceptedProfileDirectives[name] {
			return fmt.Errorf("unsafe profile directive %s", name)
		}
		switch name {
		case "client":
			seenClient = true
		case "remote":
			if len(parts) < 3 {
				return errors.New("incomplete remote directive")
			}
			port, err := strconv.Atoi(parts[2])
			if err != nil || port < 1 || port > 65535 {
				return errors.New("invalid remote port")
			}
			seenRemote = true
		case "dev":
			if len(parts) < 2 || !strings.HasPrefix(parts[1], "tun") || len(parts[1]) > 3 && !digits(parts[1][3:]) {
				return errors.New("only an explicit or numbered TUN device is accepted")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if block != "" || !seenClient || !seenRemote {
		return errors.New("profile lacks client/remote or has an unterminated block")
	}
	return nil
}

// LoadProfiles turns local .ovpn files into candidates; the CI testbed and the
// probe use it instead of the VPNGate listing. IDs are the file names.
func LoadProfiles(pattern string) ([]Candidate, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no profiles matched %q", pattern)
	}
	sort.Strings(files)
	result := make([]Candidate, 0, len(files))
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		profile := string(data)
		if err := SafeProfile(profile); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		host, port, protocol := parseRemote(profile, "")
		result = append(result, Candidate{
			ID: filepath.Base(path), IP: host, RemoteHost: host, RemotePort: port,
			Protocol: protocol, Profile: profile,
		})
	}
	return result, nil
}

// parseRemote reads the first remote and its transport. As in OpenVPN, a
// protocol on the remote line wins over the proto directive, which is where
// VPNGate profiles put it. Any tcp variant counts as tcp.
func parseRemote(profile, fallback string) (host, port, protocol string) {
	host, port, protocol = fallback, "1194", "udp"
	remoteProtocol, found := "", false
	for _, line := range strings.Split(profile, "\n") {
		parts := strings.Fields(line)
		switch {
		case len(parts) > 1 && parts[0] == "proto":
			protocol = parts[1]
		case len(parts) > 1 && parts[0] == "remote" && !found:
			found = true
			host = parts[1]
			if len(parts) > 2 {
				port = parts[2]
			}
			if len(parts) > 3 {
				remoteProtocol = parts[3]
			}
		}
	}
	if remoteProtocol != "" {
		protocol = remoteProtocol
	}
	if strings.HasPrefix(strings.ToLower(protocol), "tcp") {
		return host, port, "tcp"
	}
	return host, port, "udp"
}

func digits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hasCertificateBlocks requires inline ca/cert/key: genuine VPNGate profiles
// always embed all three, so a row without them is malformed.
func hasCertificateBlocks(profile string) bool {
	blocks := make(map[string]bool)
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		if line == "<ca>" || line == "<cert>" || line == "<key>" {
			blocks[line] = true
		}
	}
	return blocks["<ca>"] && blocks["<cert>"] && blocks["<key>"]
}
