package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Candidate struct {
	ID          string
	Country     string
	CountryName string
	IP          string
	HostName    string
	RemoteHost  string
	RemotePort  string
	Protocol    string
	Ping        int
	Speed       int
	Sessions    int
	Score       int
	Profile     string
}

// Source rotates the public candidates rather than sharing one global node.
type Source struct {
	mu     sync.Mutex
	nodes  []Candidate
	next   int
	paths  []string
	remote string
	file   string
	Client *http.Client
}

func RemoteSource(url string) *Source { return &Source{remote: url} }

// SetCandidates atomically swaps the rotation for future native sessions.
func (s *Source) SetCandidates(candidates []Candidate) {
	s.mu.Lock()
	s.nodes = append(s.nodes[:0], candidates...)
	s.next = 0
	s.mu.Unlock()
}

// Candidates snapshots immutable strings while holding the source lock.
func (s *Source) Candidates() []Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Candidate(nil), s.nodes...)
}

// LoadSnapshot replaces the candidates only after a complete, valid snapshot.
func (s *Source) LoadSnapshot(data []byte) error {
	s.mu.Lock()
	old, next := s.nodes, s.next
	s.nodes = nil
	s.next = 0
	err := s.parseCSV(data)
	if err != nil {
		s.nodes, s.next = old, next
	}
	s.mu.Unlock()
	return err
}

func NewCandidateSource(candidates []Candidate) *Source {
	return &Source{nodes: append([]Candidate(nil), candidates...)}
}

func NewSnapshotFileSource(path string) *Source { return &Source{file: path} }

func FileSource(pattern string) (*Source, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no native profiles matched %q", pattern)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := SafeProfile(string(data)); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return &Source{paths: files}, nil
}

func (s *Source) Next(ctx context.Context) (Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.nodes) == 0 {
		if err := s.load(ctx); err != nil {
			return Candidate{}, err
		}
	}
	if len(s.nodes) == 0 {
		return Candidate{}, errors.New("no available OpenVPN candidates")
	}
	node := s.nodes[s.next%len(s.nodes)]
	s.next++
	return node, nil
}

func (s *Source) load(ctx context.Context) error {
	if s.file != "" {
		body, err := os.ReadFile(s.file)
		if err != nil {
			return err
		}
		return s.parseCSV(body)
	}
	if len(s.paths) > 0 {
		for _, path := range s.paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			s.nodes = append(s.nodes, Candidate{ID: filepath.Base(path), Profile: string(data)})
		}
		sort.SliceStable(s.nodes, func(i, j int) bool { return s.nodes[i].ID < s.nodes[j].ID })
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.remote, nil)
	if err != nil {
		return err
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("VPNGate returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 12*1024*1024+1))
	if err != nil {
		return err
	}
	if len(body) > 12*1024*1024 {
		return errors.New("VPNGate snapshot exceeds 12 MiB")
	}
	return s.parseCSV(body)
}

func (s *Source) parseCSV(body []byte) error {
	if len(body) == 0 || len(body) > 12*1024*1024 || !utf8.Valid(body) {
		return errors.New("snapshot size or UTF-8 encoding is invalid")
	}
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "*") {
			filtered = append(filtered, strings.TrimPrefix(line, "#"))
		}
	}
	reader := csv.NewReader(strings.NewReader(strings.Join(filtered, "\n")))
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("read VPNGate header: %w", err)
	}
	seen := make(map[string]int, len(header))
	for index, field := range header {
		seen[field] = index
	}
	for _, required := range []string{"IP", "CountryShort", "CountryLong", "HostName", "Ping", "Speed", "NumVpnSessions", "Score", "OpenVPN_ConfigData_Base64"} {
		if _, ok := seen[required]; !ok {
			return fmt.Errorf("VPNGate snapshot lacks %s", required)
		}
	}
	ping := func(value string) int {
		value = strings.TrimSpace(value)
		if value == "" || value == "-" {
			return 999999
		}
		number, err := strconv.Atoi(value)
		if err != nil || number < 0 {
			return 999999
		}
		return number
	}
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("parse VPNGate row: %w", err)
		}
		encoded := strings.Join(strings.Fields(record[seen["OpenVPN_ConfigData_Base64"]]), "")
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) == 0 || len(raw) > 128*1024 {
			continue
		}
		if !utf8.Valid(raw) {
			continue
		}
		profile := string(raw)
		if err := SafeProfile(profile); err != nil || !vpnGateCertificateBlocks(profile) {
			continue
		}
		ip := record[seen["IP"]]
		remoteHost, remotePort, protocol := parseRemote(profile, ip)
		s.nodes = append(s.nodes, Candidate{
			ID:      fmt.Sprintf("%s-%s", record[seen["CountryShort"]], ip),
			Country: record[seen["CountryShort"]], CountryName: record[seen["CountryLong"]],
			IP: ip, HostName: record[seen["HostName"]], RemoteHost: remoteHost,
			RemotePort: remotePort, Protocol: protocol,
			Ping: ping(record[seen["Ping"]]), Speed: integer(record[seen["Speed"]]),
			Sessions: integer(record[seen["NumVpnSessions"]]), Score: integer(record[seen["Score"]]),
			Profile: profile,
		})
	}
	if len(s.nodes) == 0 {
		return errors.New("VPNGate CSV has no safe, valid OpenVPN profiles")
	}
	sort.SliceStable(s.nodes, func(i, j int) bool { return s.nodes[i].Ping < s.nodes[j].Ping })
	return nil
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

// SafeProfile limits externally parsed profiles to native connection settings;
// commands, plugins, external down/up scripts and unbounded payloads are rejected.
func SafeProfile(profile string) error {
	if len(profile) == 0 || len(profile) > 128*1024 || strings.ContainsRune(profile, '\x00') {
		return errors.New("profile has invalid size or contains a NUL byte")
	}
	block := ""
	seenClient, seenRemote := false, false
	scanner := bufio.NewScanner(bytes.NewBufferString(profile))
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
		if name == "client" {
			seenClient = true
		}
		if name == "remote" {
			if len(parts) < 3 {
				return errors.New("incomplete remote directive")
			}
			port, err := strconv.Atoi(parts[2])
			if err != nil || port < 1 || port > 65535 {
				return errors.New("invalid remote port")
			}
			seenRemote = true
		}
		if name == "dev" {
			if len(parts) < 2 || !strings.HasPrefix(parts[1], "tun") || len(parts[1]) > 3 && !tunSuffix(parts[1][3:]) {
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

// integer parses optional CSV values without promoting malformed latency ranks.
func integer(value string) int {
	result, _ := strconv.Atoi(strings.TrimSpace(value))
	return result
}

func parseRemote(profile, fallback string) (string, string, string) {
	host, port, protocol := fallback, "1194", "udp"
	for _, line := range strings.Split(profile, "\n") {
		parts := strings.Fields(line)
		if len(parts) > 1 && parts[0] == "remote" {
			host = parts[1]
			if len(parts) > 2 {
				port = parts[2]
			}
			if len(parts) > 3 {
				protocol = strings.ToLower(parts[3])
			}
			break
		}
	}
	return host, port, protocol
}

func tunSuffix(value string) bool {
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

func vpnGateCertificateBlocks(profile string) bool {
	blocks := make(map[string]bool)
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if line == "<ca>" || line == "<cert>" || line == "<key>" {
			blocks[line] = true
		}
	}
	return blocks["<ca>"] && blocks["<cert>"] && blocks["<key>"]
}
