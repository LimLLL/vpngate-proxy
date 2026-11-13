// Package nodes parses VPNGate listings and keeps the accumulated node table.
// It has no native dependencies, so it builds and tests without OpenVPN.
package nodes

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxSnapshotSize bounds one API response; real listings are around 1–2 MiB.
const maxSnapshotSize = 12 * 1024 * 1024

// Candidate is one connectable VPNGate server. ID is the server IP for listed
// nodes, because the egress IP is what a proxy client actually observes.
type Candidate struct {
	ID          string `json:"id"`
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	IP          string `json:"ip"`
	HostName    string `json:"host_name"`
	RemoteHost  string `json:"remote_host"`
	RemotePort  string `json:"remote_port"`
	Protocol    string `json:"protocol"`
	Ping        int    `json:"ping"`
	Speed       int    `json:"speed"`
	Sessions    int    `json:"sessions"`
	Score       int    `json:"score"`
	Profile     string `json:"profile"`
}

// ParseCSV extracts the safe, usable rows of a VPNGate API response. Rows with
// unsafe or incomplete profiles are skipped; an error means nothing was usable.
func ParseCSV(body []byte) ([]Candidate, error) {
	if len(body) == 0 || len(body) > maxSnapshotSize || !utf8.Valid(body) {
		return nil, errors.New("snapshot size or UTF-8 encoding is invalid")
	}
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		// The API wraps the table in "*vpn_servers" / "*" markers and prefixes
		// the header with "#".
		if line != "" && !strings.HasPrefix(line, "*") {
			filtered = append(filtered, strings.TrimPrefix(line, "#"))
		}
	}
	reader := csv.NewReader(strings.NewReader(strings.Join(filtered, "\n")))
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read VPNGate header: %w", err)
	}
	column := make(map[string]int, len(header))
	for index, field := range header {
		column[field] = index
	}
	for _, required := range []string{"IP", "CountryShort", "CountryLong", "HostName", "Ping", "Speed", "NumVpnSessions", "Score", "OpenVPN_ConfigData_Base64"} {
		if _, ok := column[required]; !ok {
			return nil, fmt.Errorf("VPNGate snapshot lacks %s", required)
		}
	}
	var result []Candidate
	seen := make(map[string]bool)
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse VPNGate row: %w", err)
		}
		encoded := strings.Join(strings.Fields(record[column["OpenVPN_ConfigData_Base64"]]), "")
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) == 0 || len(raw) > maxProfileSize || !utf8.Valid(raw) {
			continue
		}
		profile := string(raw)
		if SafeProfile(profile) != nil || !hasCertificateBlocks(profile) {
			continue
		}
		ip := strings.TrimSpace(record[column["IP"]])
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		remoteHost, remotePort, protocol := parseRemote(profile, ip)
		result = append(result, Candidate{
			ID:          ip,
			Country:     strings.ToUpper(strings.TrimSpace(record[column["CountryShort"]])),
			CountryName: record[column["CountryLong"]],
			IP:          ip, HostName: record[column["HostName"]],
			RemoteHost: remoteHost, RemotePort: remotePort, Protocol: protocol,
			Ping:     ping(record[column["Ping"]]),
			Speed:    integer(record[column["Speed"]]),
			Sessions: integer(record[column["NumVpnSessions"]]),
			Score:    integer(record[column["Score"]]),
			Profile:  profile,
		})
	}
	if len(result) == 0 {
		return nil, errors.New("VPNGate CSV has no safe, valid OpenVPN profiles")
	}
	return result, nil
}

// ping maps a missing or malformed latency to a large value so it ranks last.
func ping(value string) int {
	value = strings.TrimSpace(value)
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 {
		return 999999
	}
	return number
}

func integer(value string) int {
	result, _ := strconv.Atoi(strings.TrimSpace(value))
	return result
}
