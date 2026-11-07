package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type NodeRecord map[string]any

func (n NodeRecord) Copy() NodeRecord {
	result := make(NodeRecord, len(n))
	for key, value := range n {
		result[key] = value
	}
	return result
}

func (n NodeRecord) String(key string) string {
	if value, ok := n[key].(string); ok {
		return value
	}
	return ""
}

func (n NodeRecord) Int(key string) int {
	return intValue(n[key])
}

func (n NodeRecord) SetString(key, value string)  { n[key] = value }
func (n NodeRecord) SetInt(key string, value int) { n[key] = value }

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	switch value := value.(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	default:
		return fmt.Sprint(value)
	}
}

func intValue(value any) int {
	switch value := value.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		result, _ := strconv.Atoi(value)
		return result
	}
	return 0
}

func numberValue(value any) float64 {
	switch value := value.(type) {
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case float64:
		return value
	case json.Number:
		result, _ := value.Float64()
		return result
	case string:
		result, _ := strconv.ParseFloat(value, 64)
		return result
	}
	return 0
}

func readJSON(path string, output any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, output)
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".json-*")
	if err != nil {
		return err
	}
	filename := temporary.Name()
	defer os.Remove(filename)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(filename, path)
}

func parseRemote(profile, fallback string) (string, string, string) {
	host := fallback
	port, protocol := "1194", "udp"
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
	return host, knownPort(port), protocol
}

func knownPort(port string) string {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "1194"
	}
	return strconv.Itoa(number)
}

var safeNodePart = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

func nodeName(country, ip, port, protocol string) string {
	return strings.Trim(strings.Join([]string{country, ip, port, safeNodePart.ReplaceAllString(protocol, "_")}, "_"), "._")
}

func tcpPing(host string, port string) int {
	if net.ParseIP(host) == nil && host == "" {
		return 0
	}
	address := net.JoinHostPort(host, knownPort(port))
	dialer := net.Dialer{Timeout: 5 * time.Second}
	start := time.Now()
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return 0
	}
	_ = connection.Close()
	return max(1, int(float64(time.Since(start).Microseconds())/1000))
}

// TCPPingPublic checks the transport peer before it enters an OpenVPN session.
func TCPPingPublic(host, port string) int { return tcpPing(host, port) }

func logError(message string, err error) {
	if err != nil {
		log.Printf("%s: %v", message, err)
	}
}
