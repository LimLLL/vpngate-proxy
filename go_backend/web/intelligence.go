package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type intelligenceQuery struct {
	Query        string `json:"query"`
	Status       string `json:"status"`
	Country      string `json:"country"`
	CountryCode  string `json:"countryCode"`
	RegionName   string `json:"regionName"`
	City         string `json:"city"`
	ISP          string `json:"isp"`
	Org          string `json:"org"`
	AS           string `json:"as"`
	ASName       string `json:"asname"`
	Proxy        bool   `json:"proxy"`
	Hosting      bool   `json:"hosting"`
	Mobile       bool   `json:"mobile"`
	IsDatacenter bool   `json:"is_datacenter"`
}

var datacenterProviderPattern = regexp.MustCompile(`(?i)(?:\b(?:cloud|colo|colocation|data[ -]?center|hosting|servers?|vps)\b|softether)`)

// Enricher reads and preserves the existing classification cache version.
type Enricher struct {
	Client *http.Client
	Cache  map[string]NodeRecord
	Dir    string
}

func NewEnricher(dir string) *Enricher {
	cache := make(map[string]NodeRecord)
	readJSON(filepath.Join(dir, "ip_cache.json"), &cache)
	return &Enricher{Client: &http.Client{Timeout: 15 * time.Second}, Cache: cache, Dir: dir}
}

func (e *Enricher) cached(ip string) (NodeRecord, bool) {
	entry, ok := e.Cache[ip]
	if !ok || intValue(entry["cached_at"]) < 0 || intValue(entry["classification_version"]) != 4 {
		return nil, false
	}
	if time.Since(time.Unix(int64(numberValue(entry["cached_at"])), 0)) >= 7*24*time.Hour {
		return nil, false
	}
	return entry.Copy(), true
}

// Enrich fetches only public IP metadata, never OpenVPN credentials. A quota
// or network failure leaves existing useful fields intact rather than zeroing.
func (e *Enricher) Enrich(ctx context.Context, nodes []NodeRecord) {
	if len(nodes) == 0 {
		return
	}
	var missing []string
	for i := range nodes {
		ip := nodeIP(nodes[i])
		if ip == "" {
			continue
		}
		if cache, ok := e.cached(ip); ok {
			for key, value := range cache {
				nodes[i][key] = value
			}
			continue
		}
		missing = append(missing, ip)
	}
	for i := 0; i < len(missing) && ctx.Err() == nil; i += 100 {
		end := min(i+100, len(missing))
		rows, err := e.queryBatch(ctx, missing[i:end])
		for _, row := range rows {
			classification, reason := classify(row)
			if reason == "proxy_provider_datacenter" || reason == "missing_provider_data" {
				if secondary := e.querySecondary(ctx, row.Query); secondary != nil {
					classification = secondary.Classification
					reason = secondary.Reason
				}
			}
			entry := NodeRecord{
				"owner": row.ISP, "asn": row.AS, "as_name": row.ASName,
				"location":           strings.TrimSpace(strings.Join([]string{row.Country, row.RegionName, row.City}, " ")),
				"geo_country_short":  row.CountryCode,
				"ip_type_reason":     reason,
				"ip_type_confidence": reasonConfidence(reason),
				"ip_type":            classification,
				"is_proxy":           row.Proxy, "is_hosting": row.Hosting,
				"is_mobile":              row.Mobile,
				"classification_version": 4, "cached_at": time.Now().Unix(),
			}
			switch {
			case row.Hosting:
				entry["quality"] = "datacenter"
			case row.Mobile:
				entry["quality"] = "mobile"
			case row.Proxy:
				entry["quality"] = "proxy"
			}
			e.Cache[row.Query] = entry
			for _, node := range nodes {
				if nodeIP(node) == row.Query {
					for key, value := range entry {
						node[key] = value
					}
				}
			}
		}
		if err != nil {
			log.Printf("IP metadata: %v", err)
		}
	}
	_ = writeJSON(filepath.Join(e.Dir, "ip_cache.json"), e.Cache)
}

func (e *Enricher) queryBatch(ctx context.Context, ips []string) ([]intelligenceQuery, error) {
	payload, err := json.Marshal(ips)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://ip-api.com/batch?lang=zh-CN&fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,mobile",
		bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "AimiliVPN-IP-Classifier/4")
	response, err := e.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("IP metadata HTTP %d", response.StatusCode)
	}
	var rows []intelligenceQuery
	if err := json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&rows); err != nil {
		return nil, err
	}
	output := rows[:0]
	for _, row := range rows {
		if row.Status == "success" && row.Query != "" {
			output = append(output, row)
		}
	}
	return output, nil
}

type intelligenceResult struct {
	Classification string
	Reason         string
}

func (e *Enricher) querySecondary(ctx context.Context, ip string) *intelligenceResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipapi.is/?q="+url.QueryEscape(ip), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "AimiliVPN-IP-Classifier/4")
	response, err := e.Client.Do(req)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	var data struct {
		IsDatacenter bool `json:"is_datacenter"`
		IsMobile     bool `json:"is_mobile"`
		Error        any  `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&data); err != nil || data.Error != nil {
		return nil
	}
	if data.IsDatacenter {
		return &intelligenceResult{Classification: "hosting", Reason: "secondary_datacenter"}
	}
	if data.IsMobile {
		return &intelligenceResult{Classification: "mobile", Reason: "secondary_mobile"}
	}
	return &intelligenceResult{Classification: "unknown", Reason: "secondary_insufficient"}
}

func classify(row intelligenceQuery) (string, string) {
	if row.Mobile {
		return "mobile", "mobile_flag"
	}
	if row.Hosting {
		return "hosting", "hosting_flag"
	}
	provider := strings.TrimSpace(strings.Join([]string{row.ISP, row.Org, row.AS, row.ASName}, " "))
	if provider == "" {
		return "unknown", "missing_provider_data"
	}
	if row.Proxy && datacenterProviderPattern.MatchString(provider) {
		return "hosting", "proxy_provider_datacenter"
	}
	return "residential", "consumer_or_unclassified_network"
}

func reasonConfidence(reason string) string {
	switch reason {
	case "mobile_flag", "hosting_flag", "secondary_datacenter", "secondary_mobile":
		return "high"
	case "consumer_or_unclassified_network", "secondary_consumer_network":
		return "medium"
	default:
		return "low"
	}
}

func nodeIP(node NodeRecord) string {
	return nonempty(stringValue(node["ip"]), stringValue(node["remote_host"]))
}

func allowedIPType(node NodeRecord, routingType string) bool {
	kind := stringValue(node["ip_type"])
	switch routingType {
	case "hosting":
		return kind == "hosting"
	case "residential":
		return kind == "residential" || kind == "mobile"
	default:
		return true
	}
}

func secondaryInProgress(g *sync.Mutex, pending map[string]bool, ip string) bool {
	g.Lock()
	defer g.Unlock()
	if pending[ip] {
		return false
	}
	pending[ip] = true
	return true
}
