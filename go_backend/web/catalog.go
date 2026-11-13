package web

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
)

const mirrorRelativePath = "mirror/vpngate.csv"

type Catalog struct {
	mu          sync.RWMutex
	maintenance sync.Mutex
	nodes       []NodeRecord
	Source      *gateway.Source
	Native      *gateway.NativeFactory
	Store       *DataStore
	Fetcher     *SnapshotFetcher
	Enricher    *Enricher
	Runtime     *Runtime
	Pool        *gateway.Pool
	lastFetch   time.Time
	lastSource  string
}

func NewCatalog(store *DataStore, source *gateway.Source) (*Catalog, error) {
	if source == nil {
		return nil, errors.New("candidate source is required")
	}
	catalog := &Catalog{Store: store, Source: source, nodes: []NodeRecord{}}
	httpClient, err := newHTTPClient()
	if err != nil {
		return nil, err
	}
	mirror := os.Getenv("VPNGATE_BUNDLED_SNAPSHOT")
	if mirror == "" {
		for _, candidate := range []string{mirrorRelativePath, filepath.Join(store.Dir, mirrorRelativePath)} {
			if _, err := os.Stat(candidate); err == nil {
				mirror = candidate
				break
			}
		}
	}
	catalog.Fetcher = &SnapshotFetcher{Dir: store.Dir, Mirror: mirror, Client: httpClient}
	catalog.Enricher = NewEnricher(store.Dir)
	catalog.Enricher.Client = httpClient
	if err := readJSON(filepath.Join(store.Dir, "nodes.json"), &catalog.nodes); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read node cache: %w", err)
	}
	var cached []gateway.Candidate
	for _, node := range catalog.nodes {
		if record, err := node.RemoteCandidate(); err == nil {
			cached = append(cached, record)
		}
	}
	catalog.Source.SetCandidates(cached)
	return catalog, nil
}

var supportedNodeID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}$`)

func (e *Catalog) ByID(id string) (NodeRecord, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, node := range e.nodes {
		if node.String("id") == id {
			return node.Copy(), nil
		}
	}
	return nil, fmt.Errorf("node %q not found", id)
}

func (e *Catalog) Nodes() []NodeRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]NodeRecord, 0, len(e.nodes))
	for _, node := range e.nodes {
		result = append(result, node.Copy())
	}
	return result
}

func (e *Catalog) SaveNodes() error {
	return writeJSON(filepath.Join(e.Store.Dir, "nodes.json"), e.Nodes())
}

func (e *Catalog) Refresh(ctx context.Context) error {
	rawSource, err := e.loadSource(ctx)
	if err != nil {
		return err
	}
	fresh, err := e.refreshRecords(ctx, rawSource)
	if err != nil {
		return fmt.Errorf("save node catalog: %w", err)
	}
	e.mu.Lock()
	e.nodes = fresh
	e.lastFetch = time.Now()
	e.lastSource = "VPNGate API / last-known cache"
	e.mu.Unlock()
	return nil
}

func (e *Catalog) refreshRecords(ctx context.Context, candidates []gateway.Candidate) ([]NodeRecord, error) {
	old := make(map[string]NodeRecord)
	for _, node := range e.Nodes() {
		old[node.String("id")] = node
	}
	fresh := make([]NodeRecord, 0, len(candidates))
	countries := e.Store.Snapshot().DiscoveryCountries
	countryFilter := make(map[string]bool, len(countries))
	for _, country := range countries {
		countryFilter[country] = true
	}
	known := make(map[string]bool)
	for _, candidate := range candidates {
		if len(countryFilter) > 0 && !countryFilter[strings.ToUpper(candidate.Country)] {
			continue
		}
		id := nodeName(candidate.Country, candidate.IP, candidate.RemotePort, candidate.Protocol)
		if !supportedNodeID.MatchString(id) || known[id] {
			continue
		}
		known[id] = true
		node := NodeRecord{
			"id": id, "country": candidate.CountryName,
			"country_short": strings.ToUpper(candidate.Country),
			"country_long":  candidate.CountryName,
			"host_name":     candidate.HostName, "ip": candidate.IP,
			"score": candidate.Score, "ping": candidate.Ping, "speed": candidate.Speed,
			"sessions": candidate.Sessions, "latency_ms": 0,
			"remote_host": candidate.RemoteHost, "remote_port": candidate.RemotePort,
			"proto": candidate.Protocol, "config_text": candidate.Profile,
			"config_file": filepath.Join(e.Store.Dir, "configs", id+".ovpn"),
			"fetched_at":  time.Now().Unix(), "probe_status": "not_checked",
			"probe_message": "", "probed_at": 0,
			"owner": "", "asn": "", "as_name": "", "location": "",
			"ip_type": "", "quality": "",
		}
		for key, value := range old[id] {
			if key != "config_text" && key != "fetched_at" {
				node[key] = value
			}
		}
		fresh = append(fresh, node)
	}
	if len(fresh) == 0 {
		return nil, errors.New("snapshot contains no valid unique nodes")
	}
	e.Enricher.Enrich(ctx, fresh)
	sort.SliceStable(fresh, func(i, j int) bool {
		left, right := fresh[i], fresh[j]
		if left.String("probe_status") != right.String("probe_status") {
			return left.String("probe_status") == "available"
		}
		return left.Int("ping") < right.Int("ping")
	})
	if err := os.MkdirAll(filepath.Join(e.Store.Dir, "configs"), 0o700); err != nil {
		return nil, err
	}
	for _, node := range fresh {
		if err := os.WriteFile(node.String("config_file"), []byte(node.String("config_text")), 0o600); err != nil {
			return nil, err
		}
	}
	return fresh, writeJSON(filepath.Join(e.Store.Dir, "nodes.json"), fresh)
}

func (e *Catalog) loadSource(ctx context.Context) ([]gateway.Candidate, error) {
	if e.Fetcher == nil {
		return nil, errors.New("snapshot fetcher is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := e.Fetcher.fetch(ctx, e.Source); err != nil {
		if len(e.Source.Candidates()) == 0 {
			return nil, err
		}
		log.Printf("snapshot refresh failed; retaining cached candidates: %v", err)
	}
	return e.Source.Candidates(), nil
}

func (e *Catalog) TryMaintenance() bool { return e.maintenance.TryLock() }
func (e *Catalog) EndMaintenance()      { e.maintenance.Unlock() }

func (e *Catalog) Test(ctx context.Context, id string) (NodeRecord, error) {
	node, err := e.ByID(id)
	if err != nil {
		return nil, err
	}
	return e.testRecord(ctx, node)
}

func (e *Catalog) testRecord(ctx context.Context, node NodeRecord) (NodeRecord, error) {
	if e.Native == nil {
		return nil, errors.New("native factory is unavailable")
	}
	candidate, err := node.RemoteCandidate()
	if err != nil {
		return nil, err
	}
	testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	start := time.Now()
	endpoint, connectErr := e.Native.Connect(testCtx, candidate)
	if connectErr == nil {
		if _, infoErr := endpoint.Info(); infoErr != nil {
			connectErr = infoErr
		}
	}
	if endpoint != nil {
		closeCtx, cancelClose := context.WithTimeout(context.Background(), 10*time.Second)
		defer func() {
			if err := endpoint.Close(closeCtx); err != nil {
				log.Printf("probe close %s: %v", candidate.ID, err)
			}
			cancelClose()
		}()
	}
	current, err := e.ByID(node.String("id"))
	if err != nil {
		return nil, err
	}
	current["probed_at"] = time.Now().Unix()
	current["latency_ms"] = time.Since(start).Milliseconds()
	if connectErr != nil {
		current["probe_status"] = "unavailable"
		current["probe_message"] = connectErr.Error()
	} else {
		current["probe_status"] = "available"
		current["probe_message"] = "OpenVPN 3 原生握手成功，独立 TUN 已验证"
	}
	e.mu.Lock()
	for i, saved := range e.nodes {
		if saved.String("id") == current.String("id") {
			e.nodes[i] = current
			break
		}
	}
	e.mu.Unlock()
	if err := e.SaveNodes(); err != nil {
		return nil, err
	}
	return current, nil
}

func (e *Catalog) TestIDs(ctx context.Context, ids []string) ([]NodeRecord, error) {
	if len(ids) == 0 {
		return nil, errors.New("node id list is empty")
	}
	seen := make(map[string]bool, len(ids))
	result := make([]NodeRecord, 0, len(ids))
	for _, id := range ids {
		if !supportedNodeID.MatchString(id) || seen[id] {
			return nil, fmt.Errorf("invalid or duplicate test node %q", id)
		}
		seen[id] = true
		tested, err := e.Test(ctx, id)
		if err != nil {
			return result, err
		}
		result = append(result, tested)
	}
	return result, nil
}
