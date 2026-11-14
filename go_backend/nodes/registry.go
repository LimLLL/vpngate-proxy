package nodes

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Node is a candidate plus what has been learned about it across listings.
type Node struct {
	Candidate
	// Egress is the public IP last measured through the node; nodes behind
	// one NAT share it.
	Egress      string    `json:"egress,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	LastSuccess time.Time `json:"last_success"`
	// Reachable is the outcome of the latest liveness check at ProbedAt;
	// only reachable nodes are picked.
	Reachable     bool      `json:"reachable"`
	ProbedAt      time.Time `json:"probed_at"`
	LastReachable time.Time `json:"last_reachable"`
	// Failures counts consecutive failed connects; a success resets it.
	Failures   int       `json:"failures"`
	RetryAfter time.Time `json:"retry_after"`
}

type RegistryConfig struct {
	// Path is the JSON file backing the table; empty keeps it in memory only.
	Path string
	// MaxAge drops nodes that have been absent from every listing this long.
	MaxAge time.Duration
	// MaxFailures drops a node after this many consecutive failed connects.
	MaxFailures int
	// Cooldown skips a node for this long after each failed connect.
	Cooldown time.Duration
	// Unreachable drops a node that has failed every liveness check for
	// this long; zero keeps such nodes.
	Unreachable time.Duration
}

// Registry accumulates every node seen in VPNGate listings, because each
// listing only shows some of the servers online at that moment and IP
// variety is the point of the proxy. Liveness checks tell which of them still
// answer. Nodes leave by age, by staying unreachable or by repeated connect
// failures.
type Registry struct {
	config RegistryConfig
	saveMu sync.Mutex

	mu    sync.Mutex
	nodes map[string]*Node
	usage usage // what Next rotates by; persisted with the nodes
}

type registryFile struct {
	Usage usage  `json:"usage"`
	Nodes []Node `json:"nodes"`
}

// OpenRegistry loads the table from config.Path when the file exists.
func OpenRegistry(config RegistryConfig) (*Registry, error) {
	if config.MaxAge <= 0 || config.MaxFailures < 1 || config.Cooldown < 0 || config.Unreachable < 0 {
		return nil, errors.New("registry needs a positive max age and failure limit")
	}
	r := &Registry{config: config, nodes: make(map[string]*Node), usage: newUsage()}
	if config.Path == "" {
		return r, nil
	}
	data, err := os.ReadFile(config.Path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var file registryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("read node table %s: %w", config.Path, err)
	}
	for i := range file.Nodes {
		node := file.Nodes[i]
		r.nodes[node.ID] = &node
	}
	r.usage.merge(file.Usage)
	return r, nil
}

// Merge records a fresh listing and saves the table. New nodes are picked
// only once a liveness check reached them. Being listed does not reset
// failure counts: it shows the server registered, not that it connects.
func (r *Registry) Merge(listing []Candidate, now time.Time) (added int, err error) {
	r.mu.Lock()
	for _, candidate := range listing {
		if node, ok := r.nodes[candidate.ID]; ok {
			node.Candidate = candidate
			node.LastSeen = now
			continue
		}
		r.nodes[candidate.ID] = &Node{Candidate: candidate, FirstSeen: now, LastSeen: now}
		added++
	}
	for id, node := range r.nodes {
		if now.Sub(node.LastSeen) > r.config.MaxAge {
			delete(r.nodes, id)
		}
	}
	r.usage.prune(r.nodes)
	r.mu.Unlock()
	return added, r.Save()
}

// ReportSuccess records a working connect and the egress IP measured through
// it, which is in use from now on; egress is empty when it was not measured.
func (r *Registry) ReportSuccess(id, egress string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if node, ok := r.nodes[id]; ok {
		node.LastSuccess = now
		node.Failures = 0
		node.RetryAfter = time.Time{}
		if egress != "" {
			node.Egress = egress
		}
	}
	r.usage.markIP(egress, now)
}

// ReportUsed records that egress was in use until now.
func (r *Registry) ReportUsed(egress string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.usage.markIP(egress, now)
}

// ReportProbe records a liveness check, dropping a node that has not answered
// one for longer than the configured limit.
func (r *Registry) ReportProbe(id string, reachable bool, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	node, ok := r.nodes[id]
	if !ok {
		return
	}
	node.Reachable, node.ProbedAt = reachable, now
	if reachable {
		node.LastReachable = now
		return
	}
	since := node.LastReachable
	if since.IsZero() {
		since = node.FirstSeen
	}
	if r.config.Unreachable > 0 && now.Sub(since) > r.config.Unreachable {
		delete(r.nodes, id)
	}
}

// ReportFailure puts the node on cooldown, or drops it at the failure limit.
func (r *Registry) ReportFailure(id string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	node, ok := r.nodes[id]
	if !ok {
		return
	}
	node.Failures++
	if node.Failures >= r.config.MaxFailures {
		delete(r.nodes, id)
		return
	}
	node.RetryAfter = now.Add(r.config.Cooldown)
}

// Get returns a copy of one node.
func (r *Registry) Get(id string) (Node, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if node, ok := r.nodes[id]; ok {
		return *node, true
	}
	return Node{}, false
}

func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.nodes)
}

// Save writes the table atomically; saves are serialized so an older snapshot
// can never overwrite a newer one.
func (r *Registry) Save() error {
	if r.config.Path == "" {
		return nil
	}
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	r.mu.Lock()
	file := registryFile{Usage: newUsage(), Nodes: make([]Node, 0, len(r.nodes))}
	for _, node := range r.nodes {
		file.Nodes = append(file.Nodes, *node)
	}
	file.Usage.merge(r.usage)
	r.mu.Unlock()
	sort.Slice(file.Nodes, func(i, j int) bool { return file.Nodes[i].ID < file.Nodes[j].ID })
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return WriteFileAtomic(r.config.Path, data)
}

// WriteFileAtomic replaces path with data via a synced temporary file, so a
// crash leaves either the old or the new content, never a partial file.
func WriteFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
