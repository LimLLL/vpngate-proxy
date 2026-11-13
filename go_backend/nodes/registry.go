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
}

// Filter narrows Pick. Exclude is called while the registry is locked, so it
// must not call back into the registry.
type Filter struct {
	Country string
	Exclude func(Node) bool
}

// Registry accumulates every node seen in VPNGate listings, because each
// listing only shows the servers online at that moment and IP variety is the
// point of the proxy. Nodes leave by age or by repeated connect failures.
type Registry struct {
	config RegistryConfig
	saveMu sync.Mutex

	mu    sync.Mutex
	nodes map[string]*Node
	// egressUsed is when each egress IP was last in use, so picks can move
	// on to the IP that has rested longest.
	egressUsed map[string]time.Time
	listed     time.Time
}

type registryFile struct {
	ListedAt   time.Time            `json:"listed_at"`
	EgressUsed map[string]time.Time `json:"egress_used,omitempty"`
	Nodes      []Node               `json:"nodes"`
}

// OpenRegistry loads the table from config.Path when the file exists.
func OpenRegistry(config RegistryConfig) (*Registry, error) {
	if config.MaxAge <= 0 || config.MaxFailures < 1 || config.Cooldown < 0 {
		return nil, errors.New("registry needs a positive max age and failure limit")
	}
	r := &Registry{config: config, nodes: make(map[string]*Node), egressUsed: make(map[string]time.Time)}
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
	for egress, used := range file.EgressUsed {
		r.egressUsed[egress] = used
	}
	r.listed = file.ListedAt
	return r, nil
}

// Merge records a fresh listing and saves the table. Being listed does not
// reset failure counts: it shows the server registered, not that it connects.
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
	r.listed = now
	known := make(map[string]bool)
	for id, node := range r.nodes {
		if now.Sub(node.LastSeen) > r.config.MaxAge {
			delete(r.nodes, id)
			continue
		}
		known[node.Egress] = true
	}
	for egress := range r.egressUsed {
		if !known[egress] {
			delete(r.egressUsed, egress)
		}
	}
	r.mu.Unlock()
	return added, r.Save()
}

// Pick returns usable nodes, best first: the egress IP that has gone unused
// longest (an unknown egress counts as never used), so consecutive picks move
// between IPs rather than between nodes behind one NAT; then nodes in the
// latest listing by VPNGate score; then older nodes by how recently they last
// connected.
func (r *Registry) Pick(filter Filter, now time.Time) []Node {
	r.mu.Lock()
	defer r.mu.Unlock()
	var usable []*Node
	for _, node := range r.nodes {
		if filter.Country != "" && node.Country != filter.Country || now.Before(node.RetryAfter) {
			continue
		}
		if filter.Exclude != nil && filter.Exclude(*node) {
			continue
		}
		usable = append(usable, node)
	}
	sort.Slice(usable, func(i, j int) bool {
		a, b := usable[i], usable[j]
		if usedA, usedB := r.egressUsed[a.Egress], r.egressUsed[b.Egress]; !usedA.Equal(usedB) {
			return usedA.Before(usedB)
		}
		listedA, listedB := !a.LastSeen.Before(r.listed), !b.LastSeen.Before(r.listed)
		if listedA != listedB {
			return listedA
		}
		if listedA && a.Score != b.Score {
			return a.Score > b.Score
		}
		if !a.LastSuccess.Equal(b.LastSuccess) {
			return a.LastSuccess.After(b.LastSuccess)
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.ID < b.ID
	})
	result := make([]Node, len(usable))
	for i, node := range usable {
		result[i] = *node
	}
	return result
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
	r.markUsed(egress, now)
}

// ReportUsed records that egress was in use until now.
func (r *Registry) ReportUsed(egress string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.markUsed(egress, now)
}

// markUsed must be called with r.mu held.
func (r *Registry) markUsed(egress string, now time.Time) {
	if egress != "" {
		r.egressUsed[egress] = now
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
	file := registryFile{ListedAt: r.listed, EgressUsed: make(map[string]time.Time, len(r.egressUsed)),
		Nodes: make([]Node, 0, len(r.nodes))}
	for _, node := range r.nodes {
		file.Nodes = append(file.Nodes, *node)
	}
	for egress, used := range r.egressUsed {
		file.EgressUsed[egress] = used
	}
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
