package nodes

import (
	"fmt"
	"net"
	"time"
)

// Filter narrows Next. Exclude is called while the registry is locked, so it
// must not call back into the registry.
type Filter struct {
	Country string
	Exclude func(Node) bool
}

// Next returns the node to connect next and marks its network as used, so
// concurrent picks, and the pick after a failed connect, move on to another
// network. Among usable nodes it prefers, in order:
//
//  1. the /24 network used least recently, so consecutive connections leave
//     from unrelated addresses even where many nodes share one NAT;
//  2. within it, the egress IP used least recently, a node not yet measured
//     counting as never used;
//  3. nodes in the latest listing, by VPNGate score;
//  4. older nodes, by their last successful connect.
func (r *Registry) Next(filter Filter, now time.Time) (Node, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var best *Node
	for _, node := range r.nodes {
		if filter.Country != "" && node.Country != filter.Country || now.Before(node.RetryAfter) {
			continue
		}
		if filter.Exclude != nil && filter.Exclude(*node) {
			continue
		}
		if best == nil || r.before(node, best) {
			best = node
		}
	}
	if best == nil {
		return Node{}, false
	}
	r.usage.Networks[best.network()] = now
	return *best, true
}

func (r *Registry) before(a, b *Node) bool {
	if x, y := r.usage.Networks[a.network()], r.usage.Networks[b.network()]; !x.Equal(y) {
		return x.Before(y)
	}
	if x, y := r.usage.IPs[a.Egress], r.usage.IPs[b.Egress]; !x.Equal(y) {
		return x.Before(y)
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
}

// network is where the node's traffic leaves from: its measured egress or,
// until that is known, its own address, which is the egress of most
// volunteer nodes and in the same /24 as the egress of the academic ones.
func (n *Node) network() string {
	if n.Egress != "" {
		return network(n.Egress)
	}
	return network(n.IP)
}

// network names the /24 holding an IPv4 address: sites and blocklists
// commonly treat a /24 as one source, and NAT gateways hand out egress
// addresses from one. Anything else is its own network.
func network(ip string) string {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return ip
	}
	return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
}

// usage remembers when each /24 network and each egress IP was last used.
type usage struct {
	Networks map[string]time.Time `json:"networks,omitempty"`
	IPs      map[string]time.Time `json:"ips,omitempty"`
}

func newUsage() usage {
	return usage{Networks: make(map[string]time.Time), IPs: make(map[string]time.Time)}
}

// markIP records an egress IP, and its network, as used now.
func (u usage) markIP(ip string, now time.Time) {
	if ip != "" {
		u.IPs[ip] = now
		u.Networks[network(ip)] = now
	}
}

func (u usage) merge(other usage) {
	for key, used := range other.Networks {
		u.Networks[key] = used
	}
	for key, used := range other.IPs {
		u.IPs[key] = used
	}
}

// prune forgets addresses no remaining node can leave from.
func (u usage) prune(nodes map[string]*Node) {
	networks := make(map[string]bool)
	ips := make(map[string]bool)
	for _, node := range nodes {
		networks[node.network()] = true
		networks[network(node.IP)] = true
		ips[node.Egress] = true
	}
	for key := range u.Networks {
		if !networks[key] {
			delete(u.Networks, key)
		}
	}
	for key := range u.IPs {
		if !ips[key] {
			delete(u.IPs, key)
		}
	}
}
