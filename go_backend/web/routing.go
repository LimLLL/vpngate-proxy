package web

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/LimLLL/vpngate-proxy/go_backend/gateway"
)

// CatalogSource is a policy-aware candidate iterator for the native factory.
type CatalogSource struct {
	Catalog *Catalog
	next    atomic.Uint64
}

func (s *CatalogSource) Next(ctx context.Context) (gateway.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return gateway.Candidate{}, err
	}
	candidates, err := s.Catalog.Eligible()
	if err != nil {
		return gateway.Candidate{}, err
	}
	index := s.next.Add(1) - 1
	return candidates[index%uint64(len(candidates))], nil
}

func (n NodeRecord) RemoteCandidate() (gateway.Candidate, error) {
	profile := stringValue(n["config_text"])
	if profile == "" {
		return gateway.Candidate{}, fmt.Errorf("node %q has no native profile", n.String("id"))
	}
	if err := gateway.SafeProfile(profile); err != nil {
		return gateway.Candidate{}, err
	}
	return gateway.Candidate{
		ID: n.String("id"), Country: strings.ToUpper(n.String("country_short")),
		IP: n.String("ip"), RemoteHost: n.String("remote_host"),
		RemotePort: n.String("remote_port"), Protocol: n.String("proto"),
		Ping: n.Int("ping"), Profile: profile,
	}, nil
}

// Eligible uses the latest UI routing fields for new assignments, not a global
// tunnel. There are no fake candidates created when a filter cannot be met.
func (e *Catalog) Eligible() ([]gateway.Candidate, error) {
	e.mu.RLock()
	nodes := make([]NodeRecord, len(e.nodes))
	for i, node := range e.nodes {
		nodes[i] = node.Copy()
	}
	e.mu.RUnlock()
	cfg := e.Store.Snapshot()
	favorites := make(map[string]bool, len(cfg.FavoriteNodeIDs))
	for _, favorite := range cfg.FavoriteNodeIDs {
		favorites[favorite] = true
	}
	var result []gateway.Candidate
	for _, node := range nodes {
		id, countryShort := node.String("id"), node.String("country_short")
		switch cfg.RoutingMode {
		case "fixed_ip":
			if id != cfg.FixedNodeID {
				continue
			}
		case "fixed_region":
			if !strings.EqualFold(countryShort, cfg.ForceCountry) {
				continue
			}
		case "favorites":
			if !favorites[id] {
				continue
			}
		}
		if !allowedIPType(node, cfg.RoutingIPType) || !cfg.ConnectionEnabled {
			continue
		}
		if node.String("probe_status") == "unavailable" {
			continue
		}
		candidate, err := node.RemoteCandidate()
		if err != nil {
			continue
		}
		result = append(result, candidate)
	}
	if len(result) == 0 {
		return nil, errors.New("no healthy nodes match routing settings")
	}
	return result, nil
}
