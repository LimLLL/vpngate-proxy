package gateway

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// avoid names the node and egress a rotating session must move away from.
type avoid struct{ node, egress string }

func (a avoid) blocks(node, egress string) bool {
	return node == a.node || a.egress != "" && egress == a.egress
}

// choose returns a tunnel for a new connection with its lease, and for sticky
// requests the session, already counted under the same lock that picked it.
//
// It connects a fresh node first: one whose last known egress no tunnel is
// using and, for a session past its TTL, neither its old node nor its old IP.
// A sticky request also passes over a fresh tunnel whose measured egress
// another session already has, keeping it only as a fallback. Without a usable
// fresh node it shares a live tunnel, and only after that does a session give
// up on leaving its old IP. While tunnels are connecting or closing, or every
// slot is taken, it waits for them rather than failing.
func (p *Pool) choose(ctx context.Context, country string, away avoid, sticky bool) (*tunnel, error) {
	var spares []*tunnel // connected but with an unwanted egress; held until return
	defer func() {
		p.mu.Lock()
		for _, t := range spares {
			t.leases--
			p.closeIfIdle(t)
		}
		p.mu.Unlock()
	}()
	passes := []avoid{away}
	if away != (avoid{}) {
		passes = append(passes, avoid{})
	}
	var failures []error
	attempts := 0
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errPoolClosed
		}
		var fresh *tunnel
		strict := true
		for i, pass := range passes {
			if attempts < p.config.ConnectAttempts {
				if fresh = p.reserve(country, pass); fresh != nil {
					strict = i == 0
					break
				}
			}
			if t := p.share(country, pass, sticky); t != nil {
				p.mu.Unlock()
				if i > 0 {
					p.config.Logf("no other IP for country %q; staying on %s", country, away.egress)
				}
				return t, nil
			}
		}
		if fresh == nil {
			if !p.busy() {
				p.mu.Unlock()
				if len(failures) == 0 {
					failures = append(failures, errors.New("no usable node"))
				}
				return nil, fmt.Errorf("%w for country %q: %w", ErrUnavailable, country, errors.Join(failures...))
			}
			wait := p.changed
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w for country %q: %w", ErrUnavailable, country, ctx.Err())
			case <-wait:
			}
			continue
		}
		p.mu.Unlock()
		attempts++
		if err := p.open(ctx, fresh); err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%w for country %q: %w", ErrUnavailable, country, ctx.Err())
			}
			failures = append(failures, fmt.Errorf("%s: %w", fresh.node.ID, err))
			continue
		}
		p.mu.Lock()
		if fresh.retired {
			// Dropped right after connecting; the monitor logged why.
			p.mu.Unlock()
			spares = append(spares, fresh)
			continue
		}
		if !sticky || !strict || !away.blocks(fresh.node.ID, fresh.egress) && p.egressLoad(fresh) == 0 {
			if sticky {
				fresh.sessions++
			}
			p.mu.Unlock()
			if !strict {
				p.config.Logf("no other IP for country %q; reconnected %s", country, fresh.node.ID)
			}
			return fresh, nil
		}
		egress := fresh.egress
		p.mu.Unlock()
		p.config.Logf("%s via %s: egress %s is taken; trying another node", fresh.device, fresh.node.ID, egress)
		spares = append(spares, fresh)
	}
}

// reserve must be called with p.mu held. It claims a TUN slot and the best
// node the request may connect to, or returns nil when there is none.
func (p *Pool) reserve(country string, away avoid) *tunnel {
	slot := slices.Index(p.slots, false)
	if slot < 0 {
		return nil
	}
	inUse := make(map[string]bool)
	for _, t := range p.tunnels {
		switch {
		case t.retired:
		case t.endpoint == nil:
			inUse[t.lastEgress] = true
		default:
			inUse[t.egress] = true
		}
	}
	delete(inUse, "")
	picked := p.config.Nodes.Pick(nodes.Filter{Country: country, Exclude: func(n nodes.Node) bool {
		return p.tunnels[n.ID] != nil || away.blocks(n.ID, n.Egress) || inUse[n.Egress]
	}}, time.Now())
	if len(picked) == 0 {
		return nil
	}
	t := &tunnel{node: picked[0].Candidate, lastEgress: picked[0].Egress, slot: slot}
	p.slots[slot] = true
	p.tunnels[t.node.ID] = t
	return t
}

// share must be called with p.mu held. It takes a live tunnel for a request
// that cannot get a fresh one: sticky requests prefer an egress fewer
// sessions use, and then everyone the tunnel with the fewest connections.
func (p *Pool) share(country string, away avoid, sticky bool) *tunnel {
	var best *tunnel
	bestLoad := 0
	for _, t := range p.tunnels {
		if !t.live() || country != "" && t.node.Country != country || away.blocks(t.node.ID, t.egress) {
			continue
		}
		load := 0
		if sticky {
			load = p.egressLoad(t)
		}
		if best == nil || load < bestLoad || load == bestLoad &&
			(t.leases < best.leases || t.leases == best.leases && t.node.ID < best.node.ID) {
			best, bestLoad = t, load
		}
	}
	if best != nil {
		best.leases++
		if sticky {
			best.sessions++
		}
	}
	return best
}

// egressLoad counts sticky sessions on live tunnels sharing t's egress.
func (p *Pool) egressLoad(t *tunnel) int {
	if t.egress == "" {
		return t.sessions
	}
	load := 0
	for _, other := range p.tunnels {
		if other.live() && other.egress == t.egress {
			load += other.sessions
		}
	}
	return load
}

// busy must be called with p.mu held. It reports whether waiting can help: a
// tunnel is connecting or closing, or every slot is taken.
func (p *Pool) busy() bool {
	for _, t := range p.tunnels {
		if !t.live() {
			return true
		}
	}
	return !slices.Contains(p.slots, false)
}

// notify must be called with p.mu held.
func (p *Pool) notify() {
	close(p.changed)
	p.changed = make(chan struct{})
}
