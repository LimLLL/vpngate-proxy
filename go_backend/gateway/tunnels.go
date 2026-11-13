package gateway

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// open connects to the best node not already live or being opened, trying up
// to ConnectAttempts nodes. The returned tunnel is taken like in choose.
func (p *Pool) open(ctx context.Context, country, exclude string, sticky bool) (*tunnel, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errPoolClosed
	}
	slot := p.allocSlot()
	if slot < 0 {
		p.mu.Unlock()
		return nil, fmt.Errorf("all %d tunnel slots are in use", p.config.MaxTunnels)
	}
	candidates := p.config.Nodes.Pick(nodes.Filter{Country: country, Exclude: func(id string) bool {
		return id == exclude || p.tunnels[id] != nil || p.opening[id]
	}}, time.Now())
	if len(candidates) > p.config.ConnectAttempts {
		candidates = candidates[:p.config.ConnectAttempts]
	}
	// Reserve every attempt so concurrent opens spread across other nodes.
	for _, candidate := range candidates {
		p.opening[candidate.ID] = true
	}
	p.mu.Unlock()

	var failures []error
	for i, candidate := range candidates {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
		connectCtx, cancel := context.WithTimeout(ctx, p.config.ConnectTimeout)
		endpoint, err := p.config.Connect(connectCtx, candidate, slot)
		cancel()
		now := time.Now()
		if err != nil {
			// A caller that gave up says nothing about the node; a timeout does.
			if ctx.Err() == nil {
				p.config.Nodes.ReportFailure(candidate.ID, now)
			}
			p.config.Logf("connect %s (%s): %v", candidate.ID, candidate.Country, err)
			failures = append(failures, fmt.Errorf("%s: %w", candidate.ID, err))
			continue
		}
		p.config.Nodes.ReportSuccess(candidate.ID, now)
		p.mu.Lock()
		for _, reserved := range candidates[i:] {
			delete(p.opening, reserved.ID)
		}
		p.notify()
		if p.closed {
			p.mu.Unlock()
			t := &tunnel{node: candidate, device: endpoint.Device(), slot: slot, endpoint: endpoint, retired: true}
			return nil, errors.Join(errPoolClosed, p.closeTunnel(t))
		}
		t := &tunnel{node: candidate, device: endpoint.Device(), slot: slot, endpoint: endpoint}
		p.take(t, sticky)
		p.tunnels[candidate.ID] = t
		p.wg.Add(1)
		go p.monitor(t)
		p.mu.Unlock()
		p.config.Logf("tunnel %s up via %s (%s)", t.device, candidate.ID, candidate.Country)
		return t, nil
	}
	p.mu.Lock()
	for _, reserved := range candidates {
		delete(p.opening, reserved.ID)
	}
	p.slots[slot] = false
	p.notify()
	p.mu.Unlock()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no unused node for country %q", country)
	}
	return nil, errors.Join(failures...)
}

func (p *Pool) allocSlot() int {
	for i, used := range p.slots {
		if !used {
			p.slots[i] = true
			return i
		}
	}
	return -1
}

func (p *Pool) monitor(t *tunnel) {
	defer p.wg.Done()
	<-t.endpoint.Failure()
	p.mu.Lock()
	if t.retired {
		// A planned close; whoever retired it also closes it.
		p.mu.Unlock()
		return
	}
	p.retire(t)
	p.mu.Unlock()
	p.config.Logf("tunnel %s via %s dropped: %v", t.device, t.node.ID, t.endpoint.FailureError())
	p.config.Nodes.ReportFailure(t.node.ID, time.Now())
	_ = p.closeTunnel(t)
}

// retire must be called with p.mu held. Sessions still pointing at the tunnel
// see retired and pick a new one; open connections on it simply end.
func (p *Pool) retire(t *tunnel) {
	t.retired = true
	if p.tunnels[t.node.ID] == t {
		delete(p.tunnels, t.node.ID)
	}
}

// closeTunnel frees the slot only after a clean close, because a failed close
// may leave the device or its routes behind.
func (p *Pool) closeTunnel(t *tunnel) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := t.endpoint.Close(ctx); err != nil {
		p.config.Logf("close %s: %v; slot %d stays reserved", t.device, err, t.slot)
		return fmt.Errorf("close %s: %w", t.device, err)
	}
	p.mu.Lock()
	p.slots[t.slot] = false
	p.mu.Unlock()
	return nil
}

func (p *Pool) maintain() {
	defer p.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-ticker.C:
			p.sweep(now)
		}
	}
}

// sweep expires sessions, closes idle tunnels beyond the warm reserve and
// starts warming when the reserve is short.
func (p *Pool) sweep(now time.Time) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	for id, s := range p.sessions {
		if s.assigning == nil && !now.Before(s.expires) {
			p.unbind(s)
			if now.Sub(s.expires) > sessionRetention {
				delete(p.sessions, id)
			}
		}
	}
	var idle []*tunnel
	free := 0
	for _, t := range p.tunnels {
		if t.sessions == 0 {
			free++
			if t.leases == 0 && now.Sub(t.lastUsed) >= p.config.IdleTimeout {
				idle = append(idle, t)
			}
		}
	}
	sort.Slice(idle, func(i, j int) bool { return idle[i].lastUsed.Before(idle[j].lastUsed) })
	var closing []*tunnel
	for _, t := range idle {
		if free <= p.config.MinIdle {
			break
		}
		p.retire(t)
		closing = append(closing, t)
		free--
	}
	warm := !p.warming && free < p.config.MinIdle && !now.Before(p.warmAfter)
	if warm {
		p.warming = true
	}
	p.wg.Add(len(closing))
	if warm {
		p.wg.Add(1)
	}
	p.mu.Unlock()
	for _, t := range closing {
		go func(t *tunnel) {
			defer p.wg.Done()
			_ = p.closeTunnel(t)
		}(t)
	}
	if warm {
		go p.warm()
	}
}

// warm opens tunnels until the reserve is met; after a failure it backs off
// so an empty node table does not cause a connect attempt every second.
func (p *Pool) warm() {
	defer p.wg.Done()
	defer func() {
		p.mu.Lock()
		p.warming = false
		p.mu.Unlock()
	}()
	for {
		p.mu.Lock()
		free := 0
		for _, t := range p.tunnels {
			if t.sessions == 0 {
				free++
			}
		}
		done := p.closed || free >= p.config.MinIdle
		p.mu.Unlock()
		if done {
			return
		}
		t, err := p.open(p.ctx, "", "", false)
		if err != nil {
			p.config.Logf("warm tunnel: %v", err)
			p.mu.Lock()
			p.warmAfter = time.Now().Add(30 * time.Second)
			p.mu.Unlock()
			return
		}
		p.lease(Request{}, t).Release()
	}
}
