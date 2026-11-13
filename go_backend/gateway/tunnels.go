package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// open connects a tunnel claimed by reserve and measures its egress. On
// success the tunnel is live and the caller holds one lease on it; on failure
// it is gone, and its node cooled down unless the caller gave up first.
func (p *Pool) open(ctx context.Context, t *tunnel) error {
	connectCtx, cancel := context.WithTimeout(ctx, p.config.ConnectTimeout)
	endpoint, err := p.config.Connect(connectCtx, t.node, t.slot)
	cancel()
	if err != nil {
		p.mu.Lock()
		p.forget(t, true)
		p.mu.Unlock()
		p.connectFailed(ctx, t, err)
		return err
	}
	var egress string
	if p.config.Egress != nil {
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		egress, err = p.config.Egress(probeCtx, endpoint.Device())
		cancel()
		if err != nil {
			// Some nodes finish the handshake but forward nothing; such a
			// tunnel would only swallow requests.
			err = fmt.Errorf("no traffic through the tunnel: %w", err)
			closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			closeErr := endpoint.Close(closeCtx)
			cancel()
			p.mu.Lock()
			p.forget(t, closeErr == nil)
			p.mu.Unlock()
			p.connectFailed(ctx, t, err)
			return errors.Join(err, closeErr)
		}
	}
	p.config.Nodes.ReportSuccess(t.node.ID, egress, time.Now())
	p.mu.Lock()
	t.endpoint, t.device, t.egress, t.healthy, t.leases = endpoint, endpoint.Device(), egress, time.Now(), 1
	if p.closed {
		// Close may already be waiting on the WaitGroup, so this tunnel is
		// closed here rather than through retire.
		t.retired = true
		p.mu.Unlock()
		return errors.Join(errPoolClosed, p.shut(t))
	}
	p.wg.Add(1)
	go p.monitor(t)
	p.notify()
	p.mu.Unlock()
	p.config.Logf("tunnel %s up via %s (%s), egress %s", t.device, t.node.ID, t.node.Country, egress)
	return nil
}

func (p *Pool) connectFailed(ctx context.Context, t *tunnel, err error) {
	// A caller that gave up says nothing about the node; a timeout does.
	if ctx.Err() == nil {
		p.config.Nodes.ReportFailure(t.node.ID, time.Now())
	}
	p.config.Logf("connect %s (%s): %v", t.node.ID, t.node.Country, err)
}

// forget must be called with p.mu held. It releases the node of a tunnel that
// failed or closed, and its slot only after a clean close, because a failed
// close may leave the device or its routes behind.
func (p *Pool) forget(t *tunnel, freeSlot bool) {
	if p.tunnels[t.node.ID] == t {
		delete(p.tunnels, t.node.ID)
	}
	if freeSlot {
		p.slots[t.slot] = false
	}
	p.notify()
}

// retire must be called with p.mu held, and the caller must then call
// closeTunnel. Sessions still pointing at the tunnel see retired and pick
// another; open connections on it simply end.
func (p *Pool) retire(t *tunnel) {
	t.retired = true
	p.wg.Add(1)
}

// closeIfIdle must be called with p.mu held. It closes t in the background
// once no connection, session or chooser holds it.
func (p *Pool) closeIfIdle(t *tunnel) {
	if t.live() && t.leases == 0 && t.sessions == 0 {
		p.retire(t)
		go p.closeTunnel(t)
	}
}

func (p *Pool) closeTunnel(t *tunnel) error {
	defer p.wg.Done()
	return p.shut(t)
}

// shut closes a retired tunnel and releases its node.
func (p *Pool) shut(t *tunnel) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := t.endpoint.Close(ctx)
	cancel()
	p.mu.Lock()
	// Recorded before the node is released, so the next pick already sees
	// this IP as just used.
	p.config.Nodes.ReportUsed(t.egress, time.Now())
	p.forget(t, err == nil)
	p.mu.Unlock()
	if err != nil {
		p.config.Logf("close %s: %v; slot %d stays reserved", t.device, err, t.slot)
		return fmt.Errorf("close %s: %w", t.device, err)
	}
	return nil
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
	p.dropped(t, t.endpoint.FailureError())
}

// dropped cools down the node of a retired tunnel that stopped working and
// closes the tunnel.
func (p *Pool) dropped(t *tunnel, reason error) {
	p.config.Logf("tunnel %s via %s dropped: %v", t.device, t.node.ID, reason)
	p.config.Nodes.ReportFailure(t.node.ID, time.Now())
	_ = p.closeTunnel(t)
}

type healthCheck struct {
	done chan struct{}
	ok   bool
}

// check probes t, sharing one probe among concurrent callers, and reports
// whether the tunnel still carries traffic. A caller that gives up before the
// probe ends learns nothing and gets true.
func (p *Pool) check(ctx context.Context, t *tunnel) bool {
	p.mu.Lock()
	if t.retired {
		p.mu.Unlock()
		return false
	}
	c := p.startCheck(t)
	p.mu.Unlock()
	if c == nil {
		return true
	}
	select {
	case <-c.done:
		return c.ok
	case <-ctx.Done():
		return true
	}
}

// startCheck must be called with p.mu held on a live tunnel. It returns nil
// when the pool has no egress probe to check with.
func (p *Pool) startCheck(t *tunnel) *healthCheck {
	if p.config.Egress == nil {
		return nil
	}
	if t.check == nil {
		t.check = &healthCheck{done: make(chan struct{})}
		p.wg.Add(1)
		go p.runCheck(t, t.check)
	}
	return t.check
}

// runCheck retires a tunnel whose probe fails before it reports the result,
// so a caller retrying right away cannot be handed the same tunnel.
func (p *Pool) runCheck(t *tunnel, c *healthCheck) {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(p.ctx, probeTimeout)
	egress, err := p.config.Egress(ctx, t.device)
	cancel()
	p.mu.Lock()
	t.check = nil
	failed := err != nil && p.ctx.Err() == nil && !t.retired
	changed := err == nil && !t.retired && egress != t.egress
	switch {
	case failed:
		p.retire(t)
	case err == nil && !t.retired:
		t.healthy = time.Now()
		if changed {
			p.config.Logf("tunnel %s via %s: egress changed from %s to %s", t.device, t.node.ID, t.egress, egress)
			t.egress = egress
		}
	}
	c.ok = !t.retired
	p.mu.Unlock()
	close(c.done)
	if changed {
		p.config.Nodes.ReportSuccess(t.node.ID, egress, time.Now())
	}
	if failed {
		p.dropped(t, fmt.Errorf("health check: %w", err))
	}
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

// sweep expires sessions, which closes tunnels nothing holds any more, and
// probes session tunnels that have carried no traffic for a while.
func (p *Pool) sweep(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
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
	for _, t := range p.tunnels {
		if t.live() && t.sessions > 0 && now.Sub(t.healthy) >= p.config.HealthInterval {
			p.startCheck(t)
		}
	}
}
