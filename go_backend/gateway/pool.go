package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

// Endpoint is one connected tunnel. Failure closes on an unexpected disconnect
// and on a planned Close alike; FailureError is nil for the planned case.
type Endpoint interface {
	Device() string
	Failure() <-chan struct{}
	FailureError() error
	Close(context.Context) error
}

// Connector opens a tunnel to node on a TUN slot. Slots are unique among live
// tunnels and are reused only after the previous holder closed successfully.
type Connector func(ctx context.Context, node nodes.Candidate, slot int) (Endpoint, error)

// NodeSource is satisfied by *nodes.Registry.
type NodeSource interface {
	Pick(nodes.Filter, time.Time) []nodes.Candidate
	ReportSuccess(id string, now time.Time)
	ReportFailure(id string, now time.Time)
}

var (
	// ErrUnavailable means the request was valid but no tunnel could serve it.
	ErrUnavailable = errors.New("no tunnel available")
	// ErrSessionConflict means a live session was reused with other parameters.
	ErrSessionConflict = errors.New("session is active with different parameters")
	errPoolClosed      = errors.New("pool closed")
)

// sessionRetention keeps an expired session's last node so the next request
// with that ID still rotates away from it.
const sessionRetention = 30 * time.Minute

type PoolConfig struct {
	Nodes   NodeSource
	Connect Connector
	// MaxTunnels caps concurrent tunnels and is also the number of TUN slots.
	MaxTunnels int
	// MinIdle tunnels without a sticky session are kept warm for new sessions.
	MinIdle int
	// IdleTimeout closes unused tunnels beyond the warm reserve.
	IdleTimeout     time.Duration
	ConnectTimeout  time.Duration
	ConnectAttempts int
	Logf            func(string, ...any)
}

// tunnel is shared by every session and connection routed to its node, since
// a second tunnel to the same node would not give a different egress IP.
type tunnel struct {
	node     nodes.Candidate
	device   string
	slot     int
	endpoint Endpoint
	leases   int // open proxy connections
	sessions int // unexpired sticky sessions bound here
	lastUsed time.Time
	retired  bool
}

type session struct {
	request   Request
	tunnel    *tunnel // nil once expired or after the tunnel died
	node      string  // last assigned node, excluded when rotating
	expires   time.Time
	assigning chan struct{}
}

// Pool maps requests to tunnels. Expiry only affects new connections; open
// connections keep their tunnel alive until they finish.
type Pool struct {
	config PoolConfig
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	closed    bool
	tunnels   map[string]*tunnel
	opening   map[string]bool
	sessions  map[string]*session
	slots     []bool
	changed   chan struct{} // closed and replaced whenever an open finishes
	next      int
	warming   bool
	warmAfter time.Time
}

// Lease pins one proxy connection to a tunnel until Release.
type Lease struct {
	Request Request
	Device  string
	NodeID  string
	Country string

	pool   *Pool
	tunnel *tunnel
	once   sync.Once
}

func NewPool(parent context.Context, config PoolConfig) (*Pool, error) {
	if config.Nodes == nil || config.Connect == nil {
		return nil, errors.New("pool needs a node source and a connector")
	}
	if config.MaxTunnels < 1 || config.MinIdle < 0 || config.MinIdle > config.MaxTunnels {
		return nil, fmt.Errorf("warm reserve %d must fit within %d tunnels", config.MinIdle, config.MaxTunnels)
	}
	if config.IdleTimeout <= 0 || config.ConnectTimeout <= 0 || config.ConnectAttempts < 1 {
		return nil, errors.New("pool timeouts and connect attempts must be positive")
	}
	if config.Logf == nil {
		config.Logf = log.Printf
	}
	ctx, cancel := context.WithCancel(parent)
	p := &Pool{
		config: config, ctx: ctx, cancel: cancel,
		tunnels: make(map[string]*tunnel), opening: make(map[string]bool),
		sessions: make(map[string]*session), slots: make([]bool, config.MaxTunnels),
		changed: make(chan struct{}),
	}
	p.wg.Add(1)
	go p.maintain()
	return p, nil
}

// Acquire returns a lease for one new proxy connection.
func (p *Pool) Acquire(ctx context.Context, request Request) (*Lease, error) {
	if request.Session == "" {
		t, err := p.choose(ctx, request.Country, "", false)
		if err != nil {
			return nil, err
		}
		return p.lease(request, t), nil
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errPoolClosed
		}
		now := time.Now()
		s := p.sessions[request.Session]
		if s != nil && s.assigning != nil {
			// Another connection of this session is choosing its tunnel.
			wait := s.assigning
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
			}
			continue
		}
		if s != nil && now.Before(s.expires) {
			if s.request != request {
				p.mu.Unlock()
				return nil, fmt.Errorf("%w: %q", ErrSessionConflict, request.Session)
			}
			if t := s.tunnel; t != nil && !t.retired {
				t.leases++
				t.lastUsed = now
				p.mu.Unlock()
				return p.lease(request, t), nil
			}
		}
		exclude := ""
		if s == nil {
			s = &session{}
			p.sessions[request.Session] = s
		} else {
			exclude = s.node
			p.unbind(s)
		}
		s.request = request
		wait := make(chan struct{})
		s.assigning = wait
		p.mu.Unlock()

		t, err := p.choose(ctx, request.Country, exclude, true)

		p.mu.Lock()
		s.assigning = nil
		close(wait)
		if err != nil {
			if s.node == "" {
				delete(p.sessions, request.Session)
			}
			p.mu.Unlock()
			return nil, err
		}
		s.tunnel, s.node = t, t.node.ID
		s.expires = time.Now().Add(request.TTL)
		p.mu.Unlock()
		return p.lease(request, t), nil
	}
}

// choose returns a tunnel with a lease, and for sticky requests the session,
// already counted under the same lock that picked it, so concurrent new
// sessions cannot both claim the same free tunnel. Sticky sessions prefer a
// tunnel no other session uses, then a new node, and share only as a last
// resort; rotating connections take live tunnels in turn. While other opens
// are in flight it waits for them rather than failing, which matters for the
// burst of requests right after startup.
func (p *Pool) choose(ctx context.Context, country, exclude string, sticky bool) (*tunnel, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errPoolClosed
		}
		if t := p.pickLive(country, exclude, sticky, false); t != nil {
			p.mu.Unlock()
			return t, nil
		}
		p.mu.Unlock()
		t, openErr := p.open(ctx, country, exclude, sticky)
		if t != nil {
			return t, nil
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errPoolClosed
		}
		if t := p.pickLive(country, exclude, sticky, true); t != nil {
			p.mu.Unlock()
			return t, nil
		}
		if t := p.tunnels[exclude]; exclude != "" && t != nil && matches(t, country) {
			p.config.Logf("no other node for country %q; session stays on %s", country, exclude)
			p.take(t, sticky)
			p.mu.Unlock()
			return t, nil
		}
		if len(p.opening) == 0 {
			p.mu.Unlock()
			return nil, fmt.Errorf("%w for country %q: %v", ErrUnavailable, country, openErr)
		}
		wait := p.changed
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w for country %q: %v", ErrUnavailable, country, ctx.Err())
		case <-wait:
		}
	}
}

// notify must be called with p.mu held.
func (p *Pool) notify() {
	close(p.changed)
	p.changed = make(chan struct{})
}

// pickLive must be called with p.mu held; it takes the result like choose.
func (p *Pool) pickLive(country, exclude string, sticky, share bool) *tunnel {
	var live []*tunnel
	for id, t := range p.tunnels {
		if id != exclude && matches(t, country) && (!sticky || share || t.sessions == 0) {
			live = append(live, t)
		}
	}
	if len(live) == 0 {
		return nil
	}
	sort.Slice(live, func(i, j int) bool {
		a, b := live[i], live[j]
		if sticky && a.sessions != b.sessions {
			return a.sessions < b.sessions
		}
		if sticky && a.leases != b.leases {
			return a.leases < b.leases
		}
		return a.node.ID < b.node.ID
	})
	t := live[0]
	if !sticky {
		t = live[p.next%len(live)]
		p.next++
	}
	p.take(t, sticky)
	return t
}

func (p *Pool) take(t *tunnel, sticky bool) {
	t.leases++
	if sticky {
		t.sessions++
	}
	t.lastUsed = time.Now()
}

func matches(t *tunnel, country string) bool {
	return !t.retired && (country == "" || t.node.Country == country)
}

func (p *Pool) unbind(s *session) {
	if s.tunnel != nil {
		s.tunnel.sessions--
		s.tunnel = nil
	}
}

func (p *Pool) lease(request Request, t *tunnel) *Lease {
	return &Lease{Request: request, Device: t.device, NodeID: t.node.ID,
		Country: t.node.Country, pool: p, tunnel: t}
}

func (l *Lease) Release() {
	l.once.Do(func() {
		l.pool.mu.Lock()
		l.tunnel.leases--
		l.tunnel.lastUsed = time.Now()
		l.pool.mu.Unlock()
	})
}

type TunnelStatus struct {
	Node     string
	Country  string
	Device   string
	Sessions int
	Leases   int
}

type SessionStatus struct {
	ID      string
	Node    string
	Device  string // empty when the session currently has no live tunnel
	Expires time.Time
}

type PoolStatus struct {
	Tunnels  []TunnelStatus
	Sessions []SessionStatus
}

func (p *Pool) Status() PoolStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	var status PoolStatus
	for _, t := range p.tunnels {
		status.Tunnels = append(status.Tunnels, TunnelStatus{Node: t.node.ID, Country: t.node.Country,
			Device: t.device, Sessions: t.sessions, Leases: t.leases})
	}
	for id, s := range p.sessions {
		entry := SessionStatus{ID: id, Node: s.node, Expires: s.expires}
		if s.tunnel != nil && !s.tunnel.retired {
			entry.Device = s.tunnel.device
		}
		status.Sessions = append(status.Sessions, entry)
	}
	sort.Slice(status.Tunnels, func(i, j int) bool { return status.Tunnels[i].Device < status.Tunnels[j].Device })
	sort.Slice(status.Sessions, func(i, j int) bool { return status.Sessions[i].ID < status.Sessions[j].ID })
	return status
}

// Close stops maintenance and closes every tunnel; open proxy connections
// should be closed first.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel()
	var all []*tunnel
	for _, t := range p.tunnels {
		p.retire(t)
		all = append(all, t)
	}
	p.mu.Unlock()
	errs := make(chan error, len(all))
	for _, t := range all {
		go func(t *tunnel) { errs <- p.closeTunnel(t) }(t)
	}
	var failures []error
	for range all {
		if err := <-errs; err != nil {
			failures = append(failures, err)
		}
	}
	p.wg.Wait()
	return errors.Join(failures...)
}
