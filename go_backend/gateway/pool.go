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
	Pick(nodes.Filter, time.Time) []nodes.Node
	ReportSuccess(id, egress string, now time.Time)
	ReportFailure(id string, now time.Time)
	ReportUsed(egress string, now time.Time)
}

var (
	// ErrUnavailable means the request was valid but no tunnel could serve it.
	ErrUnavailable = errors.New("no tunnel available")
	// ErrSessionConflict means a live session was reused with other parameters.
	ErrSessionConflict = errors.New("session is active with different parameters")
	errPoolClosed      = errors.New("pool closed")
)

const (
	// sessionRetention keeps an expired session's last node and egress so the
	// next request with that ID still rotates away from them.
	sessionRetention = 30 * time.Minute
	// probeTimeout bounds one egress probe, at connect and in health checks.
	probeTimeout          = 15 * time.Second
	defaultHealthInterval = time.Minute
)

type PoolConfig struct {
	Nodes   NodeSource
	Connect Connector
	// MaxTunnels caps concurrent tunnels and is also the number of TUN slots.
	MaxTunnels     int
	ConnectTimeout time.Duration
	// ConnectAttempts is how many nodes one request may try before it falls
	// back to sharing a live tunnel.
	ConnectAttempts int
	// Egress reports the public IP seen through a tunnel. Different nodes can
	// share one NAT egress, so sessions are spread and rotated by this IP
	// rather than by node. It doubles as the health check: a tunnel whose
	// probe fails carries no traffic and is dropped. With Egress nil every
	// tunnel counts as its own IP and is never checked.
	Egress func(ctx context.Context, device string) (string, error)
	// HealthInterval is how long a session's tunnel may go without a
	// successful dial before it is probed; zero means one minute.
	HealthInterval time.Duration
	Logf           func(string, ...any)
}

// tunnel is one OpenVPN connection. Each rotating connection opens its own and
// each session keeps its own until expiry; a tunnel closes as soon as nothing
// holds it. A node never has two tunnels at once, because VPNGate servers
// often refuse a second login from the same client.
type tunnel struct {
	node nodes.Candidate
	// lastEgress is the egress the node had last time; it stands in for
	// egress while the tunnel is connecting.
	lastEgress string
	egress     string // measured public IP; empty when unknown
	device     string
	slot       int
	endpoint   Endpoint     // nil while connecting
	leases     int          // open proxy connections plus choosers holding it
	sessions   int          // unexpired sticky sessions bound here
	retired    bool         // closing or closed; never handed out again
	healthy    time.Time    // last successful dial or probe
	check      *healthCheck // the running health check, if any
}

func (t *tunnel) live() bool { return t.endpoint != nil && !t.retired }

type session struct {
	request   Request
	tunnel    *tunnel // nil once expired or after the tunnel died
	last      avoid   // last assigned node and egress, avoided when rotating
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

	mu       sync.Mutex
	closed   bool
	tunnels  map[string]*tunnel // by node ID, while connecting, live or closing
	sessions map[string]*session
	slots    []bool
	changed  chan struct{} // closed and replaced whenever a tunnel comes up or goes away
}

// Lease pins one proxy connection to a tunnel until Release.
type Lease struct {
	Request Request
	Device  string
	NodeID  string
	Country string
	Egress  string // empty when unknown

	pool   *Pool
	tunnel *tunnel
	once   sync.Once
}

func NewPool(parent context.Context, config PoolConfig) (*Pool, error) {
	if config.Nodes == nil || config.Connect == nil {
		return nil, errors.New("pool needs a node source and a connector")
	}
	if config.MaxTunnels < 1 || config.ConnectTimeout <= 0 || config.ConnectAttempts < 1 {
		return nil, errors.New("pool tunnel limit, connect timeout and connect attempts must be positive")
	}
	if config.HealthInterval <= 0 {
		config.HealthInterval = defaultHealthInterval
	}
	if config.Logf == nil {
		config.Logf = log.Printf
	}
	ctx, cancel := context.WithCancel(parent)
	p := &Pool{
		config: config, ctx: ctx, cancel: cancel,
		tunnels: make(map[string]*tunnel), sessions: make(map[string]*session),
		slots: make([]bool, config.MaxTunnels), changed: make(chan struct{}),
	}
	p.wg.Add(1)
	go p.maintain()
	return p, nil
}

// Acquire returns a lease for one new proxy connection.
func (p *Pool) Acquire(ctx context.Context, request Request) (*Lease, error) {
	if request.Session == "" {
		t, err := p.choose(ctx, request.Country, avoid{}, false)
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
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
				lease := p.lease(request, t)
				p.mu.Unlock()
				return lease, nil
			}
		}
		if s == nil {
			s = &session{}
			p.sessions[request.Session] = s
		} else {
			p.unbind(s)
		}
		previous := s.last
		s.request = request
		wait := make(chan struct{})
		s.assigning = wait
		p.mu.Unlock()

		t, err := p.choose(ctx, request.Country, previous, true)

		p.mu.Lock()
		s.assigning = nil
		close(wait)
		if err != nil {
			if s.last.node == "" {
				delete(p.sessions, request.Session)
			}
			p.mu.Unlock()
			return nil, err
		}
		s.tunnel, s.last = t, avoid{node: t.node.ID, egress: t.egress}
		s.expires = time.Now().Add(request.TTL)
		lease := p.lease(request, t)
		p.mu.Unlock()
		return lease, nil
	}
}

// unbind must be called with p.mu held.
func (p *Pool) unbind(s *session) {
	if t := s.tunnel; t != nil {
		t.sessions--
		s.tunnel = nil
		p.closeIfIdle(t)
	}
}

// lease must be called with p.mu held, on a tunnel whose lease is counted.
func (p *Pool) lease(request Request, t *tunnel) *Lease {
	return &Lease{Request: request, Device: t.device, NodeID: t.node.ID,
		Country: t.node.Country, Egress: t.egress, pool: p, tunnel: t}
}

// Release ends the connection's hold on the tunnel, which closes once
// nothing else holds it.
func (l *Lease) Release() {
	l.once.Do(func() {
		l.pool.mu.Lock()
		l.tunnel.leases--
		l.pool.closeIfIdle(l.tunnel)
		l.pool.mu.Unlock()
	})
}

// ReportSuccess records a successful dial through the lease's tunnel, which
// postpones its next health check.
func (l *Lease) ReportSuccess() {
	l.pool.mu.Lock()
	l.tunnel.healthy = time.Now()
	l.pool.mu.Unlock()
}

// Recheck probes the lease's tunnel after a dial through it timed out. A
// tunnel that no longer carries traffic is dropped and its node cooled down;
// Recheck then returns false, and a new Acquire gets another tunnel.
func (l *Lease) Recheck(ctx context.Context) bool {
	return l.pool.check(ctx, l.tunnel)
}

type TunnelStatus struct {
	Node     string
	Egress   string
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
		if !t.live() {
			continue
		}
		status.Tunnels = append(status.Tunnels, TunnelStatus{Node: t.node.ID, Egress: t.egress, Country: t.node.Country,
			Device: t.device, Sessions: t.sessions, Leases: t.leases})
	}
	for id, s := range p.sessions {
		entry := SessionStatus{ID: id, Node: s.last.node, Expires: s.expires}
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
	p.notify()
	var all []*tunnel
	for _, t := range p.tunnels {
		if t.live() {
			p.retire(t)
			all = append(all, t)
		}
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
