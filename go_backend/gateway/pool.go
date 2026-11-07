package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
)

// Endpoint is a connected tunnel. Unit tests use a lifecycle-only fake; the
// production factory creates official C++ Core sessions and real TUN devices.
type Endpoint interface {
	Device() string
	Info() (core.ConnectionInfo, error)
	Failure() <-chan struct{}
	FailureError() error
	Close(context.Context) error
}

type EndpointFactory func(context.Context) (Endpoint, error)

type PoolConfig struct {
	MinSpare       int
	MaxTunnels     int
	CreateAttempts int
	ConnectTimeout time.Duration
	IdleTimeout    time.Duration
	Factory        EndpointFactory
	Logf           func(string, ...any)
}

// SessionStatus exposes runtime assignment state without managing native clients.
type SessionStatus struct {
	ID      string    `json:"id"`
	TTL     string    `json:"ttl"`
	Expires time.Time `json:"expires"`
	Device  string    `json:"device"`
	NodeID  string    `json:"node_id,omitempty"`
	Leases  int       `json:"leases"`
}

type sessionEntry struct {
	spec     SessionSpec
	endpoint Endpoint
	expires  time.Time
	leases   int
	lastUsed time.Time
}

type Pool struct {
	mu             sync.Mutex
	config         PoolConfig
	sessions       map[string]*sessionEntry
	spare          []Endpoint
	assigned       map[Endpoint]struct{}
	owned          map[Endpoint]struct{}
	endpointLeases map[Endpoint]int
	pending        int
	wake           chan struct{}
	closed         bool
	cancel         context.CancelFunc
	workerCtx      context.Context
	workers        sync.WaitGroup
	lifecycle      sync.WaitGroup
}

// Lease pins one session egress for a single incoming proxy connection.
type Lease struct {
	Session SessionSpec
	Egress  Endpoint
	Info    core.ConnectionInfo
	Expires time.Time

	pool  *Pool
	entry *sessionEntry
	once  sync.Once
}

// NewPool starts background refresh and idle retirement. TTL expiry takes
// effect on the next connection, never by migrating established TCP streams.
func NewPool(parent context.Context, config PoolConfig) (*Pool, error) {
	if config.Factory == nil {
		return nil, errors.New("endpoint factory is required")
	}
	if config.MinSpare < 0 || config.MaxTunnels < 1 || config.MinSpare > config.MaxTunnels {
		return nil, fmt.Errorf("spare %d must be within capacity %d", config.MinSpare, config.MaxTunnels)
	}
	if config.CreateAttempts < 1 {
		return nil, errors.New("create attempts must be positive")
	}
	if config.ConnectTimeout <= 0 || config.IdleTimeout <= 0 {
		return nil, errors.New("connect and idle durations must be positive")
	}
	if config.Logf == nil {
		config.Logf = log.Printf
	}
	ctx, cancel := context.WithCancel(parent)
	p := &Pool{config: config, sessions: make(map[string]*sessionEntry),
		assigned: make(map[Endpoint]struct{}), endpointLeases: make(map[Endpoint]int),
		owned: make(map[Endpoint]struct{}),
		wake:  make(chan struct{}), cancel: cancel, workerCtx: ctx}
	p.lifecycle.Add(1)
	go func() {
		defer p.lifecycle.Done()
		p.reclaimer(ctx)
	}()
	return p, nil
}

func (p *Pool) signal() {
	close(p.wake)
	p.wake = make(chan struct{})
}

// build reserves worker lifetime before closing can wait on it. Factory must
// honor the pool's connection timeout, since native setup is not interruptible.
func (p *Pool) build() (Endpoint, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("pool closed")
	}
	p.workers.Add(1)
	p.mu.Unlock()
	endpoint, err := p.config.Factory(p.workerCtx)
	if err != nil {
		p.workers.Done()
		return nil, err
	}
	go p.monitor(endpoint)
	p.mu.Lock()
	if p.closed || terminal(endpoint) {
		p.mu.Unlock()
		p.close(endpoint)
		return nil, errors.New("tunnel failed or pool closed during setup")
	}
	p.owned[endpoint] = struct{}{}
	p.spare = append(p.spare, endpoint)
	p.pending--
	p.signal()
	p.mu.Unlock()
	return endpoint, nil
}

func (p *Pool) monitor(endpoint Endpoint) {
	defer p.workers.Done()
	<-endpoint.Failure()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	delete(p.assigned, endpoint)
	delete(p.endpointLeases, endpoint)
	p.removeSpare(endpoint)
	p.signal()
	p.mu.Unlock()
	if err := endpoint.FailureError(); err != nil {
		p.config.Logf("tunnel disconnected %s: %v", endpoint.Device(), err)
	}
	p.close(endpoint)
}

func (p *Pool) removeSpare(endpoint Endpoint) {
	for i, candidate := range p.spare {
		if candidate == endpoint {
			p.spare = append(p.spare[:i], p.spare[i+1:]...)
			return
		}
	}
}

// Acquire binds a sticky session to an available, healthy and unexpired tunnel.
func (p *Pool) Acquire(ctx context.Context, spec SessionSpec) (*Lease, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errors.New("pool closed")
		}
		now := time.Now()
		entry := p.sessions[spec.ID]
		var avoid Endpoint
		if entry != nil && !SameSession(entry.spec, spec) {
			p.mu.Unlock()
			return nil, fmt.Errorf("session %q cannot be used with a different TTL", spec.ID)
		}
		if entry != nil {
			if now.Before(entry.expires) && !terminal(entry.endpoint) {
				entry.leases++
				p.endpointLeases[entry.endpoint]++
				entry.lastUsed = now
				info, err := safeInfo(entry.endpoint)
				p.mu.Unlock()
				lease := &Lease{Session: spec, Egress: entry.endpoint,
					Info: info, Expires: entry.expires, pool: p, entry: entry}
				if err != nil {
					lease.Release()
					return nil, err
				}
				return lease, nil
			}
			avoid = entry.endpoint
			p.unassign(entry)
			delete(p.sessions, spec.ID)
		}
		for _, endpoint := range p.spare {
			if endpoint != avoid {
				return p.useEndpoint(spec, endpoint, now)
			}
		}
		if len(p.spare)+len(p.assigned)+p.pending < p.config.MaxTunnels {
			p.pending++
			p.signal()
			p.mu.Unlock()
			_, err := p.build()
			if err != nil {
				p.mu.Lock()
				p.pending--
				p.signal()
				p.mu.Unlock()
				return nil, fmt.Errorf("connect tunnel for %q: %w", spec.ID, err)
			}
			continue
		}
		if p.pending == 0 {
			p.mu.Unlock()
			return nil, fmt.Errorf("no other healthy tunnel available for session assignment %q", spec.ID)
		}
		wake := p.wake
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for tunnel: %w", ctx.Err())
		case <-wake:
		}
	}
}

func (p *Pool) useEndpoint(spec SessionSpec, endpoint Endpoint, now time.Time) (*Lease, error) {
	if terminal(endpoint) {
		p.signal()
		p.mu.Unlock()
		return nil, errors.New("tunnel failed during assignment")
	}
	p.removeSpare(endpoint)
	p.assigned[endpoint] = struct{}{}
	p.endpointLeases[endpoint]++
	entry := &sessionEntry{spec: spec, endpoint: endpoint, expires: now.Add(spec.TTL), leases: 1, lastUsed: now}
	p.sessions[spec.ID] = entry
	info, err := safeInfo(endpoint)
	p.signal()
	p.mu.Unlock()
	lease := &Lease{Session: spec, Egress: endpoint, Info: info, Expires: entry.expires, pool: p, entry: entry}
	if err != nil {
		lease.Release()
		return nil, err
	}
	return lease, nil
}

func safeInfo(endpoint Endpoint) (info core.ConnectionInfo, err error) {
	if terminal(endpoint) {
		return info, errors.New("tunnel is no longer connected")
	}
	return endpoint.Info()
}

func terminal(endpoint Endpoint) bool {
	select {
	case <-endpoint.Failure():
		return true
	default:
		return false
	}
}

func (p *Pool) unassign(entry *sessionEntry) {
	if p.endpointLeases[entry.endpoint] > 0 {
		// A prior generation can outlive its session mapping. Keep that TUN
		// assigned solely to the old TCP connections until their leases end.
		return
	}
	delete(p.assigned, entry.endpoint)
	if !terminal(entry.endpoint) {
		p.spare = append(p.spare, entry.endpoint)
	}
	p.signal()
}

// Release finishes one lease without interfering with other live connections.
func (l *Lease) Release() {
	l.once.Do(func() {
		l.pool.mu.Lock()
		if l.pool.endpointLeases[l.Egress] > 0 {
			l.pool.endpointLeases[l.Egress]--
		}
		entry := l.pool.sessions[l.Session.ID]
		if entry != nil && entry == l.entry {
			if entry.leases > 0 {
				entry.leases--
			}
			entry.lastUsed = time.Now()
		}
		if l.pool.endpointLeases[l.Egress] == 0 {
			delete(l.pool.endpointLeases, l.Egress)
			inUse := false
			for _, current := range l.pool.sessions {
				if current.endpoint == l.Egress {
					inUse = true
					break
				}
			}
			if _, assigned := l.pool.assigned[l.Egress]; assigned && !inUse {
				delete(l.pool.assigned, l.Egress)
				if !terminal(l.Egress) && !l.pool.closed {
					l.pool.spare = append(l.pool.spare, l.Egress)
				}
			}
		}
		l.pool.signal()
		l.pool.mu.Unlock()
	})
}

// Warm keeps a healthy reserve without leaving pending funds behind on error.
func (p *Pool) Warm(ctx context.Context, count int) error {
	if count < 0 {
		return errors.New("warm count cannot be negative")
	}
	if count > p.config.MaxTunnels {
		return fmt.Errorf("warm count exceeds capacity %d", p.config.MaxTunnels)
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return errors.New("pool closed")
		}
		missing := count - len(p.spare) - len(p.assigned) - p.pending
		if missing <= 0 {
			p.mu.Unlock()
			return nil
		}
		if len(p.spare)+len(p.assigned)+p.pending >= p.config.MaxTunnels {
			p.mu.Unlock()
			return errors.New("all endpoints assigned before meeting warm target")
		}
		p.pending++
		p.signal()
		p.mu.Unlock()
		var err error
		select {
		case <-ctx.Done():
			err = ctx.Err()
		default:
			_, err = p.build()
		}
		if err != nil {
			p.mu.Lock()
			p.pending--
			p.signal()
			p.mu.Unlock()
			return fmt.Errorf("warm tunnel: %w", err)
		}
	}
}

func (p *Pool) reclaimer(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				return
			}
			now := time.Now()
			for key, entry := range p.sessions {
				if entry.leases == 0 && now.Sub(entry.lastUsed) >= p.config.IdleTimeout {
					p.unassign(entry)
					delete(p.sessions, key)
				}
			}
			var discard []Endpoint
			for len(p.spare) > p.config.MinSpare {
				last := len(p.spare) - 1
				discard = append(discard, p.spare[last])
				p.spare = p.spare[:last]
			}
			p.signal()
			p.mu.Unlock()
			for _, endpoint := range discard {
				p.close(endpoint)
			}
			if count := p.config.MinSpare; count > 0 && ctx.Err() == nil {
				if err := p.Warm(ctx, count); err != nil && ctx.Err() == nil {
					p.config.Logf("%v", err)
				}
			}
		}
	}
}

func (p *Pool) close(endpoint Endpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := endpoint.Close(ctx)
	if err != nil {
		p.config.Logf("close %s: %v", endpoint.Device(), err)
	}
	p.mu.Lock()
	delete(p.owned, endpoint)
	p.mu.Unlock()
}

func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel()
	endpoints := make([]Endpoint, 0, len(p.owned))
	for endpoint := range p.owned {
		endpoints = append(endpoints, endpoint)
	}
	p.spare = nil
	p.assigned = make(map[Endpoint]struct{})
	p.sessions = make(map[string]*sessionEntry)
	p.endpointLeases = make(map[Endpoint]int)
	p.signal()
	p.mu.Unlock()
	// Native completion releases monitor goroutines, so stop live endpoints
	// before waiting. Setup workers still close resources created concurrently.
	for _, endpoint := range endpoints {
		p.close(endpoint)
	}
	p.workers.Wait()
	p.lifecycle.Wait()
	p.mu.Lock()
	for endpoint := range p.owned {
		endpoints = append(endpoints, endpoint)
	}
	p.mu.Unlock()
	for _, endpoint := range endpoints {
		p.close(endpoint)
	}
	return nil
}

// Status returns session count, spare identities and current ticket bindings.
func (p *Pool) Status() (active int, spare []SessionStatus, connected []SessionStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	connected = make([]SessionStatus, 0, len(p.sessions))
	for id, entry := range p.sessions {
		status := SessionStatus{ID: id, TTL: entry.spec.TTL.String(), Expires: entry.expires,
			Leases: entry.leases}
		if !terminal(entry.endpoint) {
			status.Device = entry.endpoint.Device()
		}
		if native, ok := entry.endpoint.(interface{ CandidateID() string }); ok {
			status.NodeID = native.CandidateID()
		}
		connected = append(connected, status)
	}
	for _, endpoint := range p.spare {
		if !terminal(endpoint) {
			spare = append(spare, SessionStatus{Device: endpoint.Device()})
		}
	}
	active = len(p.sessions)
	return active, spare, connected
}

// Invalidate closes unused prewarmed tunnels so a new routing policy cannot
// accidentally reuse them. Active leases keep their native endpoints alive.
func (p *Pool) Invalidate() {
	p.mu.Lock()
	for _, entry := range p.sessions {
		entry.expires = time.Now()
	}
	spare := append([]Endpoint(nil), p.spare...)
	p.spare = nil
	p.signal()
	p.mu.Unlock()
	for _, endpoint := range spare {
		p.close(endpoint)
	}
}

func (p *Pool) Pending() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending
}
