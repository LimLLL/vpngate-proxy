package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/nodes"
)

type fakeEndpoint struct {
	device string
	failed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	err    error
	closed bool
}

func (f *fakeEndpoint) Device() string           { return f.device }
func (f *fakeEndpoint) Failure() <-chan struct{} { return f.failed }

func (f *fakeEndpoint) FailureError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakeEndpoint) Close(context.Context) error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.once.Do(func() { close(f.failed) })
	return nil
}

// drop simulates the node going away.
func (f *fakeEndpoint) drop() {
	f.mu.Lock()
	f.err = errors.New("peer vanished")
	f.mu.Unlock()
	f.once.Do(func() { close(f.failed) })
}

func (f *fakeEndpoint) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// fakeNetwork connects instantly unless a node is marked as refusing. Nodes
// listed in egress report that public IP; others, and dead ones, fail the
// probe.
type fakeNetwork struct {
	mu        sync.Mutex
	refuse    map[string]bool
	dead      map[string]bool
	egress    map[string]string
	endpoints map[string]*fakeEndpoint
	devices   map[string]string
	connects  int
}

func (n *fakeNetwork) connect(_ context.Context, node nodes.Candidate, slot int) (Endpoint, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.connects++
	if n.refuse[node.ID] {
		return nil, errors.New("connection refused")
	}
	endpoint := &fakeEndpoint{device: fmt.Sprintf("tun%d", slot), failed: make(chan struct{})}
	n.endpoints[node.ID] = endpoint
	n.devices[endpoint.device] = node.ID
	return endpoint, nil
}

func (n *fakeNetwork) probe(_ context.Context, device string) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	id := n.devices[device]
	if egress, ok := n.egress[id]; ok && !n.dead[id] {
		return egress, nil
	}
	return "", errors.New("no reply through the tunnel")
}

// kill makes a connected node stop forwarding without dropping the tunnel.
func (n *fakeNetwork) kill(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dead[id] = true
}

func (n *fakeNetwork) endpoint(id string) *fakeEndpoint {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.endpoints[id]
}

// testNodes registers one node per country argument; earlier nodes score higher.
func testNodes(t *testing.T, countries ...string) *nodes.Registry {
	t.Helper()
	registry, err := nodes.OpenRegistry(nodes.RegistryConfig{MaxAge: time.Hour, MaxFailures: 3, Cooldown: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var listing []nodes.Candidate
	for i, country := range countries {
		id := fmt.Sprintf("10.0.0.%d", i+1)
		listing = append(listing, nodes.Candidate{ID: id, IP: id, Country: country, Score: 100 - i})
	}
	if _, err := registry.Merge(listing, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range listing {
		registry.ReportProbe(candidate.ID, true, time.Now())
	}
	return registry
}

type poolOptions struct {
	maxTunnels int
	health     time.Duration
	egress     map[string]string // node ID to public IP; nil disables probing
}

func newTestPool(t *testing.T, registry *nodes.Registry, options poolOptions) (*Pool, *fakeNetwork) {
	t.Helper()
	network := &fakeNetwork{refuse: map[string]bool{}, dead: map[string]bool{}, egress: options.egress,
		endpoints: map[string]*fakeEndpoint{}, devices: map[string]string{}}
	if options.maxTunnels == 0 {
		options.maxTunnels = 8
	}
	config := PoolConfig{
		Nodes: registry, Connect: network.connect, MaxTunnels: options.maxTunnels,
		ConnectTimeout: time.Second, ConnectAttempts: 3, HealthInterval: options.health, Logf: t.Logf,
	}
	if options.egress != nil {
		config.Egress = network.probe
	}
	pool, err := NewPool(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("pool close: %v", err)
		}
	})
	return pool, network
}

func acquire(t *testing.T, pool *Pool, request Request) *Lease {
	t.Helper()
	lease, err := pool.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("acquire %+v: %v", request, err)
	}
	t.Cleanup(lease.Release)
	return lease
}

// settled reports whether every tunnel has finished connecting or closing.
func settled(pool *Pool) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, t := range pool.tunnels {
		if !t.live() {
			return false
		}
	}
	return true
}

// coolingDown reports whether the registry currently skips the node.
func coolingDown(registry *nodes.Registry, id string) bool {
	node, ok := registry.Get(id)
	return !ok || time.Now().Before(node.RetryAfter)
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStickySessionsKeepTheirNodeAndSpreadOut(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "JP", "JP"), poolOptions{})
	seen := map[string]bool{}
	for _, id := range []string{"a", "b", "c"} {
		first := acquire(t, pool, Request{Session: id, TTL: time.Minute})
		again := acquire(t, pool, Request{Session: id, TTL: time.Minute})
		if first.NodeID != again.NodeID || first.Device != again.Device {
			t.Fatalf("session %s moved from %s to %s before expiry", id, first.NodeID, again.NodeID)
		}
		if seen[first.NodeID] {
			t.Fatalf("session %s shares node %s although free nodes exist", id, first.NodeID)
		}
		seen[first.NodeID] = true
	}
	// With every node taken, a fourth session shares instead of failing.
	acquire(t, pool, Request{Session: "d", TTL: time.Minute})
}

func TestExpiredSessionMovesToAnotherNode(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{})
	first := acquire(t, pool, Request{Session: "a", TTL: 50 * time.Millisecond})
	time.Sleep(80 * time.Millisecond)
	second := acquire(t, pool, Request{Session: "a", TTL: 50 * time.Millisecond})
	if second.NodeID == first.NodeID {
		t.Fatalf("expired session stayed on %s", first.NodeID)
	}
	if network.endpoint(first.NodeID).isClosed() {
		t.Fatal("the old tunnel was closed while a connection still used it")
	}
}

func TestExpiredSessionStaysWhenNoOtherNodeExists(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "US"), poolOptions{})
	first := acquire(t, pool, Request{Country: "JP", Session: "a", TTL: 50 * time.Millisecond})
	time.Sleep(80 * time.Millisecond)
	second := acquire(t, pool, Request{Country: "JP", Session: "a", TTL: 50 * time.Millisecond})
	if second.NodeID != first.NodeID {
		t.Fatalf("the only JP node is %s, got %s", first.NodeID, second.NodeID)
	}
}

func TestCountryFilter(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "US", "JP"), poolOptions{})
	if lease := acquire(t, pool, Request{Country: "US"}); lease.Country != "US" {
		t.Fatalf("US request got %s", lease.Country)
	}
	if lease := acquire(t, pool, Request{Country: "JP", Session: "s", TTL: time.Minute}); lease.Country != "JP" {
		t.Fatalf("JP session got %s", lease.Country)
	}
	if _, err := pool.Acquire(context.Background(), Request{Country: "KR"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("KR request: want ErrUnavailable, got %v", err)
	}
}

func TestSessionParametersCannotChangeWhileActive(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "US"), poolOptions{})
	acquire(t, pool, Request{Session: "a", TTL: time.Minute})
	for _, changed := range []Request{
		{Session: "a", TTL: 2 * time.Minute},
		{Session: "a", TTL: time.Minute, Country: "US"},
	} {
		if _, err := pool.Acquire(context.Background(), changed); !errors.Is(err, ErrSessionConflict) {
			t.Fatalf("%+v: want ErrSessionConflict, got %v", changed, err)
		}
	}
}

func TestRotatingConnectionsEachGetAFreshTunnel(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP", "JP"), poolOptions{})
	if len(pool.Status().Tunnels) != 0 {
		t.Fatal("tunnels were opened before any request")
	}
	first := acquire(t, pool, Request{})
	second := acquire(t, pool, Request{})
	if first.NodeID == second.NodeID {
		t.Fatalf("two open rotating connections share %s", first.NodeID)
	}
	first.Release()
	eventually(t, "the released tunnel to close", func() bool { return network.endpoint(first.NodeID).isClosed() })
	if network.endpoint(second.NodeID).isClosed() {
		t.Fatal("a tunnel still in use was closed")
	}
}

func TestDroppedTunnelMovesSessionAndCoolsNodeDown(t *testing.T) {
	registry := testNodes(t, "JP", "JP")
	pool, network := newTestPool(t, registry, poolOptions{})
	first := acquire(t, pool, Request{Session: "a", TTL: time.Minute})
	network.endpoint(first.NodeID).drop()
	eventually(t, "the dropped tunnel to be retired", func() bool {
		for _, tunnel := range pool.Status().Tunnels {
			if tunnel.Node == first.NodeID {
				return false
			}
		}
		return true
	})
	second := acquire(t, pool, Request{Session: "a", TTL: time.Minute})
	if second.NodeID == first.NodeID {
		t.Fatal("session stayed on a dropped node")
	}
	if !coolingDown(registry, first.NodeID) {
		t.Fatal("dropped node is not cooling down")
	}
}

func TestRefusingNodeIsSkipped(t *testing.T) {
	registry := testNodes(t, "JP", "JP")
	pool, network := newTestPool(t, registry, poolOptions{})
	network.mu.Lock()
	network.refuse["10.0.0.1"] = true
	network.mu.Unlock()
	if lease := acquire(t, pool, Request{}); lease.NodeID != "10.0.0.2" {
		t.Fatalf("expected the working node, got %s", lease.NodeID)
	}
}

func TestTunnelClosesWithItsLastLeaseAndSlotIsReused(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{})
	lease, err := pool.Acquire(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	firstNode, firstDevice := lease.NodeID, lease.Device
	lease.Release()
	eventually(t, "the tunnel to close and free its slot", func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return network.endpoint(firstNode).isClosed() && !pool.slots[0]
	})
	again := acquire(t, pool, Request{})
	if again.Device != firstDevice {
		t.Fatalf("slot was not reused: %s then %s", firstDevice, again.Device)
	}
}

func TestSessionKeepsItsTunnelBetweenConnections(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{})
	lease, err := pool.Acquire(context.Background(), Request{Session: "a", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if network.endpoint(lease.NodeID).isClosed() {
		t.Fatal("the session's tunnel closed before its TTL")
	}
	if again := acquire(t, pool, Request{Session: "a", TTL: time.Minute}); again.NodeID != lease.NodeID {
		t.Fatalf("session moved from %s to %s", lease.NodeID, again.NodeID)
	}
}

func TestFullPoolSharesALiveTunnel(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{maxTunnels: 1})
	first := acquire(t, pool, Request{})
	if second := acquire(t, pool, Request{}); second.NodeID != first.NodeID {
		t.Fatalf("with one slot the second connection should share %s, got %s", first.NodeID, second.NodeID)
	}
}

func TestPoolCloseClosesTunnels(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP"), poolOptions{})
	lease, err := pool.Acquire(context.Background(), Request{Session: "a", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if !network.endpoint(lease.NodeID).isClosed() {
		t.Fatal("Close left a tunnel open")
	}
	if _, err := pool.Acquire(context.Background(), Request{}); err == nil {
		t.Fatal("a closed pool handed out a lease")
	}
}

func TestConcurrentSessions(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "JP", "JP", "JP", "US", "US", "US", "US"), poolOptions{})
	var mu sync.Mutex
	assigned := map[string]string{}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("s%d", i%16)
			lease, err := pool.Acquire(context.Background(), Request{Session: id, TTL: time.Minute})
			if err != nil {
				errs <- err
				return
			}
			defer lease.Release()
			mu.Lock()
			defer mu.Unlock()
			if previous, ok := assigned[id]; ok && previous != lease.NodeID {
				errs <- fmt.Errorf("session %s split across %s and %s", id, previous, lease.NodeID)
			}
			assigned[id] = lease.NodeID
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
