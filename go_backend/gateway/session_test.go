package gateway

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/LimLLL/vpngate-proxy/go_backend/core"
)

func TestParseSession(t *testing.T) {
	spec, err := ParseSession("session-home_01.t-minutes-t-15")
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID != "home_01.t-minutes" || spec.TTL != 15*time.Minute {
		t.Fatalf("unexpected session: %+v", spec)
	}
	for _, username := range []string{"", "password", "session-../admin", "session-a-t-0", "session-a-t-1441"} {
		if _, err := ParseSession(username); err == nil {
			t.Errorf("expected invalid session %q to be rejected", username)
		}
	}
}

type fakeEndpoint struct {
	name   string
	failed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	closed bool
}

func testEndpoint(name string) *fakeEndpoint {
	return &fakeEndpoint{name: name, failed: make(chan struct{})}
}

func (f *fakeEndpoint) Device() string { return f.name }
func (f *fakeEndpoint) Info() (core.ConnectionInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return core.ConnectionInfo{}, fmt.Errorf("endpoint closed")
	}
	return core.ConnectionInfo{Defined: true, TUNName: f.name, VpnIP4: "10.66.0.2"}, nil
}
func (f *fakeEndpoint) Failure() <-chan struct{} { return f.failed }
func (f *fakeEndpoint) FailureError() error      { return nil }
func (f *fakeEndpoint) Close(ctx context.Context) error {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.failed)
	})
	return nil
}

func testPool(t *testing.T, spare, max int, ttl time.Duration) *Pool {
	t.Helper()
	var next int
	var mu sync.Mutex
	pool, err := NewPool(context.Background(), PoolConfig{
		MinSpare: spare, MaxTunnels: max, CreateAttempts: 1,
		ConnectTimeout: time.Second, IdleTimeout: ttl,
		Factory: func(ctx context.Context) (Endpoint, error) {
			mu.Lock()
			next++
			name := fmt.Sprintf("tun%d", next)
			mu.Unlock()
			return testEndpoint(name), nil
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("pool close: %v", err)
		}
	})
	return pool
}

func TestStickySessionAndDistinctEgress(t *testing.T) {
	pool := testPool(t, 2, 4, time.Minute)
	ctx := context.Background()
	one, err := pool.Acquire(ctx, SessionSpec{ID: "home", TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	two, err := pool.Acquire(ctx, SessionSpec{ID: "office", TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	again, err := pool.Acquire(ctx, SessionSpec{ID: "home", TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if one.Egress != again.Egress {
		t.Fatal("sticky session changed tunnel before expiration")
	}
	if one.Egress == two.Egress {
		t.Fatal("distinct sessions were assigned the same available tunnel")
	}
	one.Release()
	two.Release()
	again.Release()
}

func TestExpiryReassignsWithoutInvalidatingEarlierLease(t *testing.T) {
	pool := testPool(t, 2, 4, 20*time.Millisecond)
	first, err := pool.Acquire(context.Background(), SessionSpec{ID: "expiring", TTL: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	second, err := pool.Acquire(context.Background(), SessionSpec{ID: "expiring", TTL: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if first.Egress == second.Egress {
		t.Fatal("expired session kept the same tunnel")
	}
	first.Release()
	second.Release()
	pool.Close()
}

func TestConcurrentSessionAllocation(t *testing.T) {
	pool := testPool(t, 32, 32, time.Minute)
	var wg sync.WaitGroup
	results := make(chan error, 64)
	for index := 0; index < 64; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			id := fmt.Sprintf("session-%d", index%32)
			lease, err := pool.Acquire(context.Background(), SessionSpec{ID: id, TTL: time.Minute})
			if err == nil {
				lease.Release()
			}
			results <- err
		}(index)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
}
