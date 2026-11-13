package gateway

import (
	"context"
	"testing"
	"time"
)

// sharedEgress makes 10.0.0.1 and 10.0.0.2 leave through one NAT address,
// like VPNGate's academic servers do, while 10.0.0.3 has its own.
var sharedEgress = map[string]string{
	"10.0.0.1": "198.51.100.1", "10.0.0.2": "198.51.100.1", "10.0.0.3": "198.51.100.3",
}

func TestExpiredSessionAvoidsSharedEgress(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "JP", "JP"), poolOptions{egress: sharedEgress})
	first := acquire(t, pool, Request{Session: "a", TTL: 50 * time.Millisecond})
	time.Sleep(80 * time.Millisecond)
	second := acquire(t, pool, Request{Session: "a", TTL: 50 * time.Millisecond})
	if first.Egress != "198.51.100.1" || second.Egress != "198.51.100.3" {
		t.Fatalf("rotation went from %s (%s) to %s (%s); another node behind the same NAT is not a new IP",
			first.NodeID, first.Egress, second.NodeID, second.Egress)
	}
}

func TestSessionsSpreadAcrossEgress(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "JP", "JP"), poolOptions{egress: sharedEgress})
	x := acquire(t, pool, Request{Session: "x", TTL: time.Minute})
	y := acquire(t, pool, Request{Session: "y", TTL: time.Minute})
	if x.Egress == y.Egress {
		t.Fatalf("sessions share %s although another IP exists", x.Egress)
	}
}

func TestRotationMovesToTheLeastRecentlyUsedIP(t *testing.T) {
	pool, _ := newTestPool(t, testNodes(t, "JP", "JP", "JP"), poolOptions{egress: sharedEgress})
	var seen []string
	for i := 0; i < 6; i++ {
		lease, err := pool.Acquire(context.Background(), Request{})
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, lease.Egress)
		lease.Release()
		eventually(t, "the tunnel to close", func() bool { return settled(pool) && len(pool.Status().Tunnels) == 0 })
	}
	// The first passes learn that 10.0.0.1 and 10.0.0.2 share one IP; from
	// then on consecutive connections alternate between the two IPs.
	for i := 3; i < len(seen); i++ {
		if seen[i] == seen[i-1] {
			t.Fatalf("consecutive connections got the same IP: %v", seen)
		}
	}
}

func TestTunnelWithoutTrafficIsDropped(t *testing.T) {
	registry := testNodes(t, "JP", "JP")
	// 10.0.0.1 connects but its egress probe fails, as a dead node would.
	pool, network := newTestPool(t, registry, poolOptions{egress: map[string]string{"10.0.0.2": "198.51.100.2"}})
	if lease := acquire(t, pool, Request{Session: "a", TTL: time.Minute}); lease.NodeID != "10.0.0.2" {
		t.Fatalf("expected the node that carries traffic, got %s", lease.NodeID)
	}
	if !network.endpoint("10.0.0.1").isClosed() {
		t.Fatal("the silent tunnel was left open")
	}
	if !coolingDown(registry, "10.0.0.1") {
		t.Fatal("the silent node is not cooling down")
	}
}

var distinctEgress = map[string]string{"10.0.0.1": "198.51.100.1", "10.0.0.2": "198.51.100.2"}

func TestRecheckDropsATunnelThatStoppedForwarding(t *testing.T) {
	registry := testNodes(t, "JP", "JP")
	pool, network := newTestPool(t, registry, poolOptions{egress: distinctEgress})
	first := acquire(t, pool, Request{Session: "a", TTL: time.Minute})
	if !first.Recheck(context.Background()) {
		t.Fatal("a working tunnel failed its check")
	}
	network.kill(first.NodeID)
	if first.Recheck(context.Background()) {
		t.Fatal("a tunnel without traffic passed its check")
	}
	second := acquire(t, pool, Request{Session: "a", TTL: time.Minute})
	if second.NodeID == first.NodeID {
		t.Fatal("the session stayed on a dead tunnel")
	}
	eventually(t, "the dead tunnel to close", func() bool { return network.endpoint(first.NodeID).isClosed() })
	if !coolingDown(registry, first.NodeID) {
		t.Fatal("the dead node is not cooling down")
	}
}

func TestIdleSessionTunnelIsChecked(t *testing.T) {
	pool, network := newTestPool(t, testNodes(t, "JP", "JP"), poolOptions{egress: distinctEgress, health: time.Millisecond})
	lease, err := pool.Acquire(context.Background(), Request{Session: "a", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	network.kill(lease.NodeID)
	eventually(t, "the idle session tunnel to fail its check", func() bool { return network.endpoint(lease.NodeID).isClosed() })
	if again := acquire(t, pool, Request{Session: "a", TTL: time.Minute}); again.NodeID == lease.NodeID {
		t.Fatal("the session stayed on a dead tunnel")
	}
}
