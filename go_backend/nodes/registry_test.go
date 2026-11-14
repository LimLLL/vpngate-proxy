package nodes

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testRegistry(t *testing.T, path string) *Registry {
	t.Helper()
	registry, err := OpenRegistry(RegistryConfig{Path: path, MaxAge: 7 * 24 * time.Hour, MaxFailures: 3,
		Cooldown: 10 * time.Minute, Unreachable: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// merge adds a listing whose nodes all answered a liveness check.
func merge(registry *Registry, now time.Time, listing ...Candidate) {
	registry.Merge(listing, now)
	for _, candidate := range listing {
		registry.ReportProbe(candidate.ID, true, now)
	}
}

func node(id, country string, score int) Candidate {
	return Candidate{ID: id, IP: id, Country: country, Score: score, Profile: "profile-" + id}
}

// picks calls Next until nothing is left, never returning a node twice.
func picks(registry *Registry, filter Filter, now time.Time) []string {
	var order []string
	taken := make(map[string]bool)
	exclude := filter.Exclude
	filter.Exclude = func(n Node) bool { return taken[n.ID] || exclude != nil && exclude(n) }
	for {
		next, ok := registry.Next(filter, now)
		if !ok {
			return order
		}
		taken[next.ID] = true
		order = append(order, next.ID)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRegistryAccumulatesAndEvictsByAge(t *testing.T) {
	registry := testRegistry(t, "")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if added, _ := registry.Merge([]Candidate{node("a", "JP", 1), node("b", "US", 1)}, start); added != 2 {
		t.Fatalf("added %d, want 2", added)
	}
	updated := node("a", "JP", 9)
	updated.Profile = "new-profile"
	if added, _ := registry.Merge([]Candidate{updated, node("c", "JP", 1)}, start.Add(time.Hour)); added != 1 {
		t.Fatalf("added %d, want 1", added)
	}
	for _, id := range []string{"a", "b", "c"} {
		registry.ReportProbe(id, true, start.Add(time.Hour))
	}
	if registry.Len() != 3 {
		t.Fatalf("absent node b should be kept, have %d nodes", registry.Len())
	}
	if got := picks(registry, Filter{Country: "JP"}, start.Add(time.Hour)); !equal(got, []string{"a", "c"}) {
		t.Fatalf("unexpected JP picks: %v", got)
	}
	if a, _ := registry.Get("a"); a.Profile != "new-profile" {
		t.Fatalf("the listing did not refresh the profile: %q", a.Profile)
	}
	registry.Merge([]Candidate{node("c", "JP", 1)}, start.Add(8*24*time.Hour))
	if _, ok := registry.Get("b"); ok || registry.Len() != 1 {
		t.Fatalf("nodes unseen for 8 days should be evicted, have %d", registry.Len())
	}
}

func TestRegistryPrefersScoreThenRecentSuccess(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	merge(registry, now, node("low", "JP", 10), node("high", "JP", 20), node("low-ok", "JP", 10))
	registry.ReportSuccess("low-ok", "", now)
	// Every node is its own network here, so the order is the fallback one.
	if got, want := picks(registry, Filter{}, now.Add(time.Minute)), []string{"high", "low-ok", "low"}; !equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	excluded := picks(registry, Filter{Exclude: func(n Node) bool { return n.ID == "high" }}, now.Add(time.Minute))
	if len(excluded) != 2 || excluded[0] == "high" || excluded[1] == "high" {
		t.Fatalf("exclude ignored: %v", excluded)
	}
}

func TestRegistryPicksOnlyNodesThatAnswered(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registry.Merge([]Candidate{node("up", "JP", 1), node("new", "JP", 99), node("down", "JP", 50)}, now)
	registry.ReportProbe("up", true, now)
	registry.ReportProbe("down", false, now)
	if got := picks(registry, Filter{}, now); !equal(got, []string{"up"}) {
		t.Fatalf("picked %v; unchecked and unreachable nodes must wait", got)
	}
	registry.ReportProbe("up", false, now.Add(time.Hour))
	if _, ok := registry.Next(Filter{}, now.Add(time.Hour)); ok {
		t.Fatal("a node that stopped answering was still picked")
	}
	// Silent for over a day since it last answered, or since it was listed.
	registry.ReportProbe("up", false, now.Add(25*time.Hour))
	registry.ReportProbe("down", false, now.Add(25*time.Hour))
	if _, ok := registry.Get("up"); ok || registry.Len() != 1 {
		t.Fatalf("long unreachable nodes should be dropped, %d left", registry.Len())
	}
}

func TestRegistryProbe(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Now()
	registry.Merge([]Candidate{node("a", "JP", 1), node("b", "JP", 1), node("c", "JP", 1)}, now)
	check := func(_ context.Context, candidate Candidate) error {
		if candidate.ID == "b" {
			return errors.New("no answer")
		}
		return nil
	}
	if alive, total := registry.Probe(context.Background(), check, false, 2); alive != 2 || total != 3 {
		t.Fatalf("probe found %d of %d alive, want 2 of 3", alive, total)
	}
	if b, _ := registry.Get("b"); b.Reachable || b.ProbedAt.IsZero() {
		t.Fatalf("b's failed check was not recorded: %+v", b)
	}
	registry.Merge([]Candidate{node("d", "JP", 1)}, now)
	if _, total := registry.Probe(context.Background(), check, true, 2); total != 1 {
		t.Fatalf("checking new nodes covered %d, want only d", total)
	}
}

func TestRegistryRotatesAcrossNetworks(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Two academic servers behind one NAT outscore two home nodes.
	merge(registry, now,
		node("219.100.37.1", "JP", 100), node("219.100.37.2", "JP", 90),
		node("106.168.67.207", "JP", 50), node("118.104.101.56", "JP", 40))
	egress := map[string]string{
		"219.100.37.1": "219.100.37.240", "219.100.37.2": "219.100.37.245",
		"106.168.67.207": "106.168.67.207", "118.104.101.56": "118.104.101.56",
	}
	var order []string
	for i := 0; i < 4; i++ {
		now = now.Add(time.Minute)
		next, ok := registry.Next(Filter{}, now)
		if !ok {
			t.Fatal("ran out of nodes")
		}
		order = append(order, next.ID)
		registry.ReportSuccess(next.ID, egress[next.ID], now)
	}
	// The second academic server is unmeasured, but shares the first one's
	// /24, so it waits until the other networks had their turn.
	if want := []string{"219.100.37.1", "106.168.67.207", "118.104.101.56", "219.100.37.2"}; !equal(order, want) {
		t.Fatalf("order %v, want %v", order, want)
	}
}

func TestRegistryMovesToAnotherNetworkAfterAFailure(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	merge(registry, now, node("219.100.37.1", "JP", 100), node("219.100.37.2", "JP", 90), node("106.168.67.207", "JP", 50))
	first, _ := registry.Next(Filter{}, now)
	registry.ReportFailure(first.ID, now)
	// A full academic server says nothing good about its busy neighbours.
	if second, _ := registry.Next(Filter{}, now.Add(time.Second)); second.ID != "106.168.67.207" {
		t.Fatalf("after %s failed the next pick was %s, from the same network", first.ID, second.ID)
	}
}

func TestRegistryCooldownAndFailureLimit(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	merge(registry, now, node("a", "JP", 1))
	registry.ReportFailure("a", now)
	if _, ok := registry.Next(Filter{}, now.Add(time.Minute)); ok {
		t.Fatal("a failed node must cool down")
	}
	if _, ok := registry.Next(Filter{}, now.Add(11*time.Minute)); !ok {
		t.Fatal("the node should return after its cooldown")
	}
	registry.ReportSuccess("a", "", now)
	registry.ReportFailure("a", now)
	registry.ReportFailure("a", now)
	if registry.Len() != 1 {
		t.Fatal("a success must reset the consecutive failure count")
	}
	registry.ReportFailure("a", now)
	if registry.Len() != 0 {
		t.Fatal("three consecutive failures should drop the node")
	}
}

func TestRegistryPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registry := testRegistry(t, path)
	merge(registry, now, node("a", "JP", 1), node("198.51.100.2", "US", 3), node("203.0.113.3", "US", 2))
	registry.ReportFailure("a", now)
	registry.ReportSuccess("198.51.100.2", "198.51.100.2", now)
	if err := registry.Save(); err != nil {
		t.Fatal(err)
	}
	reopened := testRegistry(t, path)
	if reopened.Len() != 3 {
		t.Fatalf("reopened registry has %d nodes", reopened.Len())
	}
	if got, _ := reopened.Get("198.51.100.2"); got.Egress != "198.51.100.2" {
		t.Fatalf("egress was not persisted: %+v", got)
	}
	// a is still cooling down, and the higher scored node's network was just
	// used, so the other one comes first.
	if got, want := picks(reopened, Filter{}, now.Add(time.Minute)), []string{"203.0.113.3", "198.51.100.2"}; !equal(got, want) {
		t.Fatalf("order %v, want %v: cooldown or usage was not persisted", got, want)
	}
}
