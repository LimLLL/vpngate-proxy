package nodes

import (
	"path/filepath"
	"testing"
	"time"
)

func testRegistry(t *testing.T, path string) *Registry {
	t.Helper()
	registry, err := OpenRegistry(RegistryConfig{Path: path, MaxAge: 7 * 24 * time.Hour, MaxFailures: 3, Cooldown: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func node(id, country string, score int) Candidate {
	return Candidate{ID: id, IP: id, Country: country, Score: score, Profile: "profile-" + id}
}

func ids(picked []Node) []string {
	result := make([]string, len(picked))
	for i, node := range picked {
		result[i] = node.ID
	}
	return result
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
	if registry.Len() != 3 {
		t.Fatalf("absent node b should be kept, have %d nodes", registry.Len())
	}
	picked := registry.Pick(Filter{Country: "JP"}, start.Add(time.Hour))
	if !equal(ids(picked), []string{"a", "c"}) || picked[0].Profile != "new-profile" {
		t.Fatalf("unexpected JP pick: %+v", picked)
	}
	registry.Merge([]Candidate{node("c", "JP", 1)}, start.Add(8*24*time.Hour))
	if got := ids(registry.Pick(Filter{}, start.Add(8*24*time.Hour))); !equal(got, []string{"c"}) {
		t.Fatalf("nodes unseen for 8 days should be evicted, have %v", got)
	}
}

func TestRegistryOrdersListedThenRecentlySuccessful(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registry.Merge([]Candidate{node("old-ok", "JP", 1), node("old-never", "JP", 99)}, now)
	registry.ReportSuccess("old-ok", "", now)
	registry.Merge([]Candidate{node("low", "JP", 10), node("high", "JP", 20)}, now.Add(time.Minute))
	got := ids(registry.Pick(Filter{}, now.Add(time.Minute)))
	if want := []string{"high", "low", "old-ok", "old-never"}; !equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	got = ids(registry.Pick(Filter{Exclude: func(n Node) bool { return n.ID == "high" }}, now.Add(time.Minute)))
	if !equal(got, []string{"low", "old-ok", "old-never"}) {
		t.Fatalf("exclude ignored: %v", got)
	}
}

func TestRegistryCooldownAndFailureLimit(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registry.Merge([]Candidate{node("a", "JP", 1)}, now)
	registry.ReportFailure("a", now)
	if len(registry.Pick(Filter{}, now.Add(time.Minute))) != 0 {
		t.Fatal("a failed node must cool down")
	}
	if len(registry.Pick(Filter{}, now.Add(11*time.Minute))) != 1 {
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

func TestRegistryPrefersTheLeastRecentlyUsedEgress(t *testing.T) {
	registry := testRegistry(t, "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// a and b sit behind one NAT; c has not been measured yet.
	registry.Merge([]Candidate{node("a", "JP", 30), node("b", "JP", 20), node("c", "JP", 10), node("d", "JP", 5)}, now)
	registry.ReportSuccess("a", "198.51.100.1", now)
	registry.ReportSuccess("b", "198.51.100.1", now.Add(time.Minute))
	registry.ReportSuccess("d", "198.51.100.4", now.Add(2*time.Minute))
	if got, want := ids(registry.Pick(Filter{}, now.Add(time.Hour))), []string{"c", "a", "b", "d"}; !equal(got, want) {
		t.Fatalf("order %v, want %v: unknown egress first, then the IP unused longest", got, want)
	}
	registry.ReportUsed("198.51.100.1", now.Add(3*time.Minute))
	if got, want := ids(registry.Pick(Filter{}, now.Add(time.Hour))), []string{"c", "d", "a", "b"}; !equal(got, want) {
		t.Fatalf("order %v, want %v after the shared IP was used again", got, want)
	}
}

func TestRegistryPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registry := testRegistry(t, path)
	registry.Merge([]Candidate{node("a", "JP", 1), node("b", "US", 2), node("c", "US", 3)}, now)
	registry.ReportFailure("a", now)
	registry.ReportSuccess("b", "198.51.100.2", now)
	if err := registry.Save(); err != nil {
		t.Fatal(err)
	}
	reopened := testRegistry(t, path)
	if reopened.Len() != 3 {
		t.Fatalf("reopened registry has %d nodes", reopened.Len())
	}
	got := reopened.Pick(Filter{}, now.Add(time.Minute))
	if !equal(ids(got), []string{"c", "b"}) {
		t.Fatalf("cooldown or egress use was not persisted: %v", ids(got))
	}
	if got[1].Egress != "198.51.100.2" {
		t.Fatalf("egress was not persisted: %+v", got[1])
	}
}
