package simnet

import (
	"math/rand"
	"testing"
)

func TestUnopposedGrindTakesOverBench(t *testing.T) {
	cfg := SimConfig{
		AttackerSubnets:   5,
		InsertRate:        20,
		Rounds:            200,
		HonestFailureRate: 0, // honest nodes never fail -- isolates the bench admission attack alone
		FastCheckProb:     0.1,
		Seed:              20240711,
	}
	results := RunSimulation(cfg)
	final := results[len(results)-1]
	if final.AttackerBenchShare < 0.99 {
		t.Fatalf("expected bench fully grindable, got share=%.3f", final.AttackerBenchShare)
	}
}

func TestEntriesAreStickierThanBenchDueToLivenessChecks(t *testing.T) {
	// With realistic honest churn (HonestFailureRate > 0) but the
	// livenessChecks decay protecting established entries, entry share
	// should grow MUCH more slowly than bench share -- entries should
	// remain mostly honest for many rounds even though the bench is
	// immediately fully compromised.
	cfg := SimConfig{
		AttackerSubnets:   5,
		InsertRate:        20,
		Rounds:            50,
		HonestFailureRate: 0.3, // realistic churn
		FastCheckProb:     0.3,
		Seed:              20240711,
	}
	results := RunSimulation(cfg)
	final := results[len(results)-1]

	if final.AttackerBenchShare < 0.9 {
		t.Fatalf("expected bench still fully grindable under churn, got %.3f", final.AttackerBenchShare)
	}
	if final.AttackerEntryShare >= final.AttackerBenchShare {
		t.Fatalf("expected entry share (%.3f) to lag well behind bench share (%.3f) "+
			"due to the livenessChecks resilience mechanism",
			final.AttackerEntryShare, final.AttackerBenchShare)
	}
}

func TestLivenessChecksDecayNotInstantEviction(t *testing.T) {
	// A single failed ping should NOT evict an established node --
	// table_reval.go:161 divides by 3, it doesn't zero out.
	tab := NewTable(1)
	b := NewBucket()
	transport := NewPingRecorder(1.0, rand.New(rand.NewSource(1))) // ALWAYS fails
	reval := NewRevalidation(1.0, transport)                       // ALWAYS checks

	n := &Node{ID: "established", Subnet: "s1"}
	tab.HandleAddNode(b, n, false, true) // fresh admission resets LivenessChecks to 0 -- correct, matches real geth
	reval.TrackNew(n)
	n.LivenessChecks = 10 // simulate many prior successful checks, AFTER admission

	rng := rand.New(rand.NewSource(2))
	evicted := reval.Run(tab, b, rng)

	if evicted != nil {
		t.Fatalf("expected established node (livenessChecks=10) to survive one failed ping, but it was evicted")
	}
	if n.LivenessChecks != 3 { // 10 / 3 = 3 (integer division)
		t.Fatalf("expected livenessChecks to decay via /3 to 3, got %d", n.LivenessChecks)
	}
}

func TestLivenessChecksEventuallyReachesZeroAndEvicts(t *testing.T) {
	tab := NewTable(1)
	b := NewBucket()
	transport := NewPingRecorder(1.0, rand.New(rand.NewSource(1))) // ALWAYS fails
	reval := NewRevalidation(1.0, transport)

	n := &Node{ID: "doomed", Subnet: "s1", LivenessChecks: 1}
	tab.HandleAddNode(b, n, false, true)
	reval.TrackNew(n)

	// seed one replacement so there's something to promote
	tab.AddReplacement(b, &Node{ID: "backup", Subnet: "s2"})

	rng := rand.New(rand.NewSource(2))
	evicted := reval.Run(tab, b, rng)

	if evicted == nil || evicted.ID != "doomed" {
		t.Fatalf("expected node with livenessChecks=1 to be evicted on first failure (1/3=0), got %v", evicted)
	}
	if !containsID(b.Entries, "backup") {
		t.Fatalf("expected the backup replacement to be promoted into entries")
	}
}

func TestSuccessfulPingIncrementsLivenessAndGraduatesToSlowList(t *testing.T) {
	tab := NewTable(1)
	b := NewBucket()
	transport := NewPingRecorder(0.0, rand.New(rand.NewSource(1))) // ALWAYS succeeds
	reval := NewRevalidation(1.0, transport)

	n := &Node{ID: "healthy", Subnet: "s1"}
	tab.HandleAddNode(b, n, false, true)
	reval.TrackNew(n)

	if !n.InFastList {
		t.Fatalf("expected new node to start in the fast list")
	}

	rng := rand.New(rand.NewSource(2))
	reval.Run(tab, b, rng)

	if n.LivenessChecks != 1 {
		t.Fatalf("expected livenessChecks to increment to 1, got %d", n.LivenessChecks)
	}
	if !n.InSlowList || n.InFastList {
		t.Fatalf("expected node to graduate to the slow list after a successful check")
	}
}

func TestAttackerNodesNeverFailPingsOnceEstablished(t *testing.T) {
	// Once promoted into entries, an attacker node should behave EXACTLY
	// like a legitimate long-lived peer for revalidation purposes --
	// always responding, building up livenessChecks, and graduating to
	// the slow list. This is deliberate: it demonstrates that the SAME
	// protection mechanism that makes honest entries hard to attack
	// equally protects an attacker's node once it gets in.
	tab := NewTable(1)
	b := NewBucket()
	transport := NewPingRecorder(0.5, rand.New(rand.NewSource(1)))
	reval := NewRevalidation(1.0, transport)

	n := &Node{ID: "atk-established", Subnet: "s1", IsAttacker: true}
	tab.HandleAddNode(b, n, false, true)
	reval.TrackNew(n)

	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 10; i++ {
		reval.Run(tab, b, rng)
	}

	if !containsID(b.Entries, "atk-established") {
		t.Fatalf("expected attacker node to survive 10 revalidation rounds (it never fails a ping)")
	}
	if n.LivenessChecks == 0 {
		t.Fatalf("expected attacker node's livenessChecks to have grown, got %d", n.LivenessChecks)
	}
}

func TestBudgetAttackerCappedBySubnetCount(t *testing.T) {
	// 3 subnets * BucketIPLimit(2) = 6 of 10 bench slots -- attacker
	// cannot exceed this regardless of insertion rate, matching the
	// project's earlier finding that the /24 limit alone bounds bench
	// composition.
	cfg := SimConfig{
		AttackerSubnets:   3,
		InsertRate:        50,
		Rounds:            50,
		HonestFailureRate: 0,
		FastCheckProb:     0.1,
		Seed:              20240711,
	}
	results := RunSimulation(cfg)
	final := results[len(results)-1]
	expected := 0.6 // 6/10
	if final.AttackerBenchShare < expected-0.01 || final.AttackerBenchShare > expected+0.01 {
		t.Fatalf("expected attacker bench share pinned at %.2f (3 subnets * 2), got %.3f",
			expected, final.AttackerBenchShare)
	}
}

func TestReproducibleWithFixedSeed(t *testing.T) {
	cfg := SimConfig{
		AttackerSubnets:   5,
		InsertRate:        20,
		Rounds:            100,
		HonestFailureRate: 0.2,
		FastCheckProb:     0.2,
		Seed:              20240711,
	}
	r1 := RunSimulation(cfg)
	r2 := RunSimulation(cfg)
	for i := range r1 {
		if r1[i].AttackerBenchShare != r2[i].AttackerBenchShare {
			t.Fatalf("round %d: non-reproducible (%.6f vs %.6f)",
				i, r1[i].AttackerBenchShare, r2[i].AttackerBenchShare)
		}
	}
}
