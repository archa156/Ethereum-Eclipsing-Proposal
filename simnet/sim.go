package simnet

import "math/rand"

// SimConfig parameterizes one simulation run.
type SimConfig struct {
	AttackerSubnets   int
	InsertRate        int
	Rounds            int
	HonestFailureRate float64 // per-check probability an honest node fails to respond
	FastCheckProb     float64 // per-round probability the fast revalidation queue is checked
	Seed              int64
}

// RoundResult captures bucket state after one round.
type RoundResult struct {
	Round              int
	AttackerBenchShare float64
	AttackerEntryShare float64
	EvictedThisRound   string // node ID evicted this round, "" if none
}

// RunSimulation wires everything together using the SAME architectural
// pattern as go-ethereum's own tests for this exact file
// (p2p/discover/table_util_test.go): a real (faithfully-ported) Table
// driven by a fake Transport, with event hooks for observability instead
// of polling.
func RunSimulation(cfg SimConfig) []RoundResult {
	rng := rand.New(rand.NewSource(cfg.Seed))
	tab := NewTable(cfg.Seed)
	b := NewBucket()
	transport := NewPingRecorder(cfg.HonestFailureRate, rng)
	reval := NewRevalidation(cfg.FastCheckProb, transport)

	// wire the hook: every node added to Entries gets tracked for
	// revalidation, mirroring table_reval.go:57-60 nodeAdded being called
	// from within handleAddNode's real call graph.
	tab.OnNodeAdded = func(n *Node) { reval.TrackNew(n) }
	tab.OnNodeRemoved = func(n *Node) { reval.Untrack(n) }

	// seed honest entries and bench before the attack starts
	seedHonest(tab, b, rng)

	attacker := NewAttacker(cfg.AttackerSubnets, cfg.InsertRate)

	results := make([]RoundResult, 0, cfg.Rounds)
	for round := 0; round < cfg.Rounds; round++ {
		attacker.Grind(tab, b, round, true /* table already initialised */)

		evicted := reval.Run(tab, b, rng)
		evictedID := ""
		if evicted != nil {
			evictedID = evicted.ID
		}

		results = append(results, RoundResult{
			Round:              round,
			AttackerBenchShare: attackerBenchShare(b),
			AttackerEntryShare: attackerEntryShare(b),
			EvictedThisRound:   evictedID,
		})
	}
	return results
}

func seedHonest(tab *Table, b *Bucket, rng *rand.Rand) {
	for i := 0; i < BucketSize; i++ {
		n := &Node{ID: "honest-entry-" + itoa(i), Subnet: "honest-subnet-" + itoa(i%8)}
		tab.HandleAddNode(b, n, false, true)
	}
	for i := 0; i < MaxReplacements; i++ {
		n := &Node{ID: "honest-bench-" + itoa(i), Subnet: "honest-bench-subnet-" + itoa(i%5)}
		tab.AddReplacement(b, n)
	}
}

func attackerBenchShare(b *Bucket) float64 {
	if len(b.Replacements) == 0 {
		return 0
	}
	c := 0
	for _, n := range b.Replacements {
		if n.IsAttacker {
			c++
		}
	}
	return float64(c) / float64(len(b.Replacements))
}

func attackerEntryShare(b *Bucket) float64 {
	if len(b.Entries) == 0 {
		return 0
	}
	c := 0
	for _, n := range b.Entries {
		if n.IsAttacker {
			c++
		}
	}
	return float64(c) / float64(len(b.Entries))
}
