// Package attacker implements the bench-grinding attack described in the
// project's threat-model brief: an adversary who owns AttackerSubnets
// distinct /24 subnets repeatedly offers contacts to the victim's bucket,
// exploiting front-insert/back-evict admission (SchemeBaseline) to push
// honest replacements out of the bench. Alongside it, a low-rate honest
// churn process inserts occasional honest replacements and kills occasional
// live entries, modelling natural peer turnover independent of the attack.
package attacker

import (
	"math/rand"

	"benchgrind/bench"
)

// Config parameterizes one attack run.
type Config struct {
	AttackerSubnets  int     // number of distinct /24 subnets the attacker controls
	InsertionRate    int     // attacker insertion attempts per round
	HonestChurnRate  int     // honest replacement-insertion attempts per round (natural background traffic)
	EntryDeathRate   float64 // probability, per round, that ONE live entry dies and triggers a promotion
	Rounds           int     // number of rounds to simulate
	Scheme           bench.Scheme
	SampleP          float64 // used only by SchemeFractionSampling
	Secret           uint64  // used only by SchemeDeterministic
	Seed             int64
}

// RoundResult captures the bucket's state after one round, for building the
// attacker-bench-share-over-time curves (Experiments 1-3).
type RoundResult struct {
	Round             int
	AttackerBenchShare float64
	AttackerEntryShare float64
	BenchOccupancy    int
}

// Run simulates Config.Rounds rounds of a bench-grinding attack against an
// initially honest, fully populated bucket (16 live entries, 10 replacement
// slots), interleaved with background honest churn, and returns the
// per-round trajectory of attacker occupancy.
func Run(cfg Config) []RoundResult {
	b := bench.NewBucket(cfg.Scheme, cfg.SampleP, cfg.Secret, cfg.Seed)
	rng := rand.New(rand.NewSource(cfg.Seed))

	// Seed 16 honest live entries and, separately, fill the bench with
	// honest replacements first so the attack starts against an
	// established, fully-honest bucket -- the realistic scenario.
	honestSubnetPool := 40 // enough distinct honest /24s to avoid IP-limit friction
	nextID := uint64(1)
	for i := 0; i < bench.BucketSize; i++ {
		b.AddEntry(&bench.Node{ID: nextID, Subnet: honestSubnet(i, honestSubnetPool)})
		nextID++
	}
	for i := 0; i < bench.MaxReplacements; i++ {
		b.AddReplacement(&bench.Node{ID: nextID, Subnet: honestSubnet(i+bench.BucketSize, honestSubnetPool)})
		nextID++
	}

	nextAttackerID := uint64(1_000_000)
	nextHonestID := uint64(2_000_000)

	results := make([]RoundResult, 0, cfg.Rounds)
	for round := 0; round < cfg.Rounds; round++ {
		// Attacker insertion attempts this round, cycling through subnets so
		// each attacker /24 stays within BucketIPLimit at any instant --
		// mirrors an attacker deliberately respecting the subnet cap to
		// remain admissible rather than wasting attempts that get rejected.
		for i := 0; i < cfg.InsertionRate; i++ {
			s := i % cfg.AttackerSubnets
			b.AddReplacement(&bench.Node{
				ID:         nextAttackerID,
				Subnet:     attackerSubnet(s),
				IsAttacker: true,
			})
			nextAttackerID++
		}

		// Background honest churn: occasional honest nodes are also offered
		// to the bench, exactly as would happen from normal network activity.
		for i := 0; i < cfg.HonestChurnRate; i++ {
			b.AddReplacement(&bench.Node{
				ID:     nextHonestID,
				Subnet: honestSubnet(rng.Intn(honestSubnetPool), honestSubnetPool),
			})
			nextHonestID++
		}

		// Natural entry death: with probability EntryDeathRate, one live
		// entry dies and the bench's promotion rule (uniformly random,
		// matching real geth) fills the gap.
		if len(b.Entries) > 0 && rng.Float64() < cfg.EntryDeathRate {
			b.KillRandomEntry()
		}

		results = append(results, RoundResult{
			Round:              round,
			AttackerBenchShare: b.AttackerBenchShare(),
			AttackerEntryShare: b.AttackerEntryShare(),
			BenchOccupancy:     len(b.LiveReplacements()),
		})
	}
	return results
}

// RoundsToReachBenchShare runs the same attack but stops as soon as the
// attacker's bench share first reaches target, returning the round index
// (1-indexed insertion-round count) at which that happened, or -1 if the
// target was never reached within cfg.Rounds. This is the primary metric
// for Experiment 3's attacker-effort curves.
func RoundsToReachBenchShare(cfg Config, target float64) int {
	results := Run(cfg)
	for _, r := range results {
		if r.AttackerBenchShare >= target {
			return r.Round + 1
		}
	}
	return -1
}

func attackerSubnet(i int) string {
	return "attacker-subnet-" + itoa(i)
}

func honestSubnet(i, pool int) string {
	return "honest-subnet-" + itoa(i%pool)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
