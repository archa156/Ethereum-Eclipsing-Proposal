// Package experiment implements the four experiments defined in the
// project methodology:
//
//  1. Reproduce the grind (SchemeBaseline only) -- confirm the attack works.
//  2. Three-scheme comparison at fixed attack parameters -- the headline
//     attacker-bench-share-over-time graph.
//  3. Attacker effort curves -- rounds needed to reach a target bench share,
//     swept across insertion rate, for each scheme.
//  4. Honest-node overhead -- how often a legitimate honest node fails to
//     get a bench slot under each scheme, with no attacker present at all.
package experiment

import (
	"math/rand"

	"benchgrind/attacker"
	"benchgrind/bench"
)

// Experiment1Row is one round of the baseline-only grind reproduction.
type Experiment1Row struct {
	Round              int
	AttackerBenchShare float64
	AttackerEntryShare float64
}

// Experiment1ReproduceGrind runs the unopposed baseline grind and returns
// its full trajectory, confirming the vulnerability described in the
// project brief: with no honest counter-pressure, an attacker with
// attackerSubnets distinct /24s eventually dominates the bench.
func Experiment1ReproduceGrind(attackerSubnets, insertionRate, rounds int, seed int64) []Experiment1Row {
	cfg := attacker.Config{
		AttackerSubnets: attackerSubnets,
		InsertionRate:   insertionRate,
		HonestChurnRate: 0,
		EntryDeathRate:  0.1,
		Rounds:          rounds,
		Scheme:          bench.SchemeBaseline,
		Seed:            seed,
	}
	results := attacker.Run(cfg)
	rows := make([]Experiment1Row, len(results))
	for i, r := range results {
		rows[i] = Experiment1Row{
			Round:              r.Round,
			AttackerBenchShare: r.AttackerBenchShare,
			AttackerEntryShare: r.AttackerEntryShare,
		}
	}
	return rows
}

// Experiment2Row is one round across all three schemes, for the headline
// comparison graph.
type Experiment2Row struct {
	Round                    int
	BaselineBenchShare       float64
	FractionSamplingBenchShare float64
	DeterministicBenchShare  float64
}

// Experiment2SchemeComparison runs all three schemes under IDENTICAL
// sustained conditions (with honest background churn) and returns the
// per-round trajectory of each. This is the single figure the project's
// methodology calls for.
func Experiment2SchemeComparison(attackerSubnets, insertionRate, honestChurnRate, rounds int,
	sampleP float64, secret uint64, seed int64) []Experiment2Row {

	mk := func(scheme bench.Scheme) attacker.Config {
		return attacker.Config{
			AttackerSubnets: attackerSubnets,
			InsertionRate:   insertionRate,
			HonestChurnRate: honestChurnRate,
			EntryDeathRate:  0.1,
			Rounds:          rounds,
			Scheme:          scheme,
			SampleP:         sampleP,
			Secret:          secret,
			Seed:            seed,
		}
	}
	baseline := attacker.Run(mk(bench.SchemeBaseline))
	sampling := attacker.Run(mk(bench.SchemeFractionSampling))
	deterministic := attacker.Run(mk(bench.SchemeDeterministic))

	rows := make([]Experiment2Row, rounds)
	for i := 0; i < rounds; i++ {
		rows[i] = Experiment2Row{
			Round:                      i,
			BaselineBenchShare:         baseline[i].AttackerBenchShare,
			FractionSamplingBenchShare: sampling[i].AttackerBenchShare,
			DeterministicBenchShare:    deterministic[i].AttackerBenchShare,
		}
	}
	return rows
}

// Experiment3Row is one (scheme, insertion rate) combination's cost to the
// attacker: how many rounds of grinding are needed to reach the target
// bench share, averaged over multiple seeds for stability. -1 means the
// target was never reached within the round budget.
type Experiment3Row struct {
	Scheme        string
	InsertionRate int
	AvgRounds     float64 // -1 if the target was never reached in any seed
	ReachedCount  int     // how many of the seeds reached the target at all
	Seeds         int
}

// Experiment3EffortCurves sweeps insertion rate for each scheme and
// measures the average rounds needed to reach targetShare, averaged over
// `seeds` random seeds per configuration. This is the attacker-effort cost
// curve central to the project's contribution claim.
func Experiment3EffortCurves(attackerSubnets int, insertionRates []int, targetShare float64,
	roundBudget, seeds int, sampleP float64, secret uint64) []Experiment3Row {

	schemes := []struct {
		name   string
		scheme bench.Scheme
	}{
		{"baseline", bench.SchemeBaseline},
		{"fraction_sampling", bench.SchemeFractionSampling},
		{"deterministic", bench.SchemeDeterministic},
	}

	var rows []Experiment3Row
	for _, sc := range schemes {
		for _, rate := range insertionRates {
			total := 0.0
			reached := 0
			for s := 0; s < seeds; s++ {
				cfg := attacker.Config{
					AttackerSubnets: attackerSubnets,
					InsertionRate:   rate,
					HonestChurnRate: 0, // unopposed, matching Experiment 1's clean cost measurement
					EntryDeathRate:  0.1,
					Rounds:          roundBudget,
					Scheme:          sc.scheme,
					SampleP:         sampleP,
					Secret:          secret,
					Seed:            int64(s * 7919), // arbitrary distinct seeds
				}
				r := attacker.RoundsToReachBenchShare(cfg, targetShare)
				if r > 0 {
					total += float64(r)
					reached++
				}
			}
			avg := -1.0
			if reached > 0 {
				avg = total / float64(reached)
			}
			rows = append(rows, Experiment3Row{
				Scheme:        sc.name,
				InsertionRate: rate,
				AvgRounds:     avg,
				ReachedCount:  reached,
				Seeds:         seeds,
			})
		}
	}
	return rows
}

// Experiment4Row reports, for one scheme, how often a purely honest node
// (no attacker present at all) fails to obtain a bench slot when the bench
// is already at capacity with other honest nodes -- the cost the defense
// imposes on legitimate traffic.
type Experiment4Row struct {
	Scheme          string
	Attempts        int
	Succeeded       int
	RejectionRate   float64 // fraction of honest attempts that failed to gain a slot
}

// Experiment4HonestOverhead simulates a bucket receiving ONLY honest
// replacement offers from honestSubnetPool distinct /24s, and measures
// what fraction fail to be admitted once the bench is at capacity, under
// each scheme. Under SchemeDeterministic this captures hash-slot
// collisions between distinct honest subnets; under SchemeBaseline and
// SchemeFractionSampling this captures ordinary eviction/rejection
// dynamics with no attacker involved.
func Experiment4HonestOverhead(honestSubnetPool, attempts int, sampleP float64, secret uint64, seed int64) []Experiment4Row {
	schemes := []struct {
		name   string
		scheme bench.Scheme
	}{
		{"baseline", bench.SchemeBaseline},
		{"fraction_sampling", bench.SchemeFractionSampling},
		{"deterministic", bench.SchemeDeterministic},
	}

	var rows []Experiment4Row
	for _, sc := range schemes {
		b := bench.NewBucket(sc.scheme, sampleP, secret, seed)
		// Fill the bench with an initial honest population first so
		// subsequent attempts are genuinely contending for occupied
		// capacity, not just filling empty slots for free.
		for i := 0; i < bench.MaxReplacements; i++ {
			b.AddReplacement(&bench.Node{ID: uint64(i), Subnet: honestLabel(i, honestSubnetPool)})
		}

		rng := rand.New(rand.NewSource(seed + 1))
		succeeded := 0
		for i := 0; i < attempts; i++ {
			id := uint64(1000 + i)
			subnet := honestLabel(rng.Intn(honestSubnetPool), honestSubnetPool)
			if b.AddReplacement(&bench.Node{ID: id, Subnet: subnet}) {
				succeeded++
			}
		}
		rows = append(rows, Experiment4Row{
			Scheme:        sc.name,
			Attempts:      attempts,
			Succeeded:     succeeded,
			RejectionRate: 1.0 - float64(succeeded)/float64(attempts),
		})
	}
	return rows
}

func honestLabel(i, pool int) string {
	return "honest-subnet-" + itoa(i%pool)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
