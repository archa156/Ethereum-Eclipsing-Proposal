package attacker

import (
	"testing"

	"benchgrind/bench"
)

// unopposedConfig models the PDF's simplest narrative: an attacker grinds
// with no counteracting honest background traffic at all. This is the
// clean "worst case" demonstration that the baseline scheme is fully
// grindable.
func unopposedConfig(scheme bench.Scheme) Config {
	return Config{
		AttackerSubnets: 5,
		InsertionRate:   20,
		HonestChurnRate: 0,
		EntryDeathRate:  0.1,
		Rounds:          200,
		Scheme:          scheme,
		SampleP:         0.5,
		Secret:          20240711,
		Seed:            20240711,
	}
}

// sustainedConfig models a more realistic environment with ongoing honest
// background traffic. Under sustained churn, absolute attacker share is
// churn-rate-sensitive (discovered during development: even light honest
// churn meaningfully dilutes a naively-grinding attacker, because the /24
// subnet cap of 2 bottlenecks how fast the attacker can refill evicted
// slots). The robust, churn-insensitive claim is therefore RELATIVE:
// under IDENTICAL sustained conditions, baseline should still yield the
// attacker a higher share than fraction sampling, which in turn should
// yield a higher share than deterministic placement.
func sustainedConfig(scheme bench.Scheme) Config {
	return Config{
		AttackerSubnets: 5,
		InsertionRate:   20,
		HonestChurnRate: 2,
		EntryDeathRate:  0.1,
		Rounds:          300,
		Scheme:          scheme,
		SampleP:         0.5,
		Secret:          20240711,
		Seed:            20240711,
	}
}

func TestRunProducesOneResultPerRound(t *testing.T) {
	cfg := unopposedConfig(bench.SchemeBaseline)
	results := Run(cfg)
	if len(results) != cfg.Rounds {
		t.Fatalf("expected %d round results, got %d", cfg.Rounds, len(results))
	}
}

func TestBaselineUnopposedGrindReachesNearTotalTakeover(t *testing.T) {
	// With no honest counter-pressure at all, an attacker with 5 subnets
	// should be able to fully dominate the bench under today's geth logic --
	// this is the PDF's core claim, reproduced directly.
	cfg := unopposedConfig(bench.SchemeBaseline)
	results := Run(cfg)
	final := results[len(results)-1]
	if final.AttackerBenchShare < 0.9 {
		t.Fatalf("expected unopposed baseline grind to approach full bench takeover, got %.3f",
			final.AttackerBenchShare)
	}
}

func TestDeterministicUnopposedGrindStaysBounded(t *testing.T) {
	// Even with NO honest counter-pressure, deterministic placement should
	// still cap the attacker's achievable share via hash-slot coverage --
	// this is the headline difference from baseline.
	cfg := unopposedConfig(bench.SchemeDeterministic)
	results := Run(cfg)
	final := results[len(results)-1]
	if final.AttackerBenchShare >= 0.9 {
		t.Fatalf("expected deterministic scheme to cap attacker bench share even when unopposed, got %.3f",
			final.AttackerBenchShare)
	}
}

func TestDeterministicOutperformsBaselineUnderSustainedChurn(t *testing.T) {
	baselineFinal := Run(sustainedConfig(bench.SchemeBaseline))
	detFinal := Run(sustainedConfig(bench.SchemeDeterministic))
	bShare := baselineFinal[len(baselineFinal)-1].AttackerBenchShare
	dShare := detFinal[len(detFinal)-1].AttackerBenchShare
	if dShare >= bShare {
		t.Fatalf("expected deterministic placement's final attacker share (%.3f) to be lower than baseline's (%.3f) "+
			"under identical sustained-churn conditions", dShare, bShare)
	}
}

// avgFinalShare runs the same config across multiple seeds and averages the
// final attacker bench share. A single seed is noisy -- fraction sampling
// in particular throttles BOTH the attacker's insertions AND the honest
// churn's counter-insertions uniformly (the bucket cannot distinguish
// attacker from honest traffic at admission time), so its net effect on
// SHARE, as opposed to raw insertion counts, is a small, noisy edge over
// baseline rather than a large one -- averaging is needed to see it
// reliably. Deterministic placement's advantage, by contrast, comes from a
// structurally different mechanism (capping achievable hash-slot coverage)
// and is large and robust even at a single seed.
func avgFinalShare(scheme bench.Scheme, sampleP float64, seeds int) float64 {
	total := 0.0
	for s := 0; s < seeds; s++ {
		cfg := sustainedConfig(scheme)
		cfg.SampleP = sampleP
		cfg.Seed = int64(s * 1000)
		results := Run(cfg)
		total += results[len(results)-1].AttackerBenchShare
	}
	return total / float64(seeds)
}

func TestFractionSamplingIsIntermediateUnderSustainedChurn(t *testing.T) {
	const seeds = 30
	bShare := avgFinalShare(bench.SchemeBaseline, 1.0, seeds)
	sShare := avgFinalShare(bench.SchemeFractionSampling, 0.5, seeds)
	dShare := avgFinalShare(bench.SchemeDeterministic, 1.0, seeds)

	if !(dShare <= sShare && sShare <= bShare) {
		t.Fatalf("expected averaged ordering deterministic(%.3f) <= sampling(%.3f) <= baseline(%.3f) under identical churn",
			dShare, sShare, bShare)
	}
	// The deterministic-vs-baseline gap should be substantially larger than
	// the sampling-vs-baseline gap -- deterministic placement is a strong,
	// structural mitigation; fraction sampling is a weak, noisy one.
	detGap := bShare - dShare
	samplingGap := bShare - sShare
	if detGap <= samplingGap {
		t.Fatalf("expected deterministic placement's advantage over baseline (%.3f) to exceed "+
			"fraction sampling's (%.3f) -- deterministic works structurally, sampling only throttles rate",
			detGap, samplingGap)
	}
}

func TestRoundsToReachBenchShareIsMonotonicWithInsertionRate(t *testing.T) {
	// A faster-inserting attacker (baseline scheme, unopposed) should need
	// FEWER rounds to reach a given bench share than a slower one.
	slow := unopposedConfig(bench.SchemeBaseline)
	slow.InsertionRate = 2
	slow.Rounds = 2000

	fast := unopposedConfig(bench.SchemeBaseline)
	fast.InsertionRate = 20
	fast.Rounds = 2000

	roundsSlow := RoundsToReachBenchShare(slow, 0.9)
	roundsFast := RoundsToReachBenchShare(fast, 0.9)

	if roundsSlow < 0 || roundsFast < 0 {
		t.Fatalf("both configurations should reach 90%% share within the round budget; slow=%d fast=%d",
			roundsSlow, roundsFast)
	}
	if roundsFast >= roundsSlow {
		t.Fatalf("expected faster insertion rate to need fewer rounds: slow=%d (rate=%d) fast=%d (rate=%d)",
			roundsSlow, slow.InsertionRate, roundsFast, fast.InsertionRate)
	}
}

func TestReproducibleWithFixedSeed(t *testing.T) {
	cfg := unopposedConfig(bench.SchemeBaseline)
	r1 := Run(cfg)
	r2 := Run(cfg)
	if len(r1) != len(r2) {
		t.Fatalf("result lengths differ across identical-seed runs")
	}
	for i := range r1 {
		if r1[i].AttackerBenchShare != r2[i].AttackerBenchShare {
			t.Fatalf("round %d: non-reproducible result under fixed seed (%.6f vs %.6f)",
				i, r1[i].AttackerBenchShare, r2[i].AttackerBenchShare)
		}
	}
}
