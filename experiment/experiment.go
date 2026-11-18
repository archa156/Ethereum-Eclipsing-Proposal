package experiment

import (
	"math/rand"

	"benchgrind/attacker"
	"benchgrind/bench"
)

type Experiment1Row struct {
	Round              int
	AttackerBenchShare float64
	AttackerEntryShare float64
}

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

type Experiment2Row struct {
	Round                      int
	BaselineBenchShare         float64
	FractionSamplingBenchShare float64
	DeterministicBenchShare    float64
}

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

type Experiment3Row struct {
	Scheme        string
	InsertionRate int
	AvgRounds     float64
	ReachedCount  int
	Seeds         int
}

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
					HonestChurnRate: 0,
					EntryDeathRate:  0.1,
					Rounds:          roundBudget,
					Scheme:          sc.scheme,
					SampleP:         sampleP,
					Secret:          secret,
					Seed:            int64(s * 7919),
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

type Experiment4Row struct {
	Scheme        string
	Attempts      int
	Succeeded     int
	RejectionRate float64
}

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
