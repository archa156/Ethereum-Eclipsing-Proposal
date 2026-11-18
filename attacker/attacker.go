package attacker

import (
	"math/rand"

	"benchgrind/bench"
)

type Config struct {
	AttackerSubnets int
	InsertionRate   int
	HonestChurnRate int
	EntryDeathRate  float64
	Rounds          int
	Scheme          bench.Scheme
	SampleP         float64
	Secret          uint64
	Seed            int64
}

type RoundResult struct {
	Round              int
	AttackerBenchShare float64
	AttackerEntryShare float64
	BenchOccupancy     int
}

func Run(cfg Config) []RoundResult {
	b := bench.NewBucket(cfg.Scheme, cfg.SampleP, cfg.Secret, cfg.Seed)
	rng := rand.New(rand.NewSource(cfg.Seed))

	honestSubnetPool := 40
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
		for i := 0; i < cfg.InsertionRate; i++ {
			s := i % cfg.AttackerSubnets
			b.AddReplacement(&bench.Node{
				ID:         nextAttackerID,
				Subnet:     attackerSubnet(s),
				IsAttacker: true,
			})
			nextAttackerID++
		}

		for i := 0; i < cfg.HonestChurnRate; i++ {
			b.AddReplacement(&bench.Node{
				ID:     nextHonestID,
				Subnet: honestSubnet(rng.Intn(honestSubnetPool), honestSubnetPool),
			})
			nextHonestID++
		}

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
