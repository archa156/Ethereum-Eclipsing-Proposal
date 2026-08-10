package bench

import "testing"

func newTestBucket(scheme Scheme, sampleP float64, secret uint64) *Bucket {
	return NewBucket(scheme, sampleP, secret, 20240711)
}

// --- capacity and dedup -----------------------------------------------------

func TestReplacementListNeverExceedsMaxReplacements(t *testing.T) {
	b := newTestBucket(SchemeBaseline, 1.0, 0)
	for i := 0; i < 50; i++ {
		b.AddReplacement(&Node{ID: uint64(i), Subnet: subnetFor(i, 25)}) // 25 distinct subnets, well above IP limit needs
	}
	if got := len(b.LiveReplacements()); got > MaxReplacements {
		t.Fatalf("replacement list exceeded MaxReplacements: got %d", got)
	}
}

func TestDuplicateNodeIsNotDoubleCounted(t *testing.T) {
	b := newTestBucket(SchemeBaseline, 1.0, 0)
	n := &Node{ID: 1, Subnet: "10.0.0"}
	b.AddReplacement(n)
	b.AddReplacement(n) // same ID again
	if got := len(b.LiveReplacements()); got != 1 {
		t.Fatalf("expected 1 entry after duplicate insert, got %d", got)
	}
}

// --- subnet / IP limit (the only defense geth has today) -------------------

func TestBucketIPLimitAppliesUnderEveryScheme(t *testing.T) {
	// Checks CONCURRENT occupancy from one subnet, not cumulative accept
	// count -- under SchemeDeterministic a subnet always hashes to the same
	// slot, so successive distinct-ID insertions from that subnet displace
	// each other rather than accumulating; each call can still return true
	// while never holding more than 1 slot at once. Live occupancy is the
	// metric that actually matters for "is the subnet limit respected".
	for _, scheme := range []Scheme{SchemeBaseline, SchemeFractionSampling, SchemeDeterministic} {
		b := newTestBucket(scheme, 1.0, 42)
		for i := 0; i < 10; i++ {
			n := &Node{ID: uint64(i), Subnet: "10.0.0"} // ALL same /24 subnet
			b.AddReplacement(n)
		}
		fromSubnet := 0
		for _, n := range b.LiveReplacements() {
			if n.Subnet == "10.0.0" {
				fromSubnet++
			}
		}
		if fromSubnet > BucketIPLimit {
			t.Fatalf("scheme %s: subnet limit violated, %d concurrently resident from one subnet (limit %d)",
				scheme, fromSubnet, BucketIPLimit)
		}
	}
}

// --- Scheme 1: baseline, today's geth ---------------------------------------

func TestBaselineFrontInsertBackEvict(t *testing.T) {
	b := newTestBucket(SchemeBaseline, 1.0, 0)
	// fill the bench with 10 distinct-subnet honest nodes
	var honest []*Node
	for i := 0; i < MaxReplacements; i++ {
		n := &Node{ID: uint64(i), Subnet: subnetFor(i, MaxReplacements)}
		honest = append(honest, n)
		b.AddReplacement(n)
	}
	// insert one more node from a fresh subnet -- should evict the OLDEST
	// (which pushNode's front-insert/back-evict makes the FIRST one we added)
	newcomer := &Node{ID: 999, Subnet: subnetFor(999, MaxReplacements+1)}
	b.AddReplacement(newcomer)

	live := b.LiveReplacements()
	if len(live) != MaxReplacements {
		t.Fatalf("expected bench to stay at %d, got %d", MaxReplacements, len(live))
	}
	for _, n := range live {
		if n.ID == honest[0].ID {
			t.Fatalf("oldest honest node should have been evicted from the back, but is still present")
		}
	}
	if live[0].ID != newcomer.ID {
		t.Fatalf("newcomer should be at the front (slot 0), found %d instead", live[0].ID)
	}
}

func TestBaselineGrindEventuallyOwnsWholeBench(t *testing.T) {
	// This test reproduces the core vulnerability: an attacker with enough
	// distinct subnets (5, given BucketIPLimit=2) can, by repeated
	// insertion alone, come to occupy the entire bench under SchemeBaseline.
	b := newTestBucket(SchemeBaseline, 1.0, 0)
	for i := 0; i < MaxReplacements; i++ {
		b.AddReplacement(&Node{ID: uint64(i), Subnet: subnetFor(i, MaxReplacements)})
	}
	attackerSubnets := 5 // 5 subnets * BucketIPLimit(2) = 10 = MaxReplacements
	for round := 0; round < 200; round++ {
		for s := 0; s < attackerSubnets; s++ {
			for slot := 0; slot < BucketIPLimit; slot++ {
				id := uint64(100000 + round*attackerSubnets*BucketIPLimit + s*BucketIPLimit + slot)
				b.AddReplacement(&Node{ID: id, Subnet: subnetFor(s, attackerSubnets), IsAttacker: true})
			}
		}
	}
	share := b.AttackerBenchShare()
	if share < 0.99 {
		t.Fatalf("expected baseline scheme to be fully grindable (share ~1.0), got %.3f", share)
	}
}

// --- Scheme 2: fraction sampling ---------------------------------------------

func TestFractionSamplingSlowsButDoesNotStopTheGrind(t *testing.T) {
	baseline := newTestBucket(SchemeBaseline, 1.0, 0)
	sampled := newTestBucket(SchemeFractionSampling, 0.5, 0)

	attackerSubnets := 5
	rounds := 400
	insertRound := func(b *Bucket, round int) {
		for s := 0; s < attackerSubnets; s++ {
			for slot := 0; slot < BucketIPLimit; slot++ {
				id := uint64(100000 + round*attackerSubnets*BucketIPLimit + s*BucketIPLimit + slot)
				b.AddReplacement(&Node{ID: id, Subnet: subnetFor(s, attackerSubnets), IsAttacker: true})
			}
		}
	}
	for r := 0; r < rounds; r++ {
		insertRound(baseline, r)
		insertRound(sampled, r)
	}
	// both should still converge toward full attacker occupancy given enough
	// rounds -- sampling only raises the number of insertions needed, it does
	// not cap the attacker's achievable share.
	if baseline.AttackerBenchShare() < 0.99 {
		t.Fatalf("baseline sanity check failed: expected ~1.0, got %.3f", baseline.AttackerBenchShare())
	}
	if sampled.AttackerBenchShare() < 0.99 {
		t.Fatalf("fraction sampling should still be beaten given enough insertions, got %.3f",
			sampled.AttackerBenchShare())
	}
}

func TestFractionSamplingNeedsMoreInsertionsThanBaselineForSameShare(t *testing.T) {
	attackerSubnets := 5
	insertRound := func(b *Bucket, round int) {
		for s := 0; s < attackerSubnets; s++ {
			for slot := 0; slot < BucketIPLimit; slot++ {
				id := uint64(100000 + round*attackerSubnets*BucketIPLimit + s*BucketIPLimit + slot)
				b.AddReplacement(&Node{ID: id, Subnet: subnetFor(s, attackerSubnets), IsAttacker: true})
			}
		}
	}
	roundsToReachShare := func(scheme Scheme, sampleP float64, target float64) int {
		b := newTestBucket(scheme, sampleP, 0)
		// Seed an ESTABLISHED HONEST bench first -- the realistic scenario
		// is an attacker grinding against an already-full, already-honest
		// replacement list, not an empty one. Without this, even a single
		// accepted attacker insertion trivially reads as 100% share.
		for i := 0; i < MaxReplacements; i++ {
			b.AddReplacement(&Node{ID: uint64(900000 + i), Subnet: subnetFor(i, MaxReplacements)})
		}
		for r := 0; r < 5000; r++ {
			insertRound(b, r)
			if b.AttackerBenchShare() >= target {
				return r + 1
			}
		}
		return -1
	}
	roundsBaseline := roundsToReachShare(SchemeBaseline, 1.0, 0.9)
	roundsSampled := roundsToReachShare(SchemeFractionSampling, 0.3, 0.9)
	if roundsBaseline < 0 || roundsSampled < 0 {
		t.Fatalf("both schemes should eventually reach 90%% share; baseline=%d sampled=%d",
			roundsBaseline, roundsSampled)
	}
	if roundsSampled <= roundsBaseline {
		t.Fatalf("expected fraction sampling (P=0.3) to need MORE rounds than baseline to reach 90%%: baseline=%d sampled=%d",
			roundsBaseline, roundsSampled)
	}
}

// --- Scheme 3: deterministic placement ---------------------------------------

func TestDeterministicGrindingIsANoOp(t *testing.T) {
	b := newTestBucket(SchemeDeterministic, 1.0, 20240711)
	n := &Node{ID: 1, Subnet: "10.0.0", IsAttacker: true}
	first := b.AddReplacement(n)
	if !first {
		t.Fatalf("first insertion should succeed")
	}
	slotAfterFirst := findSlot(b, n.ID)
	for i := 0; i < 1000; i++ {
		b.AddReplacement(n) // insert the SAME node 1000 more times
	}
	if got := len(b.LiveReplacements()); got != 1 {
		t.Fatalf("grinding the same node 1000 times should not grow the bench, got %d entries", got)
	}
	if findSlot(b, n.ID) != slotAfterFirst {
		t.Fatalf("node's slot changed after repeated insertion -- should be stable")
	}
}

func TestDeterministicAttackerCappedByHashSlotShare(t *testing.T) {
	// With deterministic placement, an attacker with K distinct subnets can
	// occupy AT MOST the number of DISTINCT hash slots those K subnets map
	// to under this bucket's secret -- this can be LESS than K if two
	// attacker subnets happen to collide into the same slot, so the correct
	// invariant to test is against the actual distinct-slot count for this
	// secret, not a naive K/MaxReplacements ratio (which wrongly assumes
	// honest seeding perfectly fills all 10 slots -- honest subnets can
	// also collide with each other, leaving some slots empty even before
	// any attacker activity).
	const secret = 20240711
	b := newTestBucket(SchemeDeterministic, 1.0, secret)
	for i := 0; i < MaxReplacements; i++ {
		b.AddReplacement(&Node{ID: uint64(900000 + i), Subnet: subnetFor(i, MaxReplacements)})
	}
	attackerSubnets := 5
	for round := 0; round < 500; round++ { // grind hard
		for s := 0; s < attackerSubnets; s++ {
			id := uint64(1000 + round*attackerSubnets + s)
			b.AddReplacement(&Node{ID: id, Subnet: subnetFor(s, attackerSubnets), IsAttacker: true})
		}
	}

	distinctSlots := map[int]bool{}
	for s := 0; s < attackerSubnets; s++ {
		distinctSlots[b.hashSlot(subnetFor(s, attackerSubnets))] = true
	}
	attackerCount := 0
	for _, n := range b.LiveReplacements() {
		if n.IsAttacker {
			attackerCount++
		}
	}
	if attackerCount > len(distinctSlots) {
		t.Fatalf("attacker occupies %d slots but their %d subnets only hash to %d distinct slots under this secret",
			attackerCount, attackerSubnets, len(distinctSlots))
	}
}

func TestDeterministicNeeds10SubnetsForFullBench(t *testing.T) {
	// 5 subnets (the baseline-breaking count) should NOT be enough to own
	// the whole bench under deterministic placement; 10 distinct subnets
	// (one per slot, assuming no collision under this secret) should get
	// much closer to full occupancy.
	run := func(subnets int) float64 {
		b := newTestBucket(SchemeDeterministic, 1.0, 20240711)
		for i := 0; i < MaxReplacements; i++ {
			b.AddReplacement(&Node{ID: uint64(900000 + i), Subnet: subnetFor(i, MaxReplacements)})
		}
		for round := 0; round < 200; round++ {
			for s := 0; s < subnets; s++ {
				id := uint64(1000 + round*subnets + s)
				b.AddReplacement(&Node{ID: id, Subnet: subnetFor(s, subnets), IsAttacker: true})
			}
		}
		return b.AttackerBenchShare()
	}
	share5 := run(5)
	share10 := run(10)
	if share5 >= 0.9 {
		t.Fatalf("5 subnets should NOT achieve near-full bench under deterministic placement, got %.3f", share5)
	}
	if share10 <= share5 {
		t.Fatalf("10 subnets should achieve a higher bench share than 5, got share5=%.3f share10=%.3f",
			share5, share10)
	}
}

// --- promotion: uniformly random, matching real geth, NOT newest-first -----

func TestPromotionIsRandomNotNewestFirst(t *testing.T) {
	// Seed a bench where the FRONT (newest, slot 0) is honest and the
	// remaining 9 slots are attacker-controlled. If promotion were
	// newest-first, the honest node at slot 0 would ALWAYS be promoted.
	// Real geth promotion is tab.rand.Intn(len(replacements)) -- uniformly
	// random -- so across many trials the honest node should be promoted
	// roughly 1/10 of the time, not 100%.
	honestPromotions := 0
	trials := 2000
	for trial := 0; trial < trials; trial++ {
		b := NewBucket(SchemeBaseline, 1.0, 0, int64(trial)) // vary seed per trial
		b.AddEntry(&Node{ID: 0, Subnet: "0.0.0"})             // one live entry to kill
		honest := &Node{ID: 1, Subnet: "1.0.0"}
		b.AddReplacement(honest) // inserted first -> ends at front (slot 0) after no evictions
		for i := 0; i < 9; i++ {
			b.AddReplacement(&Node{ID: uint64(100 + i), Subnet: subnetFor(i, 9), IsAttacker: true})
		}
		promoted := b.KillEntry(0)
		if promoted != nil && promoted.ID == honest.ID {
			honestPromotions++
		}
	}
	rate := float64(honestPromotions) / float64(trials)
	// Expect close to 1/10 = 0.10. Allow a generous band since this is
	// randomized; a newest-first bug would show rate close to 1.0.
	if rate > 0.25 {
		t.Fatalf("promotion rate for the 'newest' honest node was %.3f, expected close to 0.10 "+
			"(promotion must be uniformly random, not newest-first)", rate)
	}
}

// --- helpers -----------------------------------------------------------------

// subnetFor deterministically maps an index into one of n distinct subnet
// labels, used to give attacker/honest nodes controlled subnet diversity.
func subnetFor(i, n int) string {
	label := i % n
	return "subnet-" + itoa(label)
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

func findSlot(b *Bucket, id uint64) int {
	for i, r := range b.hashedReplacements {
		if r != nil && r.ID == id {
			return i
		}
	}
	return -1
}
