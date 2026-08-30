package simnet

// Revalidation -- faithfully adapted from table_reval.go's tableRevalidation.
// Real geth keeps TWO queues:
//
//	fast  -- newly added / recently failed nodes, checked often
//	slow  -- nodes that have proven reliable, checked 1/3 as often
//	         (slowRevalidationFactor = 3, table_reval.go:31)
//
// On a failed ping: livenessChecks /= 3; only evicted once that reaches 0
// (table_reval.go:160-168) -- NOT on the first failure. This means an
// established node (high livenessChecks) survives one bad ping far more
// often than a brand-new one, which is the real reason entries are hard
// to attack and the bench is not.
//
// On success: livenessChecks++, and if the node wasn't just moved for an
// endpoint change, it graduates to the slow list (table_reval.go:180-183).
//
// ADAPTATION NOTE: real geth schedules checks against wall-clock time
// (mclock.AbsTime, cfg.PingInterval). This simulation is round-based, not
// time-based, so each round we check the fast list with probability
// fastCheckProb and the slow list with probability
// fastCheckProb/slowRevalidationFactor -- preserving the real 3x relative
// difference between the two queues without needing a continuous clock.
type Revalidation struct {
	fastList []*Node
	slowList []*Node

	fastCheckProb float64
	transport     *PingRecorder
}

func NewRevalidation(fastCheckProb float64, transport *PingRecorder) *Revalidation {
	return &Revalidation{
		fastCheckProb: fastCheckProb,
		transport:     transport,
	}
}

// TrackNew registers a newly-added entry on the fast list --
// table_reval.go:57-60 nodeAdded.
func (r *Revalidation) TrackNew(n *Node) {
	n.InFastList = true
	n.InSlowList = false
	r.fastList = append(r.fastList, n)
}

// Untrack removes a node from whichever list it's in --
// table_reval.go:62-68 nodeRemoved.
func (r *Revalidation) Untrack(n *Node) {
	r.fastList = removeNode(r.fastList, n)
	r.slowList = removeNode(r.slowList, n)
	n.InFastList = false
	n.InSlowList = false
}

func removeNode(list []*Node, target *Node) []*Node {
	for i, n := range list {
		if n == target {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// Run performs one round of revalidation -- adapted from
// table_reval.go:79-94 `run`. rng is the table's own seeded random source
// (mirrors tab.rand being threaded through table_reval.go throughout).
// Returns the node that was evicted this round (nil if none), for the
// caller to trigger DeleteInBucket/promotion.
func (r *Revalidation) Run(tab *Table, b *Bucket, rng randSource) *Node {
	if rng.Float64() < r.fastCheckProb && len(r.fastList) > 0 {
		return r.checkOne(tab, b, r.fastList, true, rng)
	}
	if rng.Float64() < r.fastCheckProb/slowRevalidationFactor && len(r.slowList) > 0 {
		return r.checkOne(tab, b, r.slowList, false, rng)
	}
	return nil
}

// checkOne picks a uniformly random node from the given list --
// table_reval.go:206-218 revalidationList.get -- pings it, and applies
// the real decay/eviction/promotion logic --
// table_reval.go:134-184 handleResponse.
func (r *Revalidation) checkOne(tab *Table, b *Bucket, list []*Node, fromFast bool, rng randSource) *Node {
	idx := rng.Intn(len(list))
	n := list[idx]

	alive := r.transport.Ping(n.ID, n.IsAttacker)

	if !alive {
		// table_reval.go:160-168
		n.LivenessChecks /= 3
		if n.LivenessChecks <= 0 {
			r.Untrack(n)
			promoted := tab.DeleteInBucket(b, n.ID)
			if promoted != nil {
				r.TrackNew(promoted)
			}
			return n // n is the one that was evicted
		}
		// stays in its current list for retry -- table_reval.go:166
		return nil
	}

	// table_reval.go:171-183 -- responded successfully
	n.LivenessChecks++
	if fromFast {
		// graduate to slow list (no endpoint-change modelling here --
		// our nodes have a static subnet, so nothing analogous to
		// bumpInBucket's IP/port change applies)
		r.Untrack(n)
		n.InSlowList = true
		r.slowList = append(r.slowList, n)
	}
	return nil
}
