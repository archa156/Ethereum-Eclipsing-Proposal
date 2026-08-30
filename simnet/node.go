// Package simnet simulates the bench-grinding attack using the SAME
// architectural pattern go-ethereum's own developers use to test
// p2p/discover/table.go: a real (faithfully ported) Table implementation
// driven by a FAKE transport, exactly mirroring their pingRecorder pattern
// in p2p/discover/table_util_test.go.
//
// Source verified at commit 6e49f8e6b3404ee33712d147f561fc28c7974a2f:
//   p2p/discover/table.go        -- admission, promotion, pushNode
//   p2p/discover/table_reval.go  -- the TWO-TIER (fast/slow) revalidation
//                                   scheme with livenessChecks decay, which
//                                   this package ports faithfully -- our
//                                   earlier simulator used a flat
//                                   per-round death probability instead,
//                                   which this supersedes.
//   p2p/discover/table_util_test.go -- the pingRecorder fake-transport
//                                   pattern this package's Transport type
//                                   is modelled on.
package simnet

const (
	BucketSize      = 16 // table.go:46
	MaxReplacements = 10 // table.go:47
	BucketIPLimit   = 2  // table.go:56
	TableIPLimit    = 10 // table.go:57

	// slowRevalidationFactor -- table_reval.go:31. The slow list is checked
	// 1/3 as often as the fast list. Real geth expresses this as an
	// interval multiplier on wall-clock time (cfg.PingInterval * 3); our
	// simulation is round-based rather than wall-clock-based, so we
	// preserve the same 3x RATIO as a per-round check PROBABILITY instead
	// (fast list checked with probability p each round, slow list with
	// probability p/3). This is a deliberate, documented adaptation from
	// continuous time to discrete rounds -- the relative fast:slow
	// difference that matters for the dynamics is preserved exactly.
	slowRevalidationFactor = 3
)

// Node -- extends the minimal record from discv5ref with the two fields
// table_reval.go actually uses to decide eviction:
//
//	tableNode.livenessChecks int   -- table_reval.go, decremented via /3 on failure
//	tableNode.revalList *revalidationList -- which queue (fast/slow) this node is in
type Node struct {
	ID         string
	Subnet     string
	IsAttacker bool

	LivenessChecks int      // table_reval.go's n.livenessChecks
	InFastList     bool     // true if currently in the fast revalidation queue
	InSlowList     bool     // true if currently in the slow revalidation queue
}

// Bucket -- table.go:103-110, field names kept identical.
type Bucket struct {
	Entries      []*Node
	Replacements []*Node
	ips          map[string]int
}

func NewBucket() *Bucket {
	return &Bucket{ips: make(map[string]int)}
}

func containsID(list []*Node, id string) bool {
	for _, n := range list {
		if n.ID == id {
			return true
		}
	}
	return false
}

func deleteByID(list []*Node, id string) []*Node {
	for i, n := range list {
		if n.ID == id {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// pushNode -- table.go:740-749, literal port, verified against the real
// function's exact slice mechanics before writing this port:
//
//	pushNode([A,B], N, 3)   -> ([N,A,B], nil)
//	pushNode([A,B,C], N, 3) -> ([N,A,B], C)
func pushNode(list []*Node, n *Node, max int) ([]*Node, *Node) {
	if len(list) < max {
		list = append(list, nil)
	}
	removed := list[len(list)-1]
	copy(list[1:], list)
	list[0] = n
	return list, removed
}
