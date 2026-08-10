// Package bench models a single Kademlia/Discv5 bucket's replacement list
// ("the bench"), faithfully mirroring the real go-ethereum implementation in
// p2p/discover/table.go, so that bench-grinding attacks and mitigations can
// be measured against the actual admission and promotion logic Ethereum runs.
//
// Verified against go-ethereum (github.com/ethereum/go-ethereum), package
// p2p/discover, file table.go:
//
//	bucketSize      = 16  // live entries per bucket
//	maxReplacements = 10  // replacement list ("bench") size per bucket
//	bucketIPLimit   = 2   // max nodes from the same /24 subnet, per bucket
//	tableIPLimit    = 10  // max nodes from the same /24 subnet, whole table
//
// Two behaviours matter for the attack and are reproduced exactly:
//
//  1. pushNode() inserts the new node at the FRONT of the replacement list
//     and evicts from the BACK once the list is full. This is what makes
//     the bench "grindable": repeated insertion of attacker nodes keeps
//     pushing honest nodes off the back.
//
//  2. deleteInBucket() promotes a UNIFORMLY RANDOM replacement into the live
//     entries when a live entry dies -- NOT the newest replacement. This
//     matches tab.rand.Intn(len(b.replacements)) in the real source. A
//     random pick only protects an honest-majority bench; once the bench
//     is attacker-dominated, random selection still promotes an attacker
//     node with probability equal to their bench share.
package bench

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
)

// Constants mirroring go-ethereum p2p/discover/table.go exactly.
const (
	BucketSize      = 16 // Kademlia bucket size (live entries)
	MaxReplacements = 10 // size of per-bucket replacement list (the "bench")
	BucketIPLimit   = 2  // at most 2 addresses from the same /24 per bucket
)

// Scheme selects the replacement-list admission policy under test.
// Only admission (how a node enters the bench) differs between schemes;
// promotion (how a node leaves the bench into live entries) is always the
// real geth behaviour -- a uniformly random pick -- so the experiment
// isolates admission as the single variable being compared.
type Scheme int

const (
	// SchemeBaseline is today's go-ethereum: pushNode, front-insert /
	// evict-back, gated only by the /24 subnet limit. This is what the
	// vulnerability brief describes as fully grindable.
	SchemeBaseline Scheme = iota

	// SchemeFractionSampling accepts an admission attempt into the bench
	// only with probability P. Slows a grind but does not stop it.
	SchemeFractionSampling

	// SchemeDeterministic is the addrman-style fix: a node's bench slot
	// is slot = hash(subnet || secret) % MaxReplacements. The same
	// subnet always maps to the same slot, so repeated insertion of the
	// same node is a no-op. Grinding buys nothing.
	SchemeDeterministic
)

func (s Scheme) String() string {
	switch s {
	case SchemeBaseline:
		return "baseline"
	case SchemeFractionSampling:
		return "fraction_sampling"
	case SchemeDeterministic:
		return "deterministic"
	default:
		return "unknown"
	}
}

// Node is a minimal peer record for the simulator: identity, originating
// /24 subnet (modelled as a string label so a rented cloud block can be
// given a distinct label per attacker-controlled range), and whether it is
// attacker-controlled (used only for measurement, never by the bucket
// logic itself -- the defense must work without knowing who's honest).
type Node struct {
	ID         uint64
	Subnet     string
	IsAttacker bool
}

// Bucket mirrors a single k-bucket's live entries and replacement list.
//
// The replacement list uses TWO DIFFERENT internal representations
// depending on scheme, because the two admission families are naturally
// different data structures and forcing them into one caused a real bug
// during development (see project notes): baseline/fraction-sampling need
// a genuinely ORDERED, COMPACTED list -- exactly like real geth's
// []*tableNode, where removal shrinks the slice with no gaps -- while
// deterministic placement needs a FIXED, HASH-INDEXED array where a slot
// can be legitimately empty (nil) between insertions. Both are exposed
// through the same accessor methods (LiveReplacements, AttackerBenchShare,
// etc.) so callers never need to know which is active.
type Bucket struct {
	Entries []*Node

	// orderedReplacements backs SchemeBaseline and SchemeFractionSampling.
	// Index 0 is the front (newest); index len-1 is the back (oldest,
	// evicted first). Always compacted -- no nils, matching real geth's
	// []*tableNode exactly.
	orderedReplacements []*Node

	// hashedReplacements backs SchemeDeterministic. Fixed size
	// MaxReplacements; nil means the slot is currently empty.
	hashedReplacements [MaxReplacements]*Node

	scheme  Scheme
	sampleP float64 // used by SchemeFractionSampling
	secret  uint64  // used by SchemeDeterministic; unknown to the attacker
	rng     *rand.Rand

	// subnetCounts tracks per-subnet occupancy across entries+replacements,
	// mirroring the real addIP's DistinctNetSet bookkeeping.
	subnetCounts map[string]int
}

// NewBucket constructs a bucket under the given scheme. sampleP is only
// used by SchemeFractionSampling; secret is only used by SchemeDeterministic.
// seed makes the bucket's internal randomness (coin flips, promotion choice)
// reproducible across experiment runs.
func NewBucket(scheme Scheme, sampleP float64, secret uint64, seed int64) *Bucket {
	return &Bucket{
		scheme:       scheme,
		sampleP:      sampleP,
		secret:       secret,
		rng:          rand.New(rand.NewSource(seed)),
		subnetCounts: make(map[string]int),
	}
}

// AddEntry inserts directly into live entries, bypassing admission control.
// Used only to seed a bucket with honest incumbents at experiment start --
// mirrors a bucket that is already full of established, honest peers.
func (b *Bucket) AddEntry(n *Node) bool {
	if len(b.Entries) >= BucketSize {
		return false
	}
	if b.subnetCounts[n.Subnet] >= BucketIPLimit {
		return false
	}
	b.Entries = append(b.Entries, n)
	b.subnetCounts[n.Subnet]++
	return true
}

// AddReplacement mirrors tab.addReplacement in table.go: a node arrives
// for a bucket whose live entries are full, so it is offered to the bench
// under the configured admission scheme. Returns true if the bench's
// contents changed as a result.
func (b *Bucket) AddReplacement(n *Node) bool {
	// containsID dedupe check, as in the real addReplacement.
	for _, r := range b.liveSlots() {
		if r.ID == n.ID {
			return false
		}
	}
	// addIP: subnet limit check, applies identically under every scheme --
	// this is the ONLY defense geth has today, and it is not being removed,
	// only supplemented.
	if b.subnetCounts[n.Subnet] >= BucketIPLimit {
		return false
	}

	switch b.scheme {
	case SchemeBaseline:
		return b.pushFrontEvictBack(n)
	case SchemeFractionSampling:
		if b.rng.Float64() >= b.sampleP {
			return false // rejected by the admission coin flip
		}
		return b.pushFrontEvictBack(n)
	case SchemeDeterministic:
		return b.placeDeterministic(n)
	default:
		return false
	}
}

// pushFrontEvictBack mirrors pushNode() exactly: the new node is prepended
// (front, index 0); if the list was already at MaxReplacements, the last
// element (back, oldest) is evicted. The list is always compacted -- this
// is a real slice, matching go-ethereum's []*tableNode, with no gaps. This
// exact front-insert/back-evict rule is what a grinding attacker exploits.
func (b *Bucket) pushFrontEvictBack(n *Node) bool {
	var removed *Node
	if len(b.orderedReplacements) >= MaxReplacements {
		removed = b.orderedReplacements[len(b.orderedReplacements)-1]
		b.orderedReplacements = b.orderedReplacements[:len(b.orderedReplacements)-1]
	}
	b.orderedReplacements = append([]*Node{n}, b.orderedReplacements...)
	if removed != nil {
		b.subnetCounts[removed.Subnet]--
	}
	b.subnetCounts[n.Subnet]++
	return true
}

// placeDeterministic implements the addrman-style fix. slot is a function
// only of the node's subnet and a secret unknown to the attacker, so the
// same subnet always lands in the same slot: inserting the same node 1000
// times is identical to inserting it once. A different node can only ever
// occupy that slot if it hashes to the same value.
func (b *Bucket) placeDeterministic(n *Node) bool {
	slot := b.hashSlot(n.Subnet)
	existing := b.hashedReplacements[slot]
	if existing != nil && existing.ID == n.ID {
		return false // already resident; grinding is a no-op
	}
	if existing != nil {
		b.subnetCounts[existing.Subnet]--
	}
	b.hashedReplacements[slot] = n
	b.subnetCounts[n.Subnet]++
	return true
}

func (b *Bucket) hashSlot(subnet string) int {
	h := sha256.New()
	h.Write([]byte(subnet))
	var secretBytes [8]byte
	binary.LittleEndian.PutUint64(secretBytes[:], b.secret)
	h.Write(secretBytes[:])
	sum := h.Sum(nil)
	v := binary.LittleEndian.Uint64(sum[:8])
	return int(v % uint64(MaxReplacements))
}

// KillEntry mirrors deleteInBucket: removes a specific live entry (by
// index into Entries) and promotes a UNIFORMLY RANDOM current replacement
// in its place -- matching tab.rand.Intn(len(b.replacements)) in the real
// source, not a newest-first rule. Returns the promoted node, or nil if
// the bench was empty.
func (b *Bucket) KillEntry(idx int) *Node {
	if idx < 0 || idx >= len(b.Entries) {
		return nil
	}
	dead := b.Entries[idx]
	b.Entries = append(b.Entries[:idx], b.Entries[idx+1:]...)
	b.subnetCounts[dead.Subnet]--

	live := b.liveSlots()
	if len(live) == 0 {
		return nil
	}
	rindex := b.rng.Intn(len(live))
	promoted := live[rindex]
	b.removeFromReplacements(promoted.ID)
	b.Entries = append(b.Entries, promoted)
	return promoted
}

// KillRandomEntry picks a uniformly random live entry to kill -- models
// natural honest churn (a peer going offline), independent of the attack.
func (b *Bucket) KillRandomEntry() *Node {
	if len(b.Entries) == 0 {
		return nil
	}
	return b.KillEntry(b.rng.Intn(len(b.Entries)))
}

// removeFromReplacements removes a promoted node from whichever
// representation is active. For the ordered list this shrinks and
// compacts the slice (matching slices.Delete in the real source); for the
// hashed array it simply clears that node's slot, leaving it addressable
// and empty until something else hashes there.
func (b *Bucket) removeFromReplacements(id uint64) {
	if b.scheme == SchemeDeterministic {
		for i, r := range b.hashedReplacements {
			if r != nil && r.ID == id {
				b.hashedReplacements[i] = nil
				return
			}
		}
		return
	}
	for i, r := range b.orderedReplacements {
		if r.ID == id {
			b.orderedReplacements = append(b.orderedReplacements[:i], b.orderedReplacements[i+1:]...)
			return
		}
	}
}

func (b *Bucket) liveSlots() []*Node {
	if b.scheme == SchemeDeterministic {
		out := make([]*Node, 0, MaxReplacements)
		for _, r := range b.hashedReplacements {
			if r != nil {
				out = append(out, r)
			}
		}
		return out
	}
	return b.orderedReplacements
}

// LiveReplacements returns the current occupied bench slots.
func (b *Bucket) LiveReplacements() []*Node {
	return b.liveSlots()
}

// AttackerBenchShare returns the fraction (0..1) of occupied replacement
// slots currently held by attacker-controlled nodes. This is the primary
// measurement of Experiments 1-3.
func (b *Bucket) AttackerBenchShare() float64 {
	live := b.liveSlots()
	if len(live) == 0 {
		return 0
	}
	attackerCount := 0
	for _, n := range live {
		if n.IsAttacker {
			attackerCount++
		}
	}
	return float64(attackerCount) / float64(len(live))
}

// AttackerEntryShare returns the fraction (0..1) of LIVE ENTRIES currently
// held by attacker-controlled nodes -- the ultimate eclipse metric, since
// entries (not the bench) are what the node actually uses as peers.
func (b *Bucket) AttackerEntryShare() float64 {
	if len(b.Entries) == 0 {
		return 0
	}
	attackerCount := 0
	for _, n := range b.Entries {
		if n.IsAttacker {
			attackerCount++
		}
	}
	return float64(attackerCount) / float64(len(b.Entries))
}
