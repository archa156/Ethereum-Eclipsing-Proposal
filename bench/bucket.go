package bench

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
)

const (
	BucketSize      = 16
	MaxReplacements = 10
	BucketIPLimit   = 2
)

type Scheme int

const (
	SchemeBaseline Scheme = iota

	SchemeFractionSampling

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

type Node struct {
	ID         uint64
	Subnet     string
	IsAttacker bool
}

type Bucket struct {
	Entries []*Node

	orderedReplacements []*Node

	hashedReplacements [MaxReplacements]*Node

	scheme  Scheme
	sampleP float64
	secret  uint64
	rng     *rand.Rand

	subnetCounts map[string]int
}

func NewBucket(scheme Scheme, sampleP float64, secret uint64, seed int64) *Bucket {
	return &Bucket{
		scheme:       scheme,
		sampleP:      sampleP,
		secret:       secret,
		rng:          rand.New(rand.NewSource(seed)),
		subnetCounts: make(map[string]int),
	}
}

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

func (b *Bucket) AddReplacement(n *Node) bool {

	for _, r := range b.liveSlots() {
		if r.ID == n.ID {
			return false
		}
	}

	if b.subnetCounts[n.Subnet] >= BucketIPLimit {
		return false
	}

	switch b.scheme {
	case SchemeBaseline:
		return b.pushFrontEvictBack(n)
	case SchemeFractionSampling:
		if b.rng.Float64() >= b.sampleP {
			return false
		}
		return b.pushFrontEvictBack(n)
	case SchemeDeterministic:
		return b.placeDeterministic(n)
	default:
		return false
	}
}

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

func (b *Bucket) placeDeterministic(n *Node) bool {
	slot := b.hashSlot(n.Subnet)
	existing := b.hashedReplacements[slot]
	if existing != nil && existing.ID == n.ID {
		return false
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

func (b *Bucket) KillRandomEntry() *Node {
	if len(b.Entries) == 0 {
		return nil
	}
	return b.KillEntry(b.rng.Intn(len(b.Entries)))
}

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

func (b *Bucket) LiveReplacements() []*Node {
	return b.liveSlots()
}

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
