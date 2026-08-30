package simnet

import "math/rand"

// Table -- table-wide state plus the event hooks real geth exposes.
// table.go:89-91:
//
//	nodeFeed        event.FeedOf[*enode.Node]
//	nodeAddedHook   func(*bucket, *tableNode)
//	nodeRemovedHook func(*bucket, *tableNode)
//
// Geth's own tests use these hooks via nodeEventRecorder
// (table_util_test.go:300-352) to synchronously wait for a specific node
// to be added/removed, rather than polling. We adopt the same pattern:
// OnNodeAdded/OnNodeRemoved let the experiment layer observe attacker
// takeover event-by-event instead of manually recomputing shares.
type Table struct {
	tableIPs map[string]int
	rand     *rand.Rand

	OnNodeAdded   func(n *Node)
	OnNodeRemoved func(n *Node)
}

func NewTable(seed int64) *Table {
	return &Table{
		tableIPs: make(map[string]int),
		rand:     rand.New(rand.NewSource(seed)),
	}
}

func (tab *Table) fireAdded(n *Node) {
	if tab.OnNodeAdded != nil {
		tab.OnNodeAdded(n)
	}
}

func (tab *Table) fireRemoved(n *Node) {
	if tab.OnNodeRemoved != nil {
		tab.OnNodeRemoved(n)
	}
}

// addIP -- table.go:530-547, two-level check (table-wide then bucket),
// with rollback if the bucket-level check fails after the table-level
// check already succeeded.
func (tab *Table) addIP(b *Bucket, subnet string) bool {
	if tab.tableIPs[subnet] >= TableIPLimit {
		return false
	}
	tab.tableIPs[subnet]++
	if b.ips[subnet] >= BucketIPLimit {
		tab.tableIPs[subnet]--
		return false
	}
	b.ips[subnet]++
	return true
}

// removeIP -- table.go:549-555.
func (tab *Table) removeIP(b *Bucket, subnet string) {
	if tab.tableIPs[subnet] > 0 {
		tab.tableIPs[subnet]--
	}
	if b.ips[subnet] > 0 {
		b.ips[subnet]--
	}
}

// AddReplacement -- table.go:597-613 addReplacement, literal port. This is
// "the heart of the vulnerability": past dedupe and the IP check, there is
// no liveness requirement and no rate limit -- only pushNode's
// front-insert/back-evict behaviour gates the bench.
func (tab *Table) AddReplacement(b *Bucket, n *Node) bool {
	if containsID(b.Replacements, n.ID) {
		return false
	}
	if !tab.addIP(b, n.Subnet) {
		return false
	}
	var removed *Node
	b.Replacements, removed = pushNode(b.Replacements, n, MaxReplacements)
	if removed != nil {
		tab.removeIP(b, removed.Subnet)
	}
	return true
}

// HandleAddNode -- table.go:557-595 handleAddNode, the full "front door"
// decision tree, including the anti-flood guard the project brief calls
// out (inbound contacts refused while the table is still initialising;
// found nodes have no such guard).
func (tab *Table) HandleAddNode(b *Bucket, n *Node, isInbound, tableInitialised bool) bool {
	if isInbound && !tableInitialised {
		return false // table.go:565-567
	}
	if containsID(b.Entries, n.ID) {
		return false // bumpInBucket path -- not a new admission
	}
	if len(b.Entries) >= BucketSize {
		tab.AddReplacement(b, n) // table.go:575-578
		return false
	}
	if !tab.addIP(b, n.Subnet) {
		return false // table.go:580-583
	}

	// table.go:585-593
	n.LivenessChecks = 0
	b.Entries = append(b.Entries, n)
	b.Replacements = deleteByID(b.Replacements, n.ID)
	tab.fireAdded(n)
	return true
}

// DeleteInBucket -- table.go:641-668 deleteInBucket, literal port. The
// promotion pick is tab.rand.Intn(len(b.replacements)): uniformly random,
// not newest-first -- verified by direct line reference, correcting an
// earlier draft of this project that assumed newest-first.
func (tab *Table) DeleteInBucket(b *Bucket, id string) *Node {
	index := -1
	for i, n := range b.Entries {
		if n.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		return nil
	}

	dead := b.Entries[index]
	b.Entries = append(b.Entries[:index], b.Entries[index+1:]...)
	tab.removeIP(b, dead.Subnet)
	tab.fireRemoved(dead)

	if len(b.Replacements) == 0 {
		return nil
	}
	rindex := tab.rand.Intn(len(b.Replacements)) // table.go:661
	rep := b.Replacements[rindex]
	b.Replacements = append(b.Replacements[:rindex], b.Replacements[rindex+1:]...)
	b.Entries = append(b.Entries, rep)
	rep.LivenessChecks = 0
	tab.fireAdded(rep)
	return rep
}
