package simnet

// Attacker sends inbound Pings to the victim's Table, exactly mirroring
// the real attack: a Ping arriving from an unknown node causes
// addInboundNode -> handleAddNode(isInbound=true) in real geth
// (table.go:373-389 addInboundNode's doc comment states this directly:
// "If the bucket has no space, the node is added to the replacements
// list"). This is passive discovery -- the victim didn't ask for this
// contact, it arrived on its own, and gets processed the same as any
// other inbound Ping.
type Attacker struct {
	Subnets       int
	InsertRate    int // Ping attempts per round
	nextID        int
}

func NewAttacker(subnets, insertRate int) *Attacker {
	return &Attacker{Subnets: subnets, InsertRate: insertRate}
}

// Grind sends one round's worth of Pings against the given table/bucket.
// tableInitialised should be true after the initial seeding phase, since
// real geth only applies the anti-flood guard during startup
// (table.go:565-567) -- an attacker targeting a running node faces no
// such guard on this path.
func (a *Attacker) Grind(tab *Table, b *Bucket, round int, tableInitialised bool) {
	for i := 0; i < a.InsertRate; i++ {
		subnetIdx := i % a.Subnets
		a.nextID++
		n := &Node{
			ID:         attackerID(subnetIdx, round, a.nextID),
			Subnet:     attackerSubnet(subnetIdx),
			IsAttacker: true,
		}
		tab.HandleAddNode(b, n, true /* isInbound: this is a real Ping */, tableInitialised)
	}
}

func attackerID(subnet, round, seq int) string {
	return "atk-" + itoa(subnet) + "-r" + itoa(round) + "-" + itoa(seq)
}

func attackerSubnet(i int) string {
	return "attacker-subnet-" + itoa(i)
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
