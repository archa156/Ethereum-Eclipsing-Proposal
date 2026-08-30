package simnet

// Transport is the interface Table depends on to check whether a node is
// still alive. Real geth's equivalent (table.go:94-101 `transport`) sends
// actual UDP Ping packets; ours is faithfully modelled on their OWN test
// double for it -- pingRecorder in table_util_test.go -- which fakes the
// network entirely with an in-memory map, letting the real Table logic
// run unmodified against it.
//
// We adopt exactly that pattern: PingRecorder below is our version of
// pingRecorder, used to drive OUR faithfully-ported revalidation logic
// without any real network.
type Transport interface {
	// Ping returns true if the node responds, false if it times out.
	// Mirrors pingRecorder.ping's dead-map check (table_util_test.go:192-207).
	Ping(id string) bool
}

// PingRecorder is modelled directly on go-ethereum's own pingRecorder
// (p2p/discover/table_util_test.go:130-207), adapted to our needs:
//
//   - Honest nodes fail to respond with probability HonestFailureRate,
//     simulating real-world churn (a peer's process dies, its connection
//     drops, etc.) -- geth's tests instead set exact dead/alive flags per
//     node (t.dead[id] = true), since their tests target specific
//     scenarios; we want a STATISTICAL churn model instead, since our
//     experiments measure attacker takeover under realistic background
//     conditions, not a single scripted failure.
//   - Attacker nodes NEVER fail to respond (they are attacker-controlled
//     infrastructure, deliberately kept online) -- this is a modelling
//     choice specific to our threat model, not present in geth's own test
//     double, and is documented here explicitly.
//
// Every ping is recorded in Pinged, exactly like geth's t.pinged slice,
// so a test or experiment can inspect what was actually checked.
type PingRecorder struct {
	HonestFailureRate float64 // 0..1, probability an honest node fails to respond
	Pinged            []string
	rng               randSource
}

// randSource is a tiny seam so revalidation's randomness can be swapped
// for a deterministic seed in tests, matching how real geth threads
// tab.rand through table_reval.go. rand.Rand itself satisfies this.
type randSource interface {
	Float64() float64
	Intn(n int) int
}

func NewPingRecorder(honestFailureRate float64, rng randSource) *PingRecorder {
	return &PingRecorder{HonestFailureRate: honestFailureRate, rng: rng}
}

// Ping mirrors pingRecorder.ping (table_util_test.go:192-207): record the
// ping, then decide the outcome. Real geth checks a per-node `dead` map;
// we use a per-node-class failure probability instead (see type doc).
func (p *PingRecorder) Ping(id string, isAttacker bool) bool {
	p.Pinged = append(p.Pinged, id)
	if isAttacker {
		return true // attacker infrastructure is always kept online
	}
	return p.rng.Float64() >= p.HonestFailureRate
}
