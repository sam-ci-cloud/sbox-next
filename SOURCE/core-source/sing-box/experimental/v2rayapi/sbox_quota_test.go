package v2rayapi

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"

	"google.golang.org/grpc"
)

type headroomPacket struct{ N.PacketConn }

func (*headroomPacket) FrontHeadroom() int { return 16 }
func (*headroomPacket) RearHeadroom() int  { return 8 }
func TestSboxPacketPreservesProtocolHeadroom(t *testing.T) {
	p := &sboxPacket{PacketConn: &headroomPacket{}}
	if got := N.CalculateFrontHeadroom(p); got != 16 {
		t.Fatalf("front headroom lost: %d", got)
	}
	if got := N.CalculateRearHeadroom(p); got != 8 {
		t.Fatalf("rear headroom lost: %d", got)
	}
}
func TestSboxManagedNamesProtectLegacy(t *testing.T) {
	for _, name := range []string{"legacy", "reality", "vmess", "hy2", "tuic", "anytls", "user-evil", "user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@unknown"} {
		if sboxManaged.MatchString(name) {
			t.Fatal(name)
		}
	}
	if !sboxManaged.MatchString("user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@tuic") {
		t.Fatal("managed user rejected")
	}
}
func TestSboxCloseRemovesOnlyItsOwnFlow(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	g := &sboxGuard{live: map[io.Closer]string{}, blocked: map[string]bool{}, stop: make(chan struct{})}
	c := &sboxConn{Conn: a, g: g}
	if !g.add(c, "user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@reality") {
		t.Fatal("add")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
	if len(g.live) != 0 {
		t.Fatal("closed flow retained")
	}
}

// 1.14.4 replaced Server.Close with a lifecycle scope cleanup. The SBOX guard
// must still stop when the scope closes, and a repeated close must be harmless.
func TestSboxScopeCloseStopsGuard(t *testing.T) {
	g := &sboxGuard{blocked: map[string]bool{}, live: map[io.Closer]string{}, stop: make(chan struct{})}
	s := &Server{grpcServer: grpc.NewServer(), statsService: &StatsService{guard: g}}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err := s.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal("scope close:", err)
	}
	select {
	case <-g.stop:
	default:
		t.Fatal("quota guard still running after scope close")
	}
	g.close()
}

// 1.2.1: byte budgets close a user's live flows within one fast interval of
// crossing the published counter threshold, refuse new flows, leave other
// users alone and release the user when the threshold is raised (reset).
func TestSboxByteBudgetClosesAndReleases(t *testing.T) {
	g := &sboxGuard{blocked: map[string]bool{}, live: map[io.Closer]string{}, stop: make(chan struct{}),
		limits: map[string]int64{}, overLimit: map[string]bool{}}
	counters := map[string]int64{}
	var mu sync.Mutex
	g.setCounter(func(name string) int64 { mu.Lock(); defer mu.Unlock(); return counters[name] })
	user := "user-" + strings.Repeat("a", 32)
	other := "user-" + strings.Repeat("b", 32)
	a1, a2 := net.Pipe()
	defer a2.Close()
	b1, b2 := net.Pipe()
	defer b2.Close()
	ca := &sboxConn{Conn: a1, g: g}
	cb := &sboxConn{Conn: b1, g: g}
	if !g.add(ca, user+"@hy2") || !g.add(cb, other+"@tuic") {
		t.Fatal("add")
	}
	g.limits = map[string]int64{user: 1000, other: 1000}
	mu.Lock()
	counters["user>>>"+user+"@hy2>>>traffic>>>downlink"] = 600
	counters["user>>>"+user+"@reality>>>traffic>>>uplink"] = 399
	mu.Unlock()
	g.enforceLimits()
	if len(g.live) != 2 {
		t.Fatal("closed below the threshold")
	}
	mu.Lock()
	counters["user>>>"+user+"@reality>>>traffic>>>uplink"] = 400
	mu.Unlock()
	g.enforceLimits()
	if _, ok := g.live[ca]; ok {
		t.Fatal("flow over budget not closed")
	}
	if _, ok := g.live[cb]; !ok {
		t.Fatal("another user's flow was closed")
	}
	n1, n2 := net.Pipe()
	defer n2.Close()
	if g.add(&sboxConn{Conn: n1, g: g}, user+"@vmess") {
		t.Fatal("new flow accepted over budget")
	}
	g.limits = map[string]int64{user: 1 << 40}
	g.enforceLimits()
	r1, r2 := net.Pipe()
	defer r2.Close()
	if !g.add(&sboxConn{Conn: r1, g: g}, user+"@vmess") {
		t.Fatal("raised budget (reset) did not release the user")
	}
}
