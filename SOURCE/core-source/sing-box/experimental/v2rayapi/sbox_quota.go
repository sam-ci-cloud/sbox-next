// SBOX accounting extension. GPL-3.0-or-later, same license as sing-box.
// Only local authorization and managed-identity connection lifecycle are added.
package v2rayapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	N "github.com/sagernet/sing/common/network"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

func sboxPath(key, fallback string) string {
	if p := os.Getenv(key); p != "" {
		return p
	}
	return fallback
}
func sboxRootFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || !ok || owner.Uid != 0 || st.Mode().Perm()&0007 != 0 || st.Mode().Perm()&0022 != 0 || st.Size() > 1048576 {
		return nil, errors.New("unsafe accounting control file")
	}
	return io.ReadAll(io.LimitReader(f, 1048577))
}
func sboxAuth(listen string) (grpc.UnaryServerInterceptor, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return nil, errors.New("SBOX StatsService requires an explicit loopback address")
	}
	key, err := sboxRootFile(sboxPath("SBOX_STATS_TOKEN_FILE", "/etc/sbox-manager/stats-auth.key"))
	if err != nil {
		return nil, errors.New("SBOX StatsService authorization file is unavailable")
	}
	if len(key) < 32 || len(key) > 256 {
		return nil, errors.New("invalid StatsService authorization key")
	}
	expected := "Bearer " + string(key)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		values := metadata.ValueFromIncomingContext(ctx, "authorization")
		if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "local StatsService authorization required")
		}
		switch v := req.(type) {
		case *QueryStatsRequest:
			if v.Reset_ {
				return nil, status.Error(codes.PermissionDenied, "counter resets are forbidden")
			}
		case *GetStatsRequest:
			if v.Reset_ {
				return nil, status.Error(codes.PermissionDenied, "counter resets are forbidden")
			}
		case *SysStatsRequest:
		default:
			return nil, status.Error(codes.PermissionDenied, "read-only StatsService")
		}
		return next(ctx, req)
	}, nil
}

var (
	sboxManaged   = regexp.MustCompile(`^user-[a-f0-9]{32}(?:@(reality|vmess|hy2|tuic|anytls))?$`)
	sboxLimitUser = regexp.MustCompile(`^user-[a-f0-9]{32}$`)
	sboxProtocols = []string{"reality", "vmess", "hy2", "tuic", "anytls"}
)

// sboxLimitInterval bounds quota overshoot to roughly throughput x interval.
const sboxLimitInterval = 100 * time.Millisecond

type sboxGuard struct {
	mu      sync.Mutex
	blocked map[string]bool
	live    map[io.Closer]string
	stop    chan struct{}
	once    sync.Once
	// Byte budgets: the collector publishes, per managed user, the absolute
	// value of the core's own up+down counters (all five protocols) at which
	// the quota is exhausted. The guard compares live counters every
	// sboxLimitInterval, so enforcement does not wait for the collector cycle.
	limits    map[string]int64
	overLimit map[string]bool
	counter   func(name string) int64
}

func newSboxGuard() *sboxGuard {
	g := &sboxGuard{blocked: map[string]bool{}, live: map[io.Closer]string{}, stop: make(chan struct{}),
		limits: map[string]int64{}, overLimit: map[string]bool{}}
	g.load()
	go func() {
		t := time.NewTicker(time.Second)
		fast := time.NewTicker(sboxLimitInterval)
		defer t.Stop()
		defer fast.Stop()
		for {
			select {
			case <-g.stop:
				return
			case <-t.C:
				g.load()
			case <-fast.C:
				g.enforceLimits()
			}
		}
	}()
	return g
}

func sboxUserOf(tag string) string {
	if i := strings.IndexByte(tag, '@'); i > 0 {
		return tag[:i]
	}
	return tag
}

func (g *sboxGuard) usage(user string) int64 {
	var total int64
	for _, p := range sboxProtocols {
		total += g.counter("user>>>" + user + "@" + p + ">>>traffic>>>uplink")
		total += g.counter("user>>>" + user + "@" + p + ">>>traffic>>>downlink")
	}
	return total
}

func (g *sboxGuard) enforceLimits() {
	g.mu.Lock()
	limits := g.limits
	counter := g.counter
	g.mu.Unlock()
	if counter == nil {
		return
	}
	over := map[string]bool{}
	for user, limit := range limits {
		if g.usage(user) >= limit {
			over[user] = true
		}
	}
	var closeList []io.Closer
	g.mu.Lock()
	g.overLimit = over
	for c, tag := range g.live {
		if over[sboxUserOf(tag)] {
			closeList = append(closeList, c)
		}
	}
	g.mu.Unlock()
	for _, c := range closeList {
		c.Close()
	}
}
func (g *sboxGuard) load() {
	data, err := sboxRootFile(sboxPath("SBOX_QUOTA_POLICY_FILE", "/etc/sbox-manager/quota-runtime.json"))
	if err != nil {
		return
	}
	var policy struct {
		Blocked []string         `json:"blocked"`
		Limits  map[string]int64 `json:"limits"`
	}
	if json.Unmarshal(data, &policy) != nil || len(policy.Blocked) > 5000 || len(policy.Limits) > 1000 {
		return
	}
	limits := map[string]int64{}
	for user, limit := range policy.Limits {
		if sboxLimitUser.MatchString(user) && limit >= 0 {
			limits[user] = limit
		}
	}
	next := map[string]bool{}
	for _, name := range policy.Blocked {
		if sboxManaged.MatchString(name) {
			next[name] = true
		}
	}
	var closeList []io.Closer
	g.mu.Lock()
	g.blocked = next
	g.limits = limits
	for c, name := range g.live {
		if next[name] {
			closeList = append(closeList, c)
		}
	}
	g.mu.Unlock()
	for _, c := range closeList {
		c.Close()
	}
}
func (g *sboxGuard) add(c io.Closer, user string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked[user] || g.overLimit[sboxUserOf(user)] || len(g.live) >= 8192 {
		return false
	}
	g.live[c] = user
	return true
}
func (g *sboxGuard) setCounter(counter func(string) int64) {
	g.mu.Lock()
	g.counter = counter
	g.mu.Unlock()
}

// sboxPeekCounter reads a counter without creating it.
func (s *StatsService) sboxPeekCounter(name string) int64 {
	s.access.Lock()
	counter := s.counters[name]
	s.access.Unlock()
	if counter == nil {
		return 0
	}
	return counter.Load()
}
func (g *sboxGuard) remove(c io.Closer) { g.mu.Lock(); delete(g.live, c); g.mu.Unlock() }
func (g *sboxGuard) close()             { g.once.Do(func() { close(g.stop) }) }

type sboxConn struct {
	net.Conn
	g    *sboxGuard
	once sync.Once
}

func (c *sboxConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.g.remove(c) })
	return err
}

type sboxPacket struct {
	N.PacketConn
	g    *sboxGuard
	once sync.Once
}

func (c *sboxPacket) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(func() { c.g.remove(c) })
	return err
}
func (s *StatsService) sboxConnection(conn net.Conn, user string) net.Conn {
	if !sboxManaged.MatchString(user) {
		return conn
	}
	c := &sboxConn{Conn: conn, g: s.guard}
	if !s.guard.add(c, user) {
		c.Close()
	}
	return c
}
func (s *StatsService) sboxPackets(conn N.PacketConn, user string) N.PacketConn {
	if !sboxManaged.MatchString(user) {
		return conn
	}
	c := &sboxPacket{PacketConn: conn, g: s.guard}
	if !s.guard.add(c, user) {
		c.Close()
	}
	return c
}

// Preserve protocol headroom/read-waiter discovery through the lifecycle wrapper.
func (c *sboxPacket) Upstream() any { return c.PacketConn }
func (c *sboxConn) Upstream() any   { return c.Conn }
