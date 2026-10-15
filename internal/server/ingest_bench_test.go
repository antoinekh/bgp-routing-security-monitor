package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// BenchmarkIngestDuringSessionEnd measures what a large session end costs
// ingest. A table holds owned routes of session A on one peer; ingestLoop is
// sent A's session end, then a burst of routes from session B, and the
// burst's ingest rate is compared with the same burst without the session
// end. With reannounce, B's burst re-announces A's first routes, as a router
// does after a takeover, and those are then skipped by the removal; without
// it, B's routes are on another peer and every one of A's must be removed.
//
// burst-µs/route is the burst's ingest cost; cleanup-ms is when A's
// remaining routes were all gone, measured from the start of the burst.
//
//	go test -run '^$' -bench IngestDuringSessionEnd -benchtime 3x ./internal/server/
func BenchmarkIngestDuringSessionEnd(b *testing.B) {
	const owned, burst = 1_000_000, 200_000
	peerA := netip.MustParseAddr("192.0.2.1")
	for _, reannounce := range []bool{false, true} {
		for _, withEnd := range []bool{false, true} {
			name := fmt.Sprintf("owned=%d/burst=%d/reannounce=%t/session_end=%t", owned, burst, reannounce, withEnd)
			b.Run(name, func(b *testing.B) {
				peerB := netip.MustParseAddr("192.0.2.2")
				if reannounce {
					peerB = peerA
				}
				want := uint64(owned + burst) // routes left once done
				switch {
				case withEnd:
					want = burst
				case reannounce:
					want = owned
				}
				var burstTime, cleanupTime time.Duration
				for it := 0; it < b.N; it++ {
					b.StopTimer()
					s, err := New(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
					if err != nil {
						b.Fatal(err)
					}
					fillSession(s, sessA, peerA, owned)
					close(s.rtrReady)
					ctx, cancel := context.WithCancel(context.Background())
					go s.ingestLoop(ctx)
					b.StartTimer()

					start := time.Now()
					if withEnd {
						sessionEnd(s, sessA)
					}
					for i := 0; i < burst; i++ {
						s.ingestCh <- types.IngestEvent{Route: benchRoute(peerB, i, 0), Session: sessB}
					}
					lastKey := types.RouteKey{PeerAddr: peerB, Prefix: benchRoute(peerB, burst-1, 0).Prefix}
					for r := s.table.Get(lastKey); r == nil || r.OwnerSession != sessB; r = s.table.Get(lastKey) {
						time.Sleep(100 * time.Microsecond)
					}
					burstTime += time.Since(start)
					for s.table.Count() != want {
						time.Sleep(100 * time.Microsecond)
					}
					cleanupTime += time.Since(start)

					b.StopTimer()
					cancel()
				}
				b.ReportMetric(float64(burstTime.Microseconds())/float64(b.N)/burst, "burst-µs/route")
				if withEnd {
					b.ReportMetric(float64(cleanupTime.Milliseconds())/float64(b.N), "cleanup-ms")
				}
				b.ReportMetric(0, "ns/op") // includes setup; see the metrics above
			})
		}
	}
}

var benchPostures = []types.SecurityPosture{
	types.PostureUnverified, types.PostureUnverified, types.PostureUnverified,
	types.PostureUnverified, types.PostureUnverified, types.PostureOriginOnly,
	types.PostureOriginOnly, types.PostureOriginOnly, types.PostureOriginOnly,
	types.PostureOriginInvalid,
}

// benchRoute is the i-th route of a production-shaped table: distinct /24s,
// about 70k origin ASNs, and a realistic posture mix.
func benchRoute(peer netip.Addr, i int, session uint64) *types.Route {
	return &types.Route{
		PeerAddr:        peer,
		Prefix:          netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0}), 24),
		ASPath:          []uint32{64501, 1 + uint32(i%70_000)},
		RIBType:         types.AdjRIBInPre,
		SecurityPosture: benchPostures[i%len(benchPostures)],
		OwnerSession:    session,
	}
}

func fillSession(s *Server, session uint64, peer netip.Addr, n int) {
	for i := 0; i < n; i++ {
		s.table.Insert(benchRoute(peer, i, session))
	}
}
