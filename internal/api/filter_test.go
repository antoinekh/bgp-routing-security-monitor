package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// filterFixture is the production report's shape: 1.1.1.0/24 held by four
// peers, plus other prefixes, origins and postures on the same peers. Peer
// 80.81.194.180's routes are stored under its IPv4-mapped form, which must
// match the plain form and the reverse.
func filterFixture(t *testing.T) *Server {
	t.Helper()
	table := routetable.New()
	add := func(peer, prefix string, origin uint32, posture types.SecurityPosture) {
		table.Insert(&types.Route{
			PeerAddr:        netip.MustParseAddr(peer),
			Prefix:          netip.MustParsePrefix(prefix),
			ASPath:          []uint32{64500, origin},
			RIBType:         types.AdjRIBInPre,
			SecurityPosture: posture,
		})
	}
	for _, peer := range []string{"::ffff:80.81.194.180", "80.81.194.181", "206.82.106.254", "46.18.174.241"} {
		add(peer, "1.1.1.0/24", 13335, types.PostureSecured)
	}
	add("::ffff:80.81.194.180", "8.8.8.0/24", 15169, types.PostureOriginOnly)
	add("::ffff:80.81.194.180", "9.9.9.0/24", 13335, types.PosturePathSuspect)
	add("206.82.106.254", "8.8.8.0/24", 15169, types.PostureOriginOnly)
	return NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
}

func getRoutes(t *testing.T, s *Server, q url.Values) (int, []RouteResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleRoutes(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes?"+q.Encode(), nil))
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var out []RouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec.Code, out
}

// Every filter given applies, alone and in any combination; an IPv4 peer
// matches in either form.
func TestRoutesFiltersCombine(t *testing.T) {
	s := filterFixture(t)
	key := func(r RouteResponse) string {
		return netip.MustParseAddr(r.PeerAddr).Unmap().String() + " " + r.Prefix
	}
	for _, tc := range []struct {
		name string
		q    url.Values
		want []string
	}{
		{"prefix and peer (the report)", url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24"}},
		{"prefix and peer, mapped form", url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"::ffff:80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24"}},
		{"prefix and plain-stored peer, mapped form", url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"::ffff:206.82.106.254"}},
			[]string{"206.82.106.254 1.1.1.0/24"}},
		{"prefix alone", url.Values{"prefix": {"1.1.1.0/24"}},
			[]string{"206.82.106.254 1.1.1.0/24", "46.18.174.241 1.1.1.0/24", "80.81.194.180 1.1.1.0/24", "80.81.194.181 1.1.1.0/24"}},
		{"peer alone", url.Values{"peer": {"80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24", "80.81.194.180 8.8.8.0/24", "80.81.194.180 9.9.9.0/24"}},
		{"origin and peer", url.Values{"origin-asn": {"13335"}, "peer": {"80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24", "80.81.194.180 9.9.9.0/24"}},
		{"posture and peer", url.Values{"posture": {"origin-only"}, "peer": {"206.82.106.254"}},
			[]string{"206.82.106.254 8.8.8.0/24"}},
		{"prefix and posture", url.Values{"prefix": {"8.8.8.0/24"}, "posture": {"secured"}}, nil},
		{"prefix and origin", url.Values{"prefix": {"1.1.1.0/24"}, "origin-asn": {"15169"}}, nil},
		{"all four", url.Values{"prefix": {"9.9.9.0/24"}, "origin-asn": {"13335"}, "peer": {"80.81.194.180"}, "posture": {"path-suspect"}},
			[]string{"80.81.194.180 9.9.9.0/24"}},
		{"peer with no routes", url.Values{"peer": {"192.0.2.99"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, routes := getRoutes(t, s, tc.q)
			if code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			var got []string
			for _, r := range routes {
				got = append(got, key(r))
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	for _, bad := range []url.Values{{"peer": {"not-an-ip"}}, {"prefix": {"1.1.1.0/24"}, "peer": {"x"}}, {"origin-asn": {"AS1"}}} {
		if code, _ := getRoutes(t, s, bad); code != http.StatusBadRequest {
			t.Errorf("%v: status %d, want 400", bad, code)
		}
	}
}

// raven watch applies the same filters to the stream.
func TestWatchFilters(t *testing.T) {
	s := filterFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(s.handleWatch))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"?"+url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"::ffff:80.81.194.180"}}.Encode(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for {
		s.watchMu.RLock()
		n := len(s.watchSubs)
		s.watchMu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	route := func(peer, prefix string) *types.Route {
		return &types.Route{PeerAddr: netip.MustParseAddr(peer), Prefix: netip.MustParsePrefix(prefix), ASPath: []uint32{64500, 13335}}
	}
	s.NotifyRoute(route("80.81.194.181", "1.1.1.0/24")) // other peer
	s.NotifyRoute(route("80.81.194.180", "8.8.8.0/24")) // other prefix
	s.NotifyRoute(route("80.81.194.180", "1.1.1.0/24")) // match, plain form
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var rr RouteResponse
		if err := json.Unmarshal([]byte(line), &rr); err != nil {
			t.Fatal(err)
		}
		if rr.PeerAddr != "80.81.194.180" || rr.Prefix != "1.1.1.0/24" {
			t.Fatalf("watch delivered %s via %s, which the filter excludes", rr.Prefix, rr.PeerAddr)
		}
		return
	}
	t.Fatalf("no event: %v", sc.Err())
}

// The failing ASPA hop is in the route JSON, and absent when there is none.
func TestRouteJSONFailingHop(t *testing.T) {
	r := &types.Route{Prefix: netip.MustParsePrefix("145.102.136.0/22"), ASPath: []uint32{65000, 1199}}
	b, _ := json.Marshal(routeToResponse(r, ""))
	if strings.Contains(string(b), "aspa_failing_hop") {
		t.Errorf("JSON %s has aspa_failing_hop with no failing hop", b)
	}
	r.ASPA.FailingHop = &types.ASPAHop{CustomerASN: 1199, ProviderASN: 65000, Authorization: types.HopNotAuthorized}
	b, _ = json.Marshal(routeToResponse(r, ""))
	if !strings.Contains(string(b), `"aspa_failing_hop":{"customer_asn":1199,"provider_asn":65000}`) {
		t.Errorf("JSON %s lacks the failing hop", b)
	}
}
