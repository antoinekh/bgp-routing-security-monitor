package rov

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// refValidate is ROV as it was before the covering index and the
// append-built reasons, over the old string-keyed FindCovering, kept as the
// reference the current Annotator must match. Its routes have no LocalASN,
// so an empty path has an origin (the local AS, RFC 6811 §2) RAVEN does
// not know.
func refValidate(byPrefix map[string][]types.VRP, route *types.Route) types.ROVResult {
	originASN := route.OriginASN()
	if originASN == 0 {
		return types.ROVResult{State: types.ROVNotFound, Reason: "origin unknown: local AS not known"}
	}
	var covering []types.VRP
	addr := route.Prefix.Addr()
	for pl := 0; pl <= route.Prefix.Bits(); pl++ {
		candidate, err := addr.Prefix(pl)
		if err != nil {
			continue
		}
		if vrps, ok := byPrefix[candidate.String()]; ok {
			covering = append(covering, vrps...)
		}
	}
	if len(covering) == 0 {
		return types.ROVResult{State: types.ROVNotFound, Reason: "no covering VRPs found"}
	}
	routePrefixLen := route.Prefix.Bits()
	for _, vrp := range covering {
		if vrp.ASN == originASN && routePrefixLen <= int(vrp.MaxLength) {
			return types.ROVResult{
				State:       types.ROVValid,
				MatchedVRPs: covering,
				Reason:      fmt.Sprintf("matches VRP {%s, AS%d, /%d}", vrp.Prefix, vrp.ASN, vrp.MaxLength),
			}
		}
	}
	return types.ROVResult{
		State:       types.ROVInvalid,
		MatchedVRPs: covering,
		Reason:      fmt.Sprintf("origin AS%d not authorized by any covering VRP", originASN),
	}
}

func randPrefix(rng *rand.Rand) netip.Prefix {
	var a netip.Addr
	if rng.IntN(2) == 0 {
		a = netip.AddrFrom4([4]byte{byte(10 + rng.IntN(2)), byte(rng.IntN(4)), byte(rng.IntN(4) * 64), 0})
	} else {
		a = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(rng.IntN(4)), byte(rng.IntN(2) * 128), 0, byte(rng.IntN(3))})
	}
	p, _ := a.Prefix(rng.IntN(a.BitLen() + 1))
	return p
}

// Property: for random VRP sets and random routes (IPv4 and IPv6, varied
// maxLength, matching and non-matching origins, no origin), Validate returns
// exactly the old result: state, reason text and matched VRPs in order.
func TestValidateMatchesReference(t *testing.T) {
	for seed := uint64(1); seed <= 50; seed++ {
		rng := rand.New(rand.NewPCG(seed, 11))
		vrps := make([]types.VRP, 1+rng.IntN(60))
		for i := range vrps {
			p := randPrefix(rng)
			vrps[i] = types.VRP{Prefix: p, ASN: uint32(64500 + rng.IntN(4)),
				MaxLength: uint8(p.Bits() + rng.IntN(p.Addr().BitLen()-p.Bits()+1))}
		}
		s := store.NewVRPStore()
		s.ReplaceAll(slices.Clone(vrps), 1, 1)
		byPrefix := map[string][]types.VRP{}
		for _, v := range vrps {
			byPrefix[v.Prefix.String()] = append(byPrefix[v.Prefix.String()], v)
		}
		a := NewAnnotator(s)
		for i := 0; i < 300; i++ {
			path := []uint32{64496, uint32(64500 + rng.IntN(5))}
			if rng.IntN(20) == 0 {
				path = nil
			}
			r := &types.Route{Prefix: randPrefix(rng), ASPath: path}
			got, want := a.Validate(r), refValidate(byPrefix, r)
			if got.State != want.State || got.Reason != want.Reason || !slices.Equal(got.MatchedVRPs, want.MatchedVRPs) {
				t.Fatalf("seed %d route %s path %v:\n got  %s %q %v\n want %s %q %v", seed, r.Prefix, path,
					got.State, got.Reason, got.MatchedVRPs, want.State, want.Reason, want.MatchedVRPs)
			}
		}
	}
}

// On a warm store, Validate allocates only its Reason string, and nothing
// for not-found routes.
func TestValidateAllocations(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/22"), ASN: 64500, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64501, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), ASN: 64502, MaxLength: 48},
	}, 1, 1)
	a := NewAnnotator(s)
	for _, tc := range []struct {
		prefix string
		origin uint32
		state  types.ROVState
		allocs float64
	}{
		{"198.51.100.0/24", 64501, types.ROVValid, 1},
		{"198.51.100.0/24", 64999, types.ROVInvalid, 1},
		{"2001:db8:1::/48", 64502, types.ROVValid, 1},
		{"203.0.113.0/24", 64501, types.ROVNotFound, 0},
	} {
		r := &types.Route{Prefix: netip.MustParsePrefix(tc.prefix), ASPath: []uint32{64496, tc.origin}}
		if got := a.Validate(r).State; got != tc.state { // also warms the nested list
			t.Fatalf("%s from AS%d: %s, want %s", tc.prefix, tc.origin, got, tc.state)
		}
		if got := testing.AllocsPerRun(100, func() { a.Validate(r) }); got != tc.allocs {
			t.Errorf("%s from AS%d (%s): %v allocs per Validate, want %v", tc.prefix, tc.origin, tc.state, got, tc.allocs)
		}
	}
	// Routes whose origin is the router's own AS (empty AS_PATH) build the
	// longer Reason in the same single allocation.
	for _, tc := range []struct {
		prefix string
		local  uint32
		state  types.ROVState
		allocs float64
	}{
		{"198.51.100.0/24", 64501, types.ROVValid, 1},
		{"198.51.100.0/24", 64999, types.ROVInvalid, 1},
		{"203.0.113.0/24", 64501, types.ROVNotFound, 0},
		{"198.51.100.0/24", 0, types.ROVNotFound, 0},
	} {
		r := &types.Route{Prefix: netip.MustParsePrefix(tc.prefix), LocalASN: tc.local}
		if got := a.Validate(r).State; got != tc.state {
			t.Fatalf("%s local AS%d: %s, want %s", tc.prefix, tc.local, got, tc.state)
		}
		if got := testing.AllocsPerRun(100, func() { a.Validate(r) }); got != tc.allocs {
			t.Errorf("%s local AS%d (%s): %v allocs per Validate, want %v", tc.prefix, tc.local, tc.state, got, tc.allocs)
		}
	}
}
