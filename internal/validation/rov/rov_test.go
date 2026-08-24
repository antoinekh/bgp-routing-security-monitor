package rov

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

func TestROVValid(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidOriginMismatch(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	// Wrong origin ASN — hijack scenario
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 64666},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidMoreSpecific(t *testing.T) {
	s := store.NewVRPStore()
	// ROA says /24 max, but route is /25 — more-specific hijack
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/25"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid (more-specific), got %s: %s", result.State, result.Reason)
	}
}

func TestROVValidWithMaxLength(t *testing.T) {
	s := store.NewVRPStore()
	// ROA allows up to /28
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 28},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/25"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid (within maxLength), got %s: %s", result.State, result.Reason)
	}
}

func TestROVNotFound(t *testing.T) {
	s := store.NewVRPStore()
	// No VRPs at all
	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/8"),
		ASPath: []uint32{64501, 64502},
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound, got %s: %s", result.State, result.Reason)
	}
}

func TestROVNoOriginASN(t *testing.T) {
	s := store.NewVRPStore()
	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/8"),
		ASPath: nil, // empty AS_PATH
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound for empty AS_PATH, got %s", result.State)
	}
}

func TestROVValidIPv6(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:2121::/48"),
		ASPath: []uint32{65000, 2121},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid for IPv6 match, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidIPv6OriginMismatch(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	// Wrong origin ASN — IPv6 hijack scenario
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:2121::/48"),
		ASPath: []uint32{65000, 65001},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid for IPv6 origin mismatch, got %s: %s", result.State, result.Reason)
	}
}

func TestROVNotFoundIPv6(t *testing.T) {
	s := store.NewVRPStore()
	// VRPs for a different IPv6 prefix — should not cover this route
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:dead::/48"),
		ASPath: []uint32{65000, 65001},
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound for uncovered IPv6, got %s: %s", result.State, result.Reason)
	}
}

// TestROVMixedFamilies confirms IPv4 validation still works when the store
// contains both IPv4 and IPv6 VRPs. Regression check for the IPv6 rollout.
func TestROVMixedFamilies(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("2001:db8:6501::/48"), ASN: 65001, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)

	v4 := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 13335},
	}
	if got := a.Validate(v4); got.State != types.ROVValid {
		t.Errorf("IPv4 with IPv6 VRPs in store: expected Valid, got %s: %s", got.State, got.Reason)
	}

	v6 := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:6501::/48"),
		ASPath: []uint32{65000, 65001},
	}
	if got := a.Validate(v6); got.State != types.ROVValid {
		t.Errorf("IPv6 with IPv4 VRPs in store: expected Valid, got %s: %s", got.State, got.Reason)
	}
}

func TestROVMultipleVRPs(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64501, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	// Origin is 64501 — second VRP should match
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{3356, 64501},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid (second VRP matches), got %s: %s", result.State, result.Reason)
	}
}

// ─── ReasonCode classification ───

// TestROVReasonCodes pins the machine-readable classification for every branch
// of Validate. The invalid_asn vs invalid_length split is the point of the
// field: both are RFC 6811 Invalid, but they need different operator actions.
func TestROVReasonCodes(t *testing.T) {
	vrp := types.VRP{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24}

	tests := []struct {
		name     string
		vrps     []types.VRP
		prefix   string
		asPath   []uint32
		wantStat types.ROVState
		wantCode types.ROVReasonCode
	}{
		{
			name:     "authorised origin within maxLength",
			vrps:     []types.VRP{vrp},
			prefix:   "198.51.100.0/24",
			asPath:   []uint32{64501, 13335},
			wantStat: types.ROVValid,
			wantCode: types.ROVReasonMatchedVRP,
		},
		{
			name:     "origin not authorised by any covering VRP",
			vrps:     []types.VRP{vrp},
			prefix:   "198.51.100.0/24",
			asPath:   []uint32{64501, 64666},
			wantStat: types.ROVInvalid,
			wantCode: types.ROVReasonInvalidASN,
		},
		{
			name:     "authorised origin but more specific than maxLength",
			vrps:     []types.VRP{vrp},
			prefix:   "198.51.100.0/25",
			asPath:   []uint32{64501, 13335},
			wantStat: types.ROVInvalid,
			wantCode: types.ROVReasonInvalidLength,
		},
		{
			name:     "no covering VRP",
			vrps:     nil,
			prefix:   "10.0.0.0/8",
			asPath:   []uint32{64501, 64502},
			wantStat: types.ROVNotFound,
			wantCode: types.ROVReasonNoCoveringVRP,
		},
		{
			name:     "empty AS_PATH",
			vrps:     []types.VRP{vrp},
			prefix:   "198.51.100.0/24",
			asPath:   nil,
			wantStat: types.ROVNotFound,
			wantCode: types.ROVReasonNoOriginASN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := store.NewVRPStore()
			s.ReplaceAll(tt.vrps, 1, 1)
			result := NewAnnotator(s).Validate(&types.Route{
				Prefix: netip.MustParsePrefix(tt.prefix),
				ASPath: tt.asPath,
			})
			if result.State != tt.wantStat {
				t.Errorf("state: got %s, want %s", result.State, tt.wantStat)
			}
			if result.ReasonCode != tt.wantCode {
				t.Errorf("reason code: got %q, want %q (reason: %s)", result.ReasonCode, tt.wantCode, result.Reason)
			}
		})
	}
}

// TestROVInvalidLengthPrefersASNMatchingVRP checks that a covering VRP naming a
// different AS does not mask the maxLength fault of the VRP that does name the
// origin. Ordering inside the covering set must not change the verdict.
func TestROVInvalidLengthPrefersASNMatchingVRP(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64666, MaxLength: 32},
		{Prefix: netip.MustParsePrefix("198.51.0.0/16"), ASN: 13335, MaxLength: 16},
	}, 1, 1)

	result := NewAnnotator(s).Validate(&types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 13335},
	})

	if result.State != types.ROVInvalid {
		t.Fatalf("state: got %s, want Invalid", result.State)
	}
	if result.ReasonCode != types.ROVReasonInvalidLength {
		t.Errorf("reason code: got %q, want %q (reason: %s)", result.ReasonCode, types.ROVReasonInvalidLength, result.Reason)
	}
}

// TestROVMatchedVRPsPopulated checks the covering set is carried on the result,
// since the API and the webhook payload both surface it.
func TestROVMatchedVRPsPopulated(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	invalid := NewAnnotator(s).Validate(&types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64666},
	})
	if len(invalid.MatchedVRPs) != 1 || invalid.MatchedVRPs[0].ASN != 13335 {
		t.Errorf("invalid route matched VRPs: got %v, want one VRP for AS13335", invalid.MatchedVRPs)
	}

	notFound := NewAnnotator(store.NewVRPStore()).Validate(&types.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/8"),
		ASPath: []uint32{64666},
	})
	if len(notFound.MatchedVRPs) != 0 {
		t.Errorf("not-found route matched VRPs: got %v, want none", notFound.MatchedVRPs)
	}
}
