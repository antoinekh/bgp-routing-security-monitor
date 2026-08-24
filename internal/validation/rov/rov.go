package rov

import (
	"fmt"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Annotator performs Route Origin Validation per RFC 6811.
type Annotator struct {
	vrpStore *store.VRPStore
}

// NewAnnotator creates a ROV annotator backed by the given VRP store.
func NewAnnotator(vrpStore *store.VRPStore) *Annotator {
	return &Annotator{vrpStore: vrpStore}
}

// Validate performs ROV on a single route and returns the result.
//
// Algorithm (RFC 6811 §2):
//  1. Find all VRPs whose prefix covers the route's prefix.
//  2. If no covering VRPs exist → NotFound.
//  3. If any covering VRP matches the origin ASN AND the route's
//     prefix length ≤ VRP's maxLength → Valid.
//  4. Otherwise → Invalid, classified by ReasonCode as invalid_length when a
//     covering VRP does authorise the origin AS but the route is more specific
//     than that VRP's maxLength, or invalid_asn when none authorises it.
func (a *Annotator) Validate(route *types.Route) types.ROVResult {
	originASN := route.OriginASN()
	if originASN == 0 {
		return types.ROVResult{
			State:      types.ROVNotFound,
			Reason:     "no origin ASN in AS_PATH",
			ReasonCode: types.ROVReasonNoOriginASN,
		}
	}

	covering := a.vrpStore.FindCovering(route.Prefix)

	if len(covering) == 0 {
		return types.ROVResult{
			State:      types.ROVNotFound,
			Reason:     "no covering VRPs found",
			ReasonCode: types.ROVReasonNoCoveringVRP,
		}
	}

	routePrefixLen := route.Prefix.Bits()

	// asnMatch is the first covering VRP that authorises the origin AS, whatever
	// its maxLength. It is what separates a wrong origin from a too-specific
	// prefix once the loop finds no fully valid VRP.
	var asnMatch *types.VRP

	for i, vrp := range covering {
		if vrp.ASN != originASN {
			continue
		}
		if routePrefixLen <= int(vrp.MaxLength) {
			return types.ROVResult{
				State:       types.ROVValid,
				MatchedVRPs: covering,
				Reason:      fmt.Sprintf("matches VRP {%s, AS%d, /%d}", vrp.Prefix, vrp.ASN, vrp.MaxLength),
				ReasonCode:  types.ROVReasonMatchedVRP,
			}
		}
		if asnMatch == nil {
			asnMatch = &covering[i]
		}
	}

	if asnMatch != nil {
		return types.ROVResult{
			State:       types.ROVInvalid,
			MatchedVRPs: covering,
			Reason: fmt.Sprintf("origin AS%d is authorized by VRP {%s, AS%d, /%d} but /%d is more specific than its maxLength",
				originASN, asnMatch.Prefix, asnMatch.ASN, asnMatch.MaxLength, routePrefixLen),
			ReasonCode: types.ROVReasonInvalidLength,
		}
	}

	return types.ROVResult{
		State:       types.ROVInvalid,
		MatchedVRPs: covering,
		Reason:      fmt.Sprintf("origin AS%d not authorized by any covering VRP", originASN),
		ReasonCode:  types.ROVReasonInvalidASN,
	}
}
